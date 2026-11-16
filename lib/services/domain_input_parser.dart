import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:adguard_home_manager/services/public_suffix_data.g.dart';

/// 公共后缀匹配结果（ICANN / PRIVATE / 通配 / 例外规则）。
class PublicSuffixMatch {
  final String version;
  final String suffix;
  final bool icann;
  final bool isPrivate;
  final bool isKnownRule;
  final bool isPublicSuffix;
  final String? registrableDomain;

  const PublicSuffixMatch({
    required this.version,
    required this.suffix,
    required this.icann,
    required this.isPrivate,
    required this.isKnownRule,
    required this.isPublicSuffix,
    required this.registrableDomain,
  });
}

/// 单个 URL / 域名输入的规范化解析结果（纯离线，绝不向目标 URL 发起任何网络请求）。
class DomainParseResult {
  final bool ok;
  final String normalizedHost;
  final String? unicodeHost;
  final bool isIpAddress;
  final String? errorReason;

  const DomainParseResult._({
    required this.ok,
    this.normalizedHost = '',
    this.unicodeHost,
    this.isIpAddress = false,
    this.errorReason,
  });

  factory DomainParseResult.success({
    required String normalizedHost,
    String? unicodeHost,
    bool isIpAddress = false,
  }) =>
      DomainParseResult._(
        ok: true,
        normalizedHost: normalizedHost,
        unicodeHost: unicodeHost,
        isIpAddress: isIpAddress,
      );

  factory DomainParseResult.error(String reason) => DomainParseResult._(
        ok: false,
        errorReason: reason,
      );
}

/// 纯离线、可测试的 URL / 主机名规范化解析器与可注册父域名生成器。
///
/// 安全保证：
/// - 绝不访问或预请求用户粘贴的追踪链接；
/// - 绝不静默将含歧义空白的多个片段拼接成一个新域名；
/// - 不把完整追踪路径或查询 Token 记录到持久化日志中。
class DomainInputParser {
  DomainInputParser._();

  static const int defaultMaxParentDepth = 6;

  static final RegExp _schemePrefixRe = RegExp(r'^([a-zA-Z][a-zA-Z0-9+.-]*):');
  static final RegExp _httpSchemeCountRe =
      RegExp(r'https?://', caseSensitive: false);
  static final RegExp _wsRe = RegExp(r'\s+');
  static final RegExp _asciiLabelRe =
      RegExp(r'^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$');

  static String get pslVersionString => pslVersion;

  /// 解析单个用户输入的 URL 或域名；遇多链接、空白歧义或非法输入时返回错误原因而不猜测拼接。
  static DomainParseResult parseSingleInput(String rawInput) {
    var text = rawInput.trim();
    if (text.isEmpty) {
      return DomainParseResult.error('请输入域名或链接');
    }

    text = _stripOuterWrappers(text);
    if (text.isEmpty) {
      return DomainParseResult.error('请输入有效域名或链接');
    }

    // 多个 http(s) 链接直接拒绝
    if (_httpSchemeCountRe.allMatches(text).length > 1) {
      return DomainParseResult.error('检测到多个链接，请一次只粘贴一个追踪链接或域名');
    }

    // 若不含完整 URL 协议而包含空白，先检查是否是多域名/含歧义碎片（绝不静默拼接）
    final schemeMatch = _schemePrefixRe.firstMatch(text);
    if (schemeMatch == null) {
      if (_wsRe.hasMatch(text)) {
        final tokens = text.split(_wsRe).where((e) => e.isNotEmpty).toList();
        if (tokens.length > 1) {
          return DomainParseResult.error('输入包含多个空白分隔片段或链接，存在歧义，请每次仅输入单个域名');
        }
        text = tokens.first;
      }
      // 裸域名若也误带路径，如 u56112681.ct.sendgrid.net/ls/click?...，剥离路径与查询
      return _extractHostFromAuthorityAndPath(text, hadExplicitScheme: false);
    }

    final scheme = schemeMatch.group(1)!.toLowerCase();
    if (scheme != 'http' && scheme != 'https') {
      // 区分 host:port 被误当 scheme（例如 example.com:8443 -> schemeMatch 会匹配不到 "."，但 host 若无点如 localhost:3000 会匹配到 localhost!）
      final afterColon = text.substring(schemeMatch.end);
      final portOnlyMatch = RegExp(r'^([0-9]{1,5})(?:[/?#].*)?$').firstMatch(afterColon);
      if (portOnlyMatch != null && !text.contains('://')) {
        return _extractHostFromAuthorityAndPath(text, hadExplicitScheme: false);
      }
      return DomainParseResult.error('不支持的链接协议 ($scheme:)');
    }

    if (!text.toLowerCase().startsWith('$scheme://')) {
      return DomainParseResult.error('链接格式无效');
    }

    final rest = text.substring(scheme.length + 3);
    if (rest.isEmpty) {
      return DomainParseResult.error('链接缺少主机名');
    }

    // 分离 authority 与路径/查询；authority 内部出现任意空白均属歧义/多片段输入，拒绝静默拼接
    final pathSepIdx = rest.indexOf(RegExp(r'[/?#]'));
    final authority = pathSepIdx >= 0 ? rest.substring(0, pathSepIdx) : rest;
    final remainder = pathSepIdx >= 0 ? rest.substring(pathSepIdx) : '';

    if (_wsRe.hasMatch(authority)) {
      return DomainParseResult.error('域名部分包含空白字符，存在歧义，请检查链接是否完整');
    }
    if (remainder.isNotEmpty && _wsRe.hasMatch(remainder)) {
      // 单个 URL 路径中偶有换行可容忍，但若空格后跟着第二个独立域名/URL 仍拒绝
      final afterWs = remainder.split(_wsRe).skip(1).join(' ');
      if (_httpSchemeCountRe.hasMatch(afterWs) ||
          RegExp(r'[a-zA-Z0-9-]+\.[a-zA-Z]{2,}').hasMatch(afterWs)) {
        return DomainParseResult.error('检测到多个链接或附加域名，请只保留需要排查的那一条');
      }
    }

    return _parseAuthority(authority);
  }

  static DomainParseResult _extractHostFromAuthorityAndPath(
    String input, {
    required bool hadExplicitScheme,
  }) {
    final clean = input.trim();
    if (clean.startsWith('//')) {
      return _parseAuthority(clean.substring(2).split(RegExp(r'[/?#]')).first);
    }
    final pathSepIdx = clean.indexOf(RegExp(r'[/?#]'));
    final authority = pathSepIdx >= 0 ? clean.substring(0, pathSepIdx) : clean;
    if (_wsRe.hasMatch(authority)) {
      return DomainParseResult.error('域名包含空白字符，输入有歧义');
    }
    return _parseAuthority(authority);
  }

  static DomainParseResult _parseAuthority(String rawAuthority) {
    var authority = rawAuthority.trim();
    if (authority.isEmpty) {
      return DomainParseResult.error('未能提取有效主机名');
    }

    // 剥离 userinfo@
    final atIdx = authority.lastIndexOf('@');
    if (atIdx >= 0) {
      authority = authority.substring(atIdx + 1);
      if (authority.isEmpty) {
        return DomainParseResult.error('链接缺少主机名');
      }
    }

    String hostPart;
    if (authority.startsWith('[')) {
      // IPv6 bracket form: [::1] or [2001:db8::1]:8443
      final closeIdx = authority.indexOf(']');
      if (closeIdx <= 1) {
        return DomainParseResult.error('IPv6 地址格式无效');
      }
      hostPart = authority.substring(1, closeIdx);
      final afterBracket = authority.substring(closeIdx + 1);
      if (afterBracket.isNotEmpty) {
        if (!afterBracket.startsWith(':') || !_isValidPort(afterBracket.substring(1))) {
          return DomainParseResult.error('端口格式无效');
        }
      }
      final parsedIp = InternetAddress.tryParse(hostPart);
      if (parsedIp == null || parsedIp.type != InternetAddressType.IPv6) {
        return DomainParseResult.error('IPv6 地址无效');
      }
      return DomainParseResult.success(
        normalizedHost: parsedIp.address.toLowerCase(),
        isIpAddress: true,
      );
    }

    // 处理 IPv4 / 域名带端口，同时兼容未加方括号的裸 IPv6
    final bareIp = InternetAddress.tryParse(authority);
    if (bareIp != null) {
      return DomainParseResult.success(
        normalizedHost: bareIp.address.toLowerCase(),
        isIpAddress: true,
      );
    }

    final colonIdx = authority.indexOf(':');
    if (colonIdx >= 0) {
      if (authority.indexOf(':', colonIdx + 1) >= 0) {
        return DomainParseResult.error('主机名格式无效');
      }
      hostPart = authority.substring(0, colonIdx);
      final portStr = authority.substring(colonIdx + 1);
      if (!_isValidPort(portStr)) {
        return DomainParseResult.error('端口超出有效范围 ($portStr)');
      }
    } else {
      hostPart = authority;
    }

    // 去掉末尾点并小写化
    while (hostPart.endsWith('.')) {
      hostPart = hostPart.substring(0, hostPart.length - 1);
    }
    hostPart = hostPart.trim().toLowerCase();
    if (hostPart.isEmpty) {
      return DomainParseResult.error('主机名为空');
    }

    // 再次检查 IPv4（例如 1.2.3.4:443 去端口后）
    final ipAfterPort = InternetAddress.tryParse(hostPart);
    if (ipAfterPort != null) {
      return DomainParseResult.success(
        normalizedHost: ipAfterPort.address.toLowerCase(),
        isIpAddress: true,
      );
    }

    final encodedResult = _encodeDomainToAscii(hostPart);
    if (encodedResult == null) {
      return DomainParseResult.error('域名包含非法字符或标签长度超限');
    }

    final asciiHost = encodedResult.asciiHost;
    final unicodeHost = encodedResult.unicodeHost;
    if (asciiHost.length > 253) {
      return DomainParseResult.error('域名总长度超过 253 字符');
    }

    // 单标签非本地主机（既无点也不是 localhost）拒绝作为有效公网/排错域名
    if (!asciiHost.contains('.') && asciiHost != 'localhost') {
      return DomainParseResult.error('请输入完整域名（至少包含顶级域，如 example.com）');
    }

    return DomainParseResult.success(
      normalizedHost: asciiHost,
      unicodeHost: unicodeHost != asciiHost ? unicodeHost : null,
      isIpAddress: false,
    );
  }

  static bool _isValidPort(String portStr) {
    if (portStr.isEmpty || !RegExp(r'^[0-9]+$').hasMatch(portStr)) {
      return false;
    }
    final port = int.tryParse(portStr);
    return port != null && port >= 1 && port <= 65535;
  }

  static String _stripOuterWrappers(String raw) {
    var s = raw.trim();
    const pairs = <(String, String)>[
      ('"', '"'),
      ("'", "'"),
      ('`', '`'),
      ('<', '>'),
      ('(', ')'),
      ('（', '）'),
      ('[', ']'),
      ('【', '】'),
    ];
    var changed = true;
    while (changed && s.length >= 2) {
      changed = false;
      for (final (left, right) in pairs) {
        if (s.startsWith(left) && s.endsWith(right)) {
          // 保留裸 IPv6 方括号 [::1]
          if (left == '[' &&
              InternetAddress.tryParse(s.substring(1, s.length - 1)) != null) {
            continue;
          }
          s = s.substring(left.length, s.length - right.length).trim();
          changed = true;
        }
      }
    }
    return s;
  }

  /// 使用版本化离线 PSL（含 ICANN 与 PRIVATE 分区、普通/通配/例外规则）计算公共后缀与可注册域名边界。
  /// 当主机名非合法域名或不在已知 PSL 规则内时，返回 null（不回退猜“最后两段就是主域名”）。
  static PublicSuffixMatch? inspectPublicSuffix(String rawHost) {
    final trimmed = rawHost.trim().toLowerCase();
    if (trimmed.isEmpty ||
        trimmed.startsWith('.') ||
        trimmed.endsWith('.') ||
        trimmed.contains('..') ||
        InternetAddress.tryParse(trimmed) != null) {
      return null;
    }
    final encoded = _encodeDomainToAscii(trimmed);
    if (encoded == null) return null;
    return _OfflinePublicSuffixMatcher.match(encoded.asciiHost);
  }

  /// 校验是否为合法可排查域名（排除 IP、单标签及格式错误域名）。
  static bool isValidHostname(String rawHost) {
    final clean = rawHost.trim().toLowerCase();
    if (clean.isEmpty ||
        clean.startsWith('.') ||
        clean.endsWith('.') ||
        clean.contains('..') ||
        InternetAddress.tryParse(clean) != null) {
      return false;
    }
    final encoded = _encodeDomainToAscii(clean);
    if (encoded == null || encoded.asciiHost.length > 253) return false;
    return encoded.asciiHost.contains('.');
  }

  /// 判断域名是否为公共后缀（含单标签 TLD、多级 ICANN/PRIVATE 后缀与通配公共后缀）。
  static bool isPublicSuffix(String normalizedHost) {
    final host = normalizedHost.trim().toLowerCase();
    if (host.isEmpty || InternetAddress.tryParse(host) != null) {
      return false;
    }
    if (!host.contains('.')) {
      return true;
    }
    final match = inspectPublicSuffix(host);
    if (match == null) return false;
    return match.isPublicSuffix;
  }

  /// 计算可注册根域（eTLD+1）；若为公共后缀或 PSL 无法可靠判定规则边界，返回 null（绝不瞎猜最后两段）。
  static String? registrableDomain(String normalizedHost) {
    final match = inspectPublicSuffix(normalizedHost);
    if (match == null || !match.isKnownRule || match.isPublicSuffix) {
      return null;
    }
    return match.registrableDomain;
  }

  /// 生成有边界的查询域名链（首项为原域名，随后为逐级父域名，停在可注册域名处）。
  ///
  /// - IP 地址直接返回仅含自身的列表，不展开父级；
  /// - 公共后缀与单标签 TLD 绝不进入结果列表；
  /// - PSL 无法可靠判定边界的未知后缀域名仅检测原域名本身，不猜父级与主域；
  /// - 去重并受 [maxDepth] 限制，避免极深子域无限查询。
  static List<String> buildParentDomains(
    String normalizedHost, {
    int maxDepth = defaultMaxParentDepth,
  }) {
    final clean = normalizedHost.trim().toLowerCase();
    if (clean.isEmpty) return const <String>[];
    if (InternetAddress.tryParse(clean) != null) {
      return <String>[clean];
    }
    final encoded = _encodeDomainToAscii(clean);
    if (encoded == null) return const <String>[];
    final asciiHost = encoded.asciiHost;
    if (!asciiHost.contains('.') || isPublicSuffix(asciiHost)) {
      return const <String>[];
    }

    final match = inspectPublicSuffix(asciiHost);
    if (match == null || !match.isKnownRule || match.registrableDomain == null) {
      // PSL 无法可靠确定可注册根域边界：仅保留当前域名自身，绝不猜测上级
      return <String>[asciiHost];
    }

    final regDomain = match.registrableDomain!;
    final out = <String>[asciiHost];
    final seen = <String>{asciiHost};
    if (asciiHost == regDomain) {
      return out;
    }

    var current = asciiHost;
    while (out.length < maxDepth) {
      final dotIdx = current.indexOf('.');
      if (dotIdx < 0) break;
      final parent = current.substring(dotIdx + 1);
      if (parent.isEmpty || isPublicSuffix(parent)) {
        break;
      }
      if (seen.add(parent)) {
        out.add(parent);
      }
      if (parent == regDomain || parent.split('.').length < 2) {
        break;
      }
      current = parent;
    }
    return out;
  }

  static ({String asciiHost, String unicodeHost})? _encodeDomainToAscii(
      String host) {
    if (host.startsWith('.') || host.endsWith('.')) return null;
    final labels = host.split('.');
    final asciiLabels = <String>[];
    final unicodeLabels = <String>[];

    for (final rawLabel in labels) {
      if (rawLabel.isEmpty) return null;
      final lower = rawLabel.toLowerCase();
      final isAscii = lower.codeUnits.every((c) => c < 0x80);
      if (isAscii) {
        if (!_asciiLabelRe.hasMatch(lower)) return null;
        asciiLabels.add(lower);
        unicodeLabels.add(lower);
      } else {
        final encoded = _punycodeEncodeLabel(lower);
        if (encoded == null ||
            encoded.length > 63 ||
            !_asciiLabelRe.hasMatch(encoded)) {
          return null;
        }
        asciiLabels.add(encoded);
        unicodeLabels.add(lower);
      }
    }

    return (
      asciiHost: asciiLabels.join('.'),
      unicodeHost: unicodeLabels.join('.'),
    );
  }

  /// RFC 3492 Punycode 标签编码（含 xn-- 前缀），纯离线转换 IDN。
  static String? _punycodeEncodeLabel(String label) {
    const base = 36;
    const tmin = 1;
    const tmax = 26;
    const skew = 38;
    const damp = 700;
    const initialBias = 72;
    const initialN = 128;

    final runes = label.runes.toList();
    if (runes.any((r) => r < 0x20 || r == 0x7F)) return null;

    final output = StringBuffer('xn--');
    var basicCount = 0;
    for (final r in runes) {
      if (r < 0x80) {
        output.writeCharCode(r);
        basicCount++;
      }
    }
    if (basicCount > 0) {
      output.write('-');
    }

    var n = initialN;
    var delta = 0;
    var bias = initialBias;
    var handled = basicCount;

    int adapt(int d, int numPoints, bool firstTime) {
      var k = 0;
      var dd = firstTime ? d ~/ damp : d >> 1;
      dd += dd ~/ numPoints;
      while (dd > ((base - tmin) * tmax) ~/ 2) {
        dd ~/= base - tmin;
        k += base;
      }
      return k + (((base - tmin + 1) * dd) ~/ (dd + skew));
    }

    int encodeDigit(int d) {
      return d < 26 ? 97 + d : 48 + (d - 26); // 'a'-'z', '0'-'9'
    }

    while (handled < runes.length) {
      var m = 0x10FFFF;
      for (final r in runes) {
        if (r >= n && r < m) m = r;
      }
      delta += (m - n) * (handled + 1);
      n = m;

      for (final r in runes) {
        if (r < n) {
          delta++;
        } else if (r == n) {
          var q = delta;
          var k = base;
          while (true) {
            final t = k <= bias
                ? tmin
                : (k >= bias + tmax ? tmax : k - bias);
            if (q < t) break;
            output.writeCharCode(encodeDigit(t + ((q - t) % (base - t))));
            q = (q - t) ~/ (base - t);
            k += base;
          }
          output.writeCharCode(encodeDigit(q));
          bias = adapt(delta, handled + 1, handled == basicCount);
          delta = 0;
          handled++;
        }
      }
      delta++;
      n++;
    }

    return output.toString();
  }
}

/// 离线 Public Suffix List 前缀树匹配器（与 `golang.org/x/net/publicsuffix` 数据表与算法一致）。
/// 完整覆盖 ICANN / PRIVATE 分区、普通后缀、通配 `*` 后缀与 `!` 例外规则。
class _OfflinePublicSuffixMatcher {
  _OfflinePublicSuffixMatcher._();

  static const int _notFound = -1;

  static final String _text = ascii.decode(base64Decode(pslTextBase64.replaceAll('\n', '')));
  static final Uint8List _nodes = base64Decode(pslNodesBase64.replaceAll('\n', ''));
  static final Uint8List _children = base64Decode(pslChildrenBase64.replaceAll('\n', ''));

  static int _getNode(int i) {
    final off = i * 5;
    return (_nodes[off] << 32) |
        (_nodes[off + 1] << 24) |
        (_nodes[off + 2] << 16) |
        (_nodes[off + 3] << 8) |
        _nodes[off + 4];
  }

  static int _getChild(int i) {
    final off = i * 4;
    return (_children[off] << 24) |
        (_children[off + 1] << 16) |
        (_children[off + 2] << 8) |
        _children[off + 3];
  }

  static String _nodeLabel(int i) {
    var x = _getNode(i);
    final length = x & ((1 << pslNodesBitsTextLength) - 1);
    x >>= pslNodesBitsTextLength;
    final offset = x & ((1 << pslNodesBitsTextOffset) - 1);
    return _text.substring(offset, offset + length);
  }

  static int _find(String label, int lo, int hi) {
    var l = lo;
    var h = hi;
    while (l < h) {
      final mid = l + ((h - l) >> 1);
      final s = _nodeLabel(mid);
      final cmp = s.compareTo(label);
      if (cmp < 0) {
        l = mid + 1;
      } else if (cmp == 0) {
        return mid;
      } else {
        h = mid;
      }
    }
    return _notFound;
  }

  static PublicSuffixMatch match(String domain) {
    var lo = 0;
    var hi = pslNumTld;
    var s = domain;
    var suffix = domain.length;
    var icann = false;
    var icannNode = false;
    var wildcard = false;
    var matchedExplicitRule = false;

    while (true) {
      final dot = s.lastIndexOf('.');
      if (wildcard) {
        icann = icannNode;
        suffix = 1 + dot;
        matchedExplicitRule = true;
      }
      if (lo == hi) {
        break;
      }
      final label = s.substring(1 + dot);
      final f = _find(label, lo, hi);
      if (f == _notFound) {
        break;
      }

      var u = _getNode(f) >> (pslNodesBitsTextOffset + pslNodesBitsTextLength);
      icannNode = (u & ((1 << pslNodesBitsIcann) - 1)) != 0;
      u >>= pslNodesBitsIcann;
      u = _getChild(u & ((1 << pslNodesBitsChildren) - 1));
      lo = u & ((1 << pslChildrenBitsLo) - 1);
      u >>= pslChildrenBitsLo;
      hi = u & ((1 << pslChildrenBitsHi) - 1);
      u >>= pslChildrenBitsHi;
      final nodeType = u & ((1 << pslChildrenBitsNodeType) - 1);
      if (nodeType == pslNodeTypeNormal) {
        suffix = 1 + dot;
        matchedExplicitRule = true;
      } else if (nodeType == pslNodeTypeException) {
        suffix = 1 + s.length;
        matchedExplicitRule = true;
        break;
      }
      u >>= pslChildrenBitsNodeType;
      wildcard = (u & ((1 << pslChildrenBitsWildcard) - 1)) != 0;
      if (!wildcard) {
        icann = icannNode;
      }

      if (dot == -1) {
        break;
      }
      s = s.substring(0, dot);
    }

    String resolvedSuffix;
    bool isKnownRule;
    if (suffix == domain.length || !matchedExplicitRule) {
      // 未命中任何显式 ICANN/PRIVATE/通配/例外 PSL 规则，属于未知顶级域（不作为可信赖 PSL 边界）。
      resolvedSuffix = domain.substring(1 + domain.lastIndexOf('.'));
      isKnownRule = false;
      icann = false;
    } else {
      resolvedSuffix = domain.substring(suffix);
      isKnownRule = true;
    }

    final isSingleLabel = !domain.contains('.');
    final isPs = isSingleLabel || (isKnownRule && domain.length <= resolvedSuffix.length);

    String? regDomain;
    if (isKnownRule && !isPs && domain.length > resolvedSuffix.length) {
      final sepIdx = domain.length - resolvedSuffix.length - 1;
      if (sepIdx > 0 && domain[sepIdx] == '.') {
        final prevDot = domain.lastIndexOf('.', sepIdx - 1);
        regDomain = domain.substring(1 + prevDot);
      }
    }

    return PublicSuffixMatch(
      version: pslVersion,
      suffix: resolvedSuffix,
      icann: icann,
      isPrivate: isKnownRule && !icann,
      isKnownRule: isKnownRule,
      isPublicSuffix: isPs,
      registrableDomain: regDomain,
    );
  }
}
