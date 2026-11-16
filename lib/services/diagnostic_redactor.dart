/// 在导出诊断包前执行的确定性脱敏器（纯内存处理，不落盘未脱敏中间文件）
class RedactionContext {
  final Map<String, String> _ipMap = <String, String>{};
  final Map<String, String> _macMap = <String, String>{};
  final Map<String, String> _pkgMap = <String, String>{};

  String placeholderForIp(String raw) {
    final normalized = raw.trim();
    return _ipMap.putIfAbsent(
      normalized,
      () => '<IP_${_ipMap.length + 1}>',
    );
  }

  String placeholderForMac(String raw) {
    final normalized = raw.trim().toLowerCase();
    return _macMap.putIfAbsent(
      normalized,
      () => '<MAC_${_macMap.length + 1}>',
    );
  }

  String placeholderForPkg(String raw) {
    final normalized = raw.trim();
    return _pkgMap.putIfAbsent(
      normalized,
      () => '<PKG_${_pkgMap.length + 1}>',
    );
  }
}

class DiagnosticRedactor {
  static const Set<String> _whitelistedIps = <String>{
    '127.0.0.1',
    '127.0.0.1/32',
    '127.0.0.0/8',
    '0.0.0.0',
    '0.0.0.0/8',
    '198.18.0.0/15',
    '172.19.0.0/16',
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '169.254.0.0/16',
    '224.0.0.0/4',
    '240.0.0.0/4',
    '8.8.8.8',
    '8.8.4.4',
    '1.1.1.1',
    '1.0.0.1',
    '9.9.9.9',
    '223.5.5.5',
    '223.6.6.6',
    '119.29.29.29',
    '114.114.114.114',
  };

  static const Set<String> _whitelistedIpv6 = <String>{
    '::',
    '::/0',
    '::1',
    '::1/128',
    'fc00::/7',
    'fc00::/18',
    'fe80::/10',
    'ff00::/8',
    'fdfe:dcba:9876::/48',
    '::ffff:127.0.0.0/104',
    '::ffff:10.0.0.0/104',
    '::ffff:172.16.0.0/108',
    '::ffff:192.168.0.0/112',
    '::ffff:169.254.0.0/112',
  };

  static const Set<String> _whitelistedUrlHosts = <String>{
    'dns.google',
    'dns.alidns.com',
    'doh.pub',
    'dns.quad9.net',
    'cloudflare-dns.com',
    'dns.adguard-dns.com',
    'dns.opendns.com',
    '8.8.8.8',
    '8.8.4.4',
    '1.1.1.1',
    '1.0.0.1',
    '9.9.9.9',
    '223.5.5.5',
    '223.6.6.6',
    '119.29.29.29',
  };

  static const Set<String> _whitelistedPackages = <String>{
    'com.wu.adgogogo',
    'com.android.shell',
    'com.android.settings',
    'com.android.systemui',
  };

  static const Set<String> _safeFileExtensions = <String>{
    '.sh',
    '.yaml',
    '.yml',
    '.txt',
    '.log',
    '.prop',
    '.conf',
    '.apk',
    '.zip',
    '.flock',
    '.pid',
    '.tmp',
    '.meta',
    '.orig',
    '.json',
    '.db',
    '.pem',
  };

  static final RegExp _proxyUrlLineRe = RegExp(
    r'\bPROXY_URL\s*[:=].*$',
    caseSensitive: false,
  );

  static final RegExp _sensitiveHeaderRe = RegExp(
    r'''^(.*?\b(?:authorization|proxy-authorization|proxy-auth|cookie|set-cookie|x-api-key|x-api-token|x-auth-token|x-access-token|x-csrf-token|x-session-token)\b["']?\s*[:=]\s*)(.+)$''',
    caseSensitive: false,
  );

  static final RegExp _authBearerBasicRe = RegExp(
    r'\b(Bearer|Basic|Digest)\s+[A-Za-z0-9\-._~+/]+=*',
    caseSensitive: false,
  );

  static final RegExp _jwtRe = RegExp(
    r'\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]*)?\b',
  );

  static final RegExp _passwordHashRe = RegExp(
    r'''\$(?:2[aby]|argon2(?:id|i|d)|pbkdf2|scrypt)\$[^\s"']+''',
    caseSensitive: false,
  );

  static final RegExp _kvSecretRe = RegExp(
    r'''\b((?:password|passwd|pwd|pass|secret|token|access_token|refresh_token|id_token|api_key|apikey|client_secret|session_id|session|sid|signature|sig|hmac|private_key|signing_key|signingkey|auth_key|authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-api-token|x-auth-token|x-access-token|x-csrf-token|x-session-token)\b["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;\}]+)''',
    caseSensitive: false,
  );

  static final RegExp _kvDeviceIdRe = RegExp(
    r'''\b((?:ssid|bssid|imei|imsi|iccid|serialno|ro\.serialno|android_id|oaid|udid|gaid|advertising_id|device_id)\b["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;\}]+)''',
    caseSensitive: false,
  );

  static final RegExp _urlRe = RegExp(
    r'''(?:https?|tls|quic|h3|sdns|socks5?|vmess|vless|trojan|ss|ssr)://[^\s<>")\]']+|(?:https?|tls|quic|h3|sdns|socks5?|vmess|vless|trojan|ss|ssr)://[^\s<>"]+"[^"]*''',
    caseSensitive: false,
  );

  static final RegExp _macRe = RegExp(
    r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b',
  );

  static final RegExp _ipv4Re = RegExp(
    r'(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:/(?:3[0-2]|[12]?\d))?(?![\d.])',
  );

  static final RegExp _ipv6Re = RegExp(
    r'(?<![0-9A-Fa-f:])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:[0-9A-Fa-f:]*|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{0,4})(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){0,3}(?:25[0-5]|2[0-4]\d|1?\d?\d)?(?:%[A-Za-z0-9_.-]+)?(?:/(?:12[0-8]|1[01]\d|[1-9]?\d))?(?![0-9A-Fa-f:])',
  );

  static final RegExp _personalPathRe = RegExp(
    r'(?:/storage/emulated/\d+|/sdcard|/mnt/user/\d+|/data/media/\d+|/Users/[^/\s]+|/home/[^/\s]+)(?:/[^\s"'':;]*)?',
  );

  static final RegExp _appDataPathRe = RegExp(
    r'(/data/(?:user/\d+|data|app(?:/~~[^/]+)?)/)([a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)+)([^\s"'':;]*)',
  );

  static final RegExp _packageTokenRe = RegExp(
    r'\b(?:com|org|net|io|cn|me|tv|app|dev|moe|top|xyz)\.[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+\b',
  );

  static String redact(String input, {RedactionContext? context}) {
    if (input.isEmpty) return input;
    final ctx = context ?? RedactionContext();
    final rawLines = input.split('\n');
    final outLines = <String>[];
    var inSensitiveFoldedHeader = false;

    for (final rawLine in rawLines) {
      var line = rawLine.replaceAll('\r', '');

      // 处理 HTTP 折行 Cookie / Authorization 续行
      if (inSensitiveFoldedHeader) {
        if (line.startsWith(' ') || line.startsWith('\t')) {
          outLines.add('  <REDACTED_HEADER_CONTINUATION>');
          continue;
        }
        inSensitiveFoldedHeader = false;
      }

      final headerMatch = _sensitiveHeaderRe.firstMatch(line);
      if (headerMatch != null) {
        outLines.add('${headerMatch.group(1)}<REDACTED_SECRET>');
        inSensitiveFoldedHeader = true;
        continue;
      }

      if (_proxyUrlLineRe.hasMatch(line)) {
        line = line.replaceAll(_proxyUrlLineRe, 'PROXY_URL=<REDACTED_PROXY_URL>');
      }

      line = line.replaceAll(_passwordHashRe, '<REDACTED_HASH>');
      line = line.replaceAll(_jwtRe, '<REDACTED_JWT>');
      line = line.replaceAllMapped(
        _authBearerBasicRe,
        (m) => '${m.group(1)} <REDACTED_TOKEN>',
      );

      line = line.replaceAllMapped(_urlRe, (m) {
        final rawUrl = m.group(0) ?? '';
        return _redactUrl(rawUrl, ctx);
      });

      line = line.replaceAllMapped(
        _kvSecretRe,
        (m) => '${m.group(1)}<REDACTED_SECRET>',
      );
      line = line.replaceAllMapped(
        _kvDeviceIdRe,
        (m) => '${m.group(1)}<REDACTED_ID>',
      );

      line = line.replaceAllMapped(_appDataPathRe, (m) {
        final prefix = m.group(1) ?? '';
        final pkg = m.group(2) ?? '';
        final keptPkg =
            _whitelistedPackages.contains(pkg) ? pkg : ctx.placeholderForPkg(pkg);
        return '$prefix$keptPkg/<REDACTED_PATH>';
      });

      line = line.replaceAllMapped(_personalPathRe, (m) {
        final p = m.group(0) ?? '';
        if (p.startsWith('/Users/') || p.startsWith('/home/')) {
          return '/<REDACTED_HOME>/<REDACTED_PATH>';
        }
        return '<REDACTED_PERSONAL_PATH>';
      });

      line = line.replaceAllMapped(
        _macRe,
        (m) => ctx.placeholderForMac(m.group(0) ?? ''),
      );

      line = line.replaceAllMapped(_ipv6Re, (m) {
        final ip = m.group(0) ?? '';
        final lower = ip.toLowerCase();
        // 仅含 1 个冒号或纯 2 位十进制时间戳 HH:MM:SS 不当作 IPv6
        if (':'.allMatches(ip).length < 2) return ip;
        if (!lower.contains('::') &&
            RegExp(r'^\d{1,2}:\d{2}:\d{2}$').hasMatch(ip)) {
          return ip;
        }
        if (_whitelistedIpv6.contains(lower)) return ip;
        return ctx.placeholderForIp(ip);
      });

      line = line.replaceAllMapped(_ipv4Re, (m) {
        final ip = m.group(0) ?? '';
        if (_whitelistedIps.contains(ip)) return ip;
        return ctx.placeholderForIp(ip);
      });

      line = line.replaceAllMapped(_packageTokenRe, (m) {
        final token = m.group(0) ?? '';
        final lower = token.toLowerCase();
        if (_whitelistedPackages.contains(lower) ||
            _whitelistedUrlHosts.contains(lower)) {
          return token;
        }
        for (final ext in _safeFileExtensions) {
          if (lower.endsWith(ext)) return token;
        }
        return ctx.placeholderForPkg(token);
      });

      outLines.add(line);
    }

    return outLines.join('\n');
  }

  static String _redactUrl(String rawUrl, RedactionContext ctx) {
    final lower = rawUrl.toLowerCase();
    if (lower.startsWith('sdns://') ||
        lower.startsWith('vmess://') ||
        lower.startsWith('vless://') ||
        lower.startsWith('trojan://') ||
        lower.startsWith('ss://') ||
        lower.startsWith('ssr://')) {
      return '<REDACTED_URL>';
    }
    final schemeIdx = rawUrl.indexOf('://');
    if (schemeIdx <= 0) return '<REDACTED_URL>';
    final scheme = rawUrl.substring(0, schemeIdx).toLowerCase();
    final rest = rawUrl.substring(schemeIdx + 3);
    // 分离 authority 与 /path?query#fragment
    final sepIdx = rest.indexOf(RegExp(r'[/?#]'));
    final authority = sepIdx >= 0 ? rest.substring(0, sepIdx) : rest;
    final hasExtra = sepIdx >= 0;
    final atIdx = authority.lastIndexOf('@');
    final hostPort = atIdx >= 0 ? authority.substring(atIdx + 1) : authority;
    final hasUserInfo = atIdx >= 0;

    // 剥离端口检查严格白名单域名/IP
    var hostOnly = hostPort.toLowerCase();
    if (!hostOnly.startsWith('[')) {
      final colonIdx = hostOnly.indexOf(':');
      if (colonIdx > 0) hostOnly = hostOnly.substring(0, colonIdx);
    }

    if (_whitelistedUrlHosts.contains(hostOnly) || hostOnly == '127.0.0.1') {
      if (hasUserInfo || hasExtra) {
        return '$scheme://$hostPort/<REDACTED_PATH>';
      }
      return '$scheme://$hostPort';
    }

    // 非常规 URL（如代理订阅、复杂带参数 URL、恶意 URL）整条脱敏
    if (hostPort.isEmpty) return '<REDACTED_URL>';
    if (_ipv4Re.hasMatch(hostOnly)) {
      ctx.placeholderForIp(hostOnly);
    }
    return '<REDACTED_URL>';
  }
}
