import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';

import 'package:adguard_home_manager/models/filtering.dart';
import 'package:adguard_home_manager/models/logs.dart';
import 'package:adguard_home_manager/services/api_client.dart';
import 'package:adguard_home_manager/services/domain_input_parser.dart';

/// 实时规则检测状态（严格区分查询失败/不支持与真实放行）。
enum RuleCheckStatus {
  blocked,
  whitelisted,
  rewritten,
  notBlocked,
  failed,
  unsupported,
}

/// 命中规则条目及订阅来源名称映射结果。
class MatchedRuleInfo {
  final String text;
  final int filterListId;
  final String sourceName;
  final bool isCustomRule;
  final bool isImportant;

  const MatchedRuleInfo({
    required this.text,
    required this.filterListId,
    required this.sourceName,
    this.isCustomRule = false,
    this.isImportant = false,
  });

  static String resolveSourceName(
    int id, {
    Map<int, String> filterNames = const {},
    Map<int, String> whitelistNames = const {},
  }) {
    if (id == 0) return '自定义规则';
    if (id == -1) return 'Hosts 文件';
    if (id == -3) return '家长控制';
    if (id == -4) return '安全浏览';
    final wl = whitelistNames[id];
    if (wl != null && wl.isNotEmpty) return '$wl (白名单订阅)';
    final bl = filterNames[id];
    if (bl != null && bl.isNotEmpty) return bl;
    return '来源 ID $id';
  }
}

/// 单个域名（及指定 DNS 记录类型）的 `/filtering/check_host` 检测结论。
class HostCheckResult {
  final String host;
  final bool isOriginal;
  final RuleCheckStatus status;
  final String rawReason;
  final List<MatchedRuleInfo> rules;
  final String qtype;
  final String? secondaryQtypeNote;
  final String? errorDetail;

  const HostCheckResult({
    required this.host,
    required this.isOriginal,
    required this.status,
    required this.rawReason,
    required this.rules,
    this.qtype = 'A',
    this.secondaryQtypeNote,
    this.errorDetail,
  });

  bool get isBlocked => status == RuleCheckStatus.blocked;
  bool get hasImportantBlock =>
      isBlocked && rules.any((r) => r.isImportant);

  String get statusLabel {
    switch (status) {
      case RuleCheckStatus.blocked:
        return '规则阻断';
      case RuleCheckStatus.whitelisted:
        return '白名单命中';
      case RuleCheckStatus.rewritten:
        return '重写或其他处理';
      case RuleCheckStatus.notBlocked:
        return '未命中阻断规则';
      case RuleCheckStatus.unsupported:
        return '核心不支持该检测接口';
      case RuleCheckStatus.failed:
        return errorDetail != null && errorDetail!.isNotEmpty
            ? '查询失败（$errorDetail）'
            : '查询失败／超时／未连接';
    }
  }

  static RuleCheckStatus classifyReason(String reason) {
    switch (reason) {
      case 'FilteredBlackList':
      case 'FilteredSafeBrowsing':
      case 'FilteredParental':
      case 'FilteredInvalid':
      case 'FilteredSafeSearch':
      case 'FilteredBlockedService':
      case 'FilteredSNI':
        return RuleCheckStatus.blocked;
      case 'NotFilteredWhiteList':
        return RuleCheckStatus.whitelisted;
      case 'Rewrite':
      case 'RewriteEtcHosts':
      case 'RewriteRule':
        return RuleCheckStatus.rewritten;
      case 'NotFilteredNotFound':
      case 'NotFilteredSNI':
      case 'NotFilteredError':
        return RuleCheckStatus.notBlocked;
      default:
        return reason.startsWith('Filtered')
            ? RuleCheckStatus.blocked
            : RuleCheckStatus.notBlocked;
    }
  }

  factory HostCheckResult.fromApiResponse({
    required String host,
    required ApiResponse response,
    required bool isOriginal,
    String qtype = 'A',
    Map<int, String> filterNames = const {},
    Map<int, String> whitelistNames = const {},
  }) {
    if (!response.successful) {
      if (response.statusCode == 404 || response.statusCode == 501) {
        return HostCheckResult(
          host: host,
          isOriginal: isOriginal,
          status: RuleCheckStatus.unsupported,
          rawReason: '',
          rules: const [],
          qtype: qtype,
          errorDetail: 'HTTP ${response.statusCode}',
        );
      }
      final detail = response.statusCode != null
          ? 'HTTP ${response.statusCode}'
          : (response.content?.toString().isNotEmpty == true
              ? response.content.toString()
              : '未连接或超时');
      return HostCheckResult(
        host: host,
        isOriginal: isOriginal,
        status: RuleCheckStatus.failed,
        rawReason: '',
        rules: const [],
        qtype: qtype,
        errorDetail: detail,
      );
    }

    if (response.content is! Map) {
      return HostCheckResult(
        host: host,
        isOriginal: isOriginal,
        status: RuleCheckStatus.failed,
        rawReason: '',
        rules: const [],
        qtype: qtype,
        errorDetail: '响应格式异常',
      );
    }

    final map = Map<String, dynamic>.from(response.content as Map);
    final reason = (map['reason'] ?? '').toString().trim();
    if (reason.isEmpty) {
      return HostCheckResult(
        host: host,
        isOriginal: isOriginal,
        status: RuleCheckStatus.failed,
        rawReason: '',
        rules: const [],
        qtype: qtype,
        errorDetail: '缺少 reason 字段',
      );
    }

    final parsedRules = <MatchedRuleInfo>[];
    final seenRules = <String>{};

    void addRule(String text, int id) {
      final cleanText = text.trim();
      if (cleanText.isEmpty) return;
      final key = '$id\x00$cleanText';
      if (!seenRules.add(key)) return;
      parsedRules.add(MatchedRuleInfo(
        text: cleanText,
        filterListId: id,
        sourceName: MatchedRuleInfo.resolveSourceName(
          id,
          filterNames: filterNames,
          whitelistNames: whitelistNames,
        ),
        isCustomRule: id == 0,
        isImportant: _ruleHasImportantModifier(cleanText),
      ));
    }

    if (map['rules'] is List) {
      for (final raw in (map['rules'] as List)) {
        if (raw is Map) {
          final text = (raw['text'] ?? '').toString();
          final rawId = raw['filter_list_id'] ?? raw['filter_id'] ?? raw['filterId'];
          final id = rawId is int
              ? rawId
              : int.tryParse(rawId?.toString() ?? '') ?? 0;
          addRule(text, id);
        }
      }
    }

    // 兼容旧版单条 rule + filter_id / filterId 字段（仅补充未重复项）
    final legacyRule = (map['rule'] ?? '').toString();
    if (legacyRule.trim().isNotEmpty) {
      final legacyIdRaw = map['filter_id'] ?? map['filterId'];
      final legacyId = legacyIdRaw is int
          ? legacyIdRaw
          : int.tryParse(legacyIdRaw?.toString() ?? '') ?? 0;
      addRule(legacyRule, legacyId);
    }

    return HostCheckResult(
      host: host,
      isOriginal: isOriginal,
      status: classifyReason(reason),
      rawReason: reason,
      rules: parsedRules,
      qtype: qtype,
    );
  }

  static bool _ruleHasImportantModifier(String text) {
    final dollarIdx = text.lastIndexOf(r'$');
    if (dollarIdx < 0) return false;
    final mods = text.substring(dollarIdx + 1).split(',');
    return mods.any((m) {
      final t = m.trim().toLowerCase();
      return t == 'important' || t == '~important';
    });
  }
}

/// 整条域名的实时检测报告：原域名结论优先（含 A/AAAA 差异说明）+ 父级辅助检查列表。
class HostFamilyCheckReport {
  final DomainParseResult parsedInput;
  final HostCheckResult originalA;
  final HostCheckResult? originalAAAA;
  final List<HostCheckResult> parentResults;

  const HostFamilyCheckReport({
    required this.parsedInput,
    required this.originalA,
    this.originalAAAA,
    required this.parentResults,
  });

  HostCheckResult get effectiveOriginal {
    final aaaa = originalAAAA;
    if (aaaa == null) return originalA;
    // 若 A 未命中而 AAAA 阻断/重写，合并显示并保留各自记录类型提示
    if (originalA.status == RuleCheckStatus.notBlocked &&
        (aaaa.status == RuleCheckStatus.blocked ||
            aaaa.status == RuleCheckStatus.rewritten ||
            aaaa.status == RuleCheckStatus.whitelisted)) {
      return HostCheckResult(
        host: aaaa.host,
        isOriginal: true,
        status: aaaa.status,
        rawReason: aaaa.rawReason,
        rules: aaaa.rules,
        qtype: 'AAAA',
        secondaryQtypeNote: 'A=${originalA.statusLabel}, AAAA=${aaaa.statusLabel}',
      );
    }
    if (originalA.status != aaaa.status &&
        aaaa.status != RuleCheckStatus.failed &&
        aaaa.status != RuleCheckStatus.unsupported) {
      return HostCheckResult(
        host: originalA.host,
        isOriginal: true,
        status: originalA.status,
        rawReason: originalA.rawReason,
        rules: originalA.rules,
        qtype: originalA.qtype,
        secondaryQtypeNote: 'A=${originalA.statusLabel}, AAAA=${aaaa.statusLabel}',
      );
    }
    return originalA;
  }
}

typedef HostCheckerFn = Future<ApiResponse> Function(String host, String qtype);

/// 受控并发（默认 <= 3）、带单项超时与代数防错乱的原域 + 父域名实时检测调度器。
class RuleBatchChecker {
  static const int maxConcurrency = 3;
  static const Duration perItemTimeout = Duration(seconds: 5);

  RuleBatchChecker._();

  static Map<int, String> buildFilterNameMap(List<Filter> filters) {
    return <int, String>{
      for (final f in filters) f.id: f.name,
    };
  }

  static Future<HostFamilyCheckReport?> checkDomainFamily({
    required DomainParseResult parsed,
    required HostCheckerFn checker,
    required bool Function() isCancelled,
    Map<int, String> filterNames = const {},
    Map<int, String> whitelistNames = const {},
    bool checkAAAAForOriginal = true,
  }) async {
    if (!parsed.ok) return null;
    final chain = DomainInputParser.buildParentDomains(parsed.normalizedHost);
    if (chain.isEmpty) return null;

    final tasks = <({String host, String qtype, bool isOriginal})>[
      (host: chain.first, qtype: 'A', isOriginal: true),
      if (checkAAAAForOriginal && !parsed.isIpAddress)
        (host: chain.first, qtype: 'AAAA', isOriginal: true),
      for (final parent in chain.skip(1))
        (host: parent, qtype: 'A', isOriginal: false),
    ];

    final results = List<HostCheckResult?>.filled(tasks.length, null);
    var cursor = 0;

    Future<void> worker() async {
      while (true) {
        if (isCancelled()) return;
        final idx = cursor;
        if (idx >= tasks.length) return;
        cursor++;

        final task = tasks[idx];
        ApiResponse resp;
        try {
          resp = await checker(task.host, task.qtype).timeout(perItemTimeout);
        } on TimeoutException {
          resp = const ApiResponse(successful: false, content: '超时');
        } catch (e) {
          resp = ApiResponse(successful: false, content: e.toString());
        }
        if (isCancelled()) return;

        results[idx] = HostCheckResult.fromApiResponse(
          host: task.host,
          response: resp,
          isOriginal: task.isOriginal,
          qtype: task.qtype,
          filterNames: filterNames,
          whitelistNames: whitelistNames,
        );
      }
    }

    final workerCount = tasks.length < maxConcurrency ? tasks.length : maxConcurrency;
    await Future.wait(List.generate(workerCount, (_) => worker()));
    if (isCancelled()) return null;

    final origA = results[0] ??
        HostCheckResult(
          host: chain.first,
          isOriginal: true,
          status: RuleCheckStatus.failed,
          rawReason: '',
          rules: const [],
          errorDetail: '未完成',
        );
    final hasAAAA = checkAAAAForOriginal && !parsed.isIpAddress;
    final origAAAA = hasAAAA ? results[1] : null;
    final parentStart = hasAAAA ? 2 : 1;
    final parentResults = <HostCheckResult>[
      for (var i = parentStart; i < results.length; i++)
        if (results[i] != null) results[i]!,
    ];

    return HostFamilyCheckReport(
      parsedInput: parsed,
      originalA: origA,
      originalAAAA: origAAAA,
      parentResults: parentResults,
    );
  }
}

/// 核心 `/control/querylog/blocked_summary` 解析模型。
class BlockedSummaryData {
  final int maxEntries;
  final int ttlSeconds;
  final String retentionNote;
  final List<BlockedSummaryEntry> entries;

  const BlockedSummaryData({
    required this.maxEntries,
    required this.ttlSeconds,
    required this.retentionNote,
    required this.entries,
  });

  factory BlockedSummaryData.fromJson(Map<String, dynamic> json) {
    final rawList = json['data'] is List ? (json['data'] as List) : const [];
    return BlockedSummaryData(
      maxEntries: (json['max_entries'] as num?)?.toInt() ?? 256,
      ttlSeconds: (json['ttl_seconds'] as num?)?.toInt() ?? 300,
      retentionNote: (json['retention_note'] ?? '').toString(),
      entries: rawList
          .whereType<Map>()
          .map((m) => BlockedSummaryEntry.fromJson(Map<String, dynamic>.from(m)))
          .toList(),
    );
  }
}

class BlockedSummaryEntry {
  final String domain;
  final String reason;
  final bool isSni;
  final int count;
  final DateTime firstTime;
  final DateTime time;
  final String client;
  final String? clientId;
  final String? destination;
  final List<Rule> rules;
  final String? legacyRule;
  final int? legacyFilterId;

  const BlockedSummaryEntry({
    required this.domain,
    required this.reason,
    required this.isSni,
    required this.count,
    required this.firstTime,
    required this.time,
    required this.client,
    this.clientId,
    this.destination,
    required this.rules,
    this.legacyRule,
    this.legacyFilterId,
  });

  factory BlockedSummaryEntry.fromJson(Map<String, dynamic> json) {
    final qMap = json['question'] is Map
        ? Map<String, dynamic>.from(json['question'] as Map)
        : const <String, dynamic>{};
    final domain = (json['domain'] ?? qMap['name'] ?? '').toString().trim();
    final reason = (json['reason'] ?? 'FilteredBlackList').toString();
    final parsedRules = json['rules'] is List
        ? (json['rules'] as List)
            .whereType<Map>()
            .map((r) => Rule.fromJson(Map<String, dynamic>.from(r)))
            .toList()
        : <Rule>[];
    final legacyRule = json['rule']?.toString();
    final rawLegacyId = json['filterId'] ?? json['filter_id'];
    final legacyFilterId = rawLegacyId is int
        ? rawLegacyId
        : int.tryParse(rawLegacyId?.toString() ?? '');
    if (parsedRules.isEmpty && legacyRule != null && legacyRule.isNotEmpty) {
      parsedRules.add(Rule(filterListId: legacyFilterId ?? 0, text: legacyRule));
    }

    return BlockedSummaryEntry(
      domain: domain,
      reason: reason,
      isSni: json['is_sni'] == true || reason == 'FilteredSNI',
      count: (json['count'] as num?)?.toInt() ?? 1,
      firstTime: DateTime.tryParse((json['first_time'] ?? '').toString()) ??
          DateTime.fromMillisecondsSinceEpoch(0),
      time: DateTime.tryParse((json['time'] ?? '').toString()) ??
          DateTime.fromMillisecondsSinceEpoch(0),
      client: (json['client'] ?? '').toString(),
      clientId: json['client_id']?.toString(),
      destination: json['destination']?.toString(),
      rules: parsedRules,
      legacyRule: legacyRule,
      legacyFilterId: legacyFilterId,
    );
  }
}

/// 同秒/同域名/同来源(DNS vs SNI)/同命中规则聚合条目（保留底层原始事件供展开核验）。
class AggregatedLogGroup {
  final String domain;
  final bool isSni;
  final String reason;
  final DateTime time;
  final DateTime? firstTime;
  final int count;
  final List<MatchedRuleInfo> matchedRules;
  final String primaryRuleText;
  final String clientLabel;
  final String? destination;
  final List<Log> rawEvents;
  final bool isFromCoreSummary;
  final bool isNewAfterCapture;

  const AggregatedLogGroup({
    required this.domain,
    required this.isSni,
    required this.reason,
    required this.time,
    this.firstTime,
    required this.count,
    required this.matchedRules,
    required this.primaryRuleText,
    required this.clientLabel,
    this.destination,
    required this.rawEvents,
    this.isFromCoreSummary = false,
    this.isNewAfterCapture = false,
  });
}

/// 统一 SNI/DNS 分类及先聚合再限长折叠工具（供首页排查面板与「日志」页共用）。
class BlockedEventAggregator {
  BlockedEventAggregator._();

  /// 优先按核心实际 reason 判断 SNI 事件，兼容旧版本 client_proto / question.type 辅助识别。
  static bool isSniEvent(Log log) {
    if (log.reason == 'FilteredSNI' || log.reason == 'NotFilteredSNI') {
      return true;
    }
    if (log.question.type.toUpperCase() == 'SNI') {
      return true;
    }
    return log.clientProto?.toLowerCase().contains('sni') ?? false;
  }

  static List<MatchedRuleInfo> extractRulesFromLog(
    Log log, {
    Map<int, String> filterNames = const {},
    Map<int, String> whitelistNames = const {},
  }) {
    final out = <MatchedRuleInfo>[];
    final seen = <String>{};
    for (final r in log.rules) {
      final text = r.text.trim();
      if (text.isEmpty) continue;
      final k = '${r.filterListId}\x00$text';
      if (!seen.add(k)) continue;
      out.add(MatchedRuleInfo(
        text: text,
        filterListId: r.filterListId,
        sourceName: MatchedRuleInfo.resolveSourceName(
          r.filterListId,
          filterNames: filterNames,
          whitelistNames: whitelistNames,
        ),
        isCustomRule: r.filterListId == 0,
        isImportant: HostCheckResult._ruleHasImportantModifier(text),
      ));
    }
    if (out.isEmpty && (log.rule?.trim().isNotEmpty == true)) {
      final t = log.rule!.trim();
      final id = log.filterId ?? 0;
      out.add(MatchedRuleInfo(
        text: t,
        filterListId: id,
        sourceName: MatchedRuleInfo.resolveSourceName(
          id,
          filterNames: filterNames,
          whitelistNames: whitelistNames,
        ),
        isCustomRule: id == 0,
        isImportant: HostCheckResult._ruleHasImportantModifier(t),
      ));
    }
    return out;
  }

  static String _rulesSignature(List<MatchedRuleInfo> rules, String reason) {
    if (rules.isEmpty) return reason;
    final parts = rules.map((r) => '${r.filterListId}:${r.text}').toList()..sort();
    return parts.join('|');
  }

  /// 按“同一秒 + 同一域名 + 同一来源(DNS/SNI) + 同一 reason + 同一命中规则 + 同一客户端上下文”
  /// 先聚合折叠，再保持确定性排序后允许上层截取显示数量；绝不把不同规则、DNS/SNI 或不同客户端混成一条。
  static List<AggregatedLogGroup> aggregateRawLogs(
    List<Log> logs, {
    Map<int, String> filterNames = const {},
    Map<int, String> whitelistNames = const {},
    int? maxGroups,
  }) {
    final buckets = <String, List<Log>>{};
    final ruleMeta = <String, List<MatchedRuleInfo>>{};

    for (final log in logs) {
      final domain = (log.question.name ?? '').trim();
      if (domain.isEmpty) continue;
      final secEpoch = log.time.millisecondsSinceEpoch ~/ 1000;
      final isSni = isSniEvent(log);
      final rules = extractRulesFromLog(
        log,
        filterNames: filterNames,
        whitelistNames: whitelistNames,
      );
      final rulesSig = _rulesSignature(rules, log.reason);
      final clientCtx = log.client.isNotEmpty
          ? log.client
          : (log.clientInfo?.name ?? '');
      final key =
          '$secEpoch\x00${domain.toLowerCase()}\x00${isSni ? "SNI" : "DNS"}\x00${log.reason}\x00$rulesSig\x00$clientCtx';
      buckets.putIfAbsent(key, () => <Log>[]).add(log);
      ruleMeta.putIfAbsent(key, () => rules);
    }

    final groups = <AggregatedLogGroup>[];
    for (final entry in buckets.entries) {
      final raw = entry.value;
      raw.sort((a, b) => b.time.compareTo(a.time));
      final latest = raw.first;
      final earliest = raw.last;
      final domain = (latest.question.name ?? '').trim();
      final isSni = isSniEvent(latest);
      final rules = ruleMeta[entry.key]!;
      final clientLabel = latest.clientInfo?.name.isNotEmpty == true
          ? '${latest.clientInfo!.name} (${latest.client})'
          : latest.client;
      groups.add(AggregatedLogGroup(
        domain: domain,
        isSni: isSni,
        reason: latest.reason,
        time: latest.time,
        firstTime: earliest.time,
        count: raw.length,
        matchedRules: rules,
        primaryRuleText: rules.isNotEmpty ? rules.first.text : latest.reason,
        clientLabel: clientLabel,
        destination: latest.destination,
        rawEvents: List<Log>.unmodifiable(raw),
      ));
    }

    // 确定性排序：时间倒序 -> SNI/DNS -> 域名 -> 规则签名
    groups.sort((a, b) {
      final cmpTime = b.time.compareTo(a.time);
      if (cmpTime != 0) return cmpTime;
      if (a.isSni != b.isSni) return a.isSni ? -1 : 1;
      final cmpDom = a.domain.toLowerCase().compareTo(b.domain.toLowerCase());
      if (cmpDom != 0) return cmpDom;
      return a.primaryRuleText.compareTo(b.primaryRuleText);
    });

    if (maxGroups != null && maxGroups > 0 && groups.length > maxGroups) {
      return groups.sublist(0, maxGroups);
    }
    return groups;
  }

  /// 将 Core 持久聚合摘要与当前未聚合/本地捕获结果组合：
  /// Core `/querylog/blocked_summary` 中的事件能兜底保留未被 500 条环形队列挤出的关键拦截。
  static List<AggregatedLogGroup> fromBlockedSummary(
    BlockedSummaryData summary, {
    Map<int, String> filterNames = const {},
    Map<int, String> whitelistNames = const {},
  }) {
    final groups = <AggregatedLogGroup>[];
    for (final item in summary.entries) {
      final rules = <MatchedRuleInfo>[];
      final seen = <String>{};
      for (final r in item.rules) {
        final t = r.text.trim();
        if (t.isEmpty) continue;
        final k = '${r.filterListId}\x00$t';
        if (!seen.add(k)) continue;
        rules.add(MatchedRuleInfo(
          text: t,
          filterListId: r.filterListId,
          sourceName: MatchedRuleInfo.resolveSourceName(
            r.filterListId,
            filterNames: filterNames,
            whitelistNames: whitelistNames,
          ),
          isCustomRule: r.filterListId == 0,
          isImportant: HostCheckResult._ruleHasImportantModifier(t),
        ));
      }
      final synthLog = Log(
        cached: false,
        client: item.client,
        clientProto: item.isSni ? 'sni' : '',
        elapsedMs: '',
        question: Question(
          questionClass: 'IN',
          name: item.domain,
          type: 'A',
        ),
        reason: item.reason,
        rules: item.rules,
        time: item.time,
        upstream: '',
        destination: item.destination,
        answer: const [],
        filterId: item.legacyFilterId,
        rule: item.legacyRule,
      );
      groups.add(AggregatedLogGroup(
        domain: item.domain,
        isSni: item.isSni,
        reason: item.reason,
        time: item.time,
        firstTime: item.firstTime,
        count: item.count,
        matchedRules: rules,
        primaryRuleText: rules.isNotEmpty ? rules.first.text : item.reason,
        clientLabel: item.clientId?.isNotEmpty == true
            ? '${item.clientId} (${item.client})'
            : item.client,
        destination: item.destination,
        rawEvents: <Log>[synthLog],
        isFromCoreSummary: true,
      ));
    }
    groups.sort((a, b) => b.time.compareTo(a.time));
    return groups;
  }
}

/// 两级放行方案建议：明确区分“放行此子域名”与“放行命中规则域名”，不自动扩大至根域，也不隐式添加 $important。
class WhitelistSuggestion {
  final String? narrowTargetHost;
  final String? narrowRule;
  final String narrowDescription;

  final String? broadTargetHost;
  final String? broadRule;
  final String? broadDisabledReason;
  final String? broadDescription;
  final bool matchedImportantBlock;

  const WhitelistSuggestion({
    required this.narrowTargetHost,
    required this.narrowRule,
    required this.narrowDescription,
    required this.broadTargetHost,
    required this.broadRule,
    this.broadDisabledReason,
    this.broadDescription,
    this.matchedImportantBlock = false,
  });
}

class WhitelistPlanner {
  WhitelistPlanner._();

  static final RegExp _simpleAnchorRuleRe = RegExp(
    r'^\|\|([a-z0-9](?:[a-z0-9._-]*[a-z0-9])?)\^(\$.*)?$',
    caseSensitive: false,
  );

  /// 仅从明确安全的域名锚定规则（如 `||ct.sendgrid.net^` 或带无路径修饰符的 `||ct.sendgrid.net^$important`）
  /// 中提取规则目标域名；正则、通配符、`||host/path`、`||net^`、公共后缀及无效语法一律返回 null。
  static String? extractSafeAnchorDomain(String rawRule) {
    final trimmed = rawRule.trim();
    if (trimmed.isEmpty) return null;
    if (trimmed.startsWith('@@') || trimmed.startsWith('!') || trimmed.startsWith('#')) {
      return null;
    }
    // 拒绝正则 /.../
    if (trimmed.startsWith('/')) return null;
    // 拒绝通配符 * 或路径 / ? =
    final dollarIdx = trimmed.indexOf(r'$');
    final body = dollarIdx >= 0 ? trimmed.substring(0, dollarIdx) : trimmed;
    if (body.contains('*') || body.contains('/')) return null;

    final m = _simpleAnchorRuleRe.firstMatch(trimmed);
    if (m == null) return null;

    final candidate = (m.group(1) ?? '').toLowerCase();
    if (candidate.isEmpty ||
        candidate.contains('..') ||
        DomainInputParser.isPublicSuffix(candidate) ||
        InternetAddress.tryParse(candidate) != null) {
      return null;
    }
    if (!candidate.contains('.')) return null;

    // 若携带 $modifiers，检查不包含改变规则语义到纯改写的选项以外也允许提取（仅 $important/$third-party 等正常阻断修饰）
    return candidate;
  }

  /// 基于原域名与实际命中规则生成两级加白方案。
  static WhitelistSuggestion buildSuggestion({
    required String originalHost,
    required List<MatchedRuleInfo> matchedRules,
  }) {
    final cleanHost = originalHost.trim().toLowerCase();
    final isValidNonSuffixHost = cleanHost.isNotEmpty &&
        !DomainInputParser.isPublicSuffix(cleanHost) &&
        InternetAddress.tryParse(cleanHost) == null;

    final narrowTarget = isValidNonSuffixHost ? cleanHost : null;
    final narrowRule = narrowTarget != null ? '@@||$narrowTarget^' : null;
    final parentHint = (narrowTarget != null && narrowTarget.contains('.'))
        ? narrowTarget.substring(narrowTarget.indexOf('.') + 1)
        : '上级域名';
    final narrowDesc = narrowTarget != null
        ? '放行此域名及其下级域名，不放行 $parentHint 下的其他兄弟子域名'
        : '当前地址为 IP 或公共后缀，不提供子域名放行规则';

    final matchedImportant = matchedRules.any((r) => r.isImportant);
    String? broadTarget;
    String? broadDisabledReason;

    if (matchedRules.isEmpty) {
      broadDisabledReason = '未检测到可解析的具体阻断规则文本，不能生成宽范围规则放行建议';
    } else {
      final candidates = <String>[];
      for (final r in matchedRules) {
        final ext = extractSafeAnchorDomain(r.text);
        if (ext == null) {
          broadDisabledReason ??= '命中的规则含正则、通配符、路径或公共后缀 (${r.text})，无法安全解析为单一宽范围域名';
          continue;
        }
        if (!candidates.contains(ext)) {
          candidates.add(ext);
        }
      }

      if (candidates.length == 1) {
        final cand = candidates.first;
        if (cand == cleanHost) {
          broadDisabledReason = '命中规则域名与当前域名相同，无需更宽范围放行';
        } else {
          broadTarget = cand;
          broadDisabledReason = null;
        }
      } else if (candidates.length > 1) {
        // 多条可解析规则时选择与原域名共享的最窄非原域规则，绝不扩大成可注册根域
        final others = candidates.where((c) => c != cleanHost).toList();
        if (others.isNotEmpty) {
          others.sort((a, b) => b.length.compareTo(a.length));
          broadTarget = others.first;
          broadDisabledReason = null;
        } else {
          broadDisabledReason = '命中规则目标均为当前域名本身';
        }
      }
    }

    final broadRule = broadTarget != null ? '@@||$broadTarget^' : null;
    final broadDesc = broadTarget != null
        ? '会放行 $broadTarget 及其所有下级域名，范围更大，可能同时放行其他追踪链接。'
        : null;

    return WhitelistSuggestion(
      narrowTargetHost: narrowTarget,
      narrowRule: narrowRule,
      narrowDescription: narrowDesc,
      broadTargetHost: broadTarget,
      broadRule: broadRule,
      broadDisabledReason: broadDisabledReason,
      broadDescription: broadDesc,
      matchedImportantBlock: matchedImportant,
    );
  }
}

/// 写入并核验例外的完整结果（明确区分：写后确认生效 / 仍被 $important 阻断 / 写后核验失败 / 写入失败）。
class ExceptionWriteOutcome {
  final bool writeSucceeded;
  final bool verifiedUnblocked;
  final bool stillBlockedByImportant;
  final String? addedRule;
  final HostCheckResult? postCheckResult;
  final String message;

  const ExceptionWriteOutcome({
    required this.writeSucceeded,
    required this.verifiedUnblocked,
    this.stillBlockedByImportant = false,
    this.addedRule,
    this.postCheckResult,
    required this.message,
  });
}

/// 安全的例外规则写入与撤销协调器：
/// - 串行互斥锁防止并发写丢失其他用户规则；
/// - 写入前实时读取 `/filtering/status` 的 `user_rules`，原样保留全部既有规则顺序与注释，仅追加新增例外；
/// - 绝不静默删改已有拦截规则，也绝不自动加 `$important`；
/// - 写入后回读 `/filtering/status` 确认持久化、刷新核心与系统 DNS 缓存，再调用 `/filtering/check_host` 真实核验是否解除阻断。
class ExceptionRuleCoordinator {
  Future<void> _writeTail = Future<void>.value();

  Future<T> _serialized<T>(Future<T> Function() fn) {
    final completer = Completer<T>();
    _writeTail = _writeTail.catchError((_) {}).then((_) async {
      try {
        completer.complete(await fn());
      } catch (e, st) {
        completer.completeError(e, st);
      }
    });
    return completer.future;
  }

  Future<ExceptionWriteOutcome> applyExceptionAndVerify({
    required ApiClientV2 apiClient,
    required String verifyHost,
    required String exceptionRule,
    Future<void> Function()? flushSystemDnsCache,
    Map<int, String> filterNames = const {},
    Map<int, String> whitelistNames = const {},
  }) {
    return _serialized(() async {
      final cleanRule = exceptionRule.trim();
      if (cleanRule.isEmpty) {
        return const ExceptionWriteOutcome(
          writeSucceeded: false,
          verifiedUnblocked: false,
          message: '例外规则为空',
        );
      }

      // 1) 获取当前最新 user_rules，避免覆盖或丢失既有规则
      final beforeFiltering = await apiClient.getFiltering();
      if (!beforeFiltering.successful || beforeFiltering.content is! Filtering) {
        return const ExceptionWriteOutcome(
          writeSucceeded: false,
          verifiedUnblocked: false,
          message: '读取当前自定义规则失败，未修改任何规则',
        );
      }
      final filteringData = beforeFiltering.content as Filtering;
      final existingRules = List<String>.from(filteringData.userRules);
      final alreadyExists = existingRules.any((r) => r.trim() == cleanRule);

      final updatedRules = List<String>.from(existingRules);
      String? addedRule;
      if (!alreadyExists) {
        updatedRules.add(cleanRule);
        addedRule = cleanRule;

        final setRes = await apiClient.setCustomRules(rules: updatedRules);
        if (!setRes.successful) {
          return const ExceptionWriteOutcome(
            writeSucceeded: false,
            verifiedUnblocked: false,
            message: '提交例外规则失败，请重试',
          );
        }

        // 2) 回读 /filtering/status 确认核心确实已应用该规则
        final confirmRes = await apiClient.getFiltering();
        if (!confirmRes.successful || confirmRes.content is! Filtering) {
          return ExceptionWriteOutcome(
            writeSucceeded: true,
            verifiedUnblocked: false,
            addedRule: addedRule,
            message: '规则已提交，但回读确认核心状态失败，请手动检查',
          );
        }
        final persisted = (confirmRes.content as Filtering)
            .userRules
            .any((r) => r.trim() == cleanRule);
        if (!persisted) {
          return const ExceptionWriteOutcome(
            writeSucceeded: false,
            verifiedUnblocked: false,
            message: '核心状态回读未包含新增规则，写入未生效',
          );
        }
      }

      // 3) 清理核心 DNS 缓存与 Android 系统缓存
      await apiClient.resetDnsCache();
      if (flushSystemDnsCache != null) {
        await flushSystemDnsCache();
      } else if (Platform.isAndroid) {
        // 默认由外部调用方传入 ModuleConfigService().flushSystemDnsCache，保持核心协调器可测解耦
      }

      // 4) 用 /filtering/check_host 重新检测原域名（检查 A 与 AAAA）
      final checkA = await apiClient.checkHostFiltered(host: verifyHost, qtype: 'A');
      final resA = HostCheckResult.fromApiResponse(
        host: verifyHost,
        response: checkA,
        isOriginal: true,
        qtype: 'A',
        filterNames: filterNames,
        whitelistNames: whitelistNames,
      );

      HostCheckResult effective = resA;
      if (resA.status == RuleCheckStatus.notBlocked ||
          resA.status == RuleCheckStatus.whitelisted) {
        final checkAAAA =
            await apiClient.checkHostFiltered(host: verifyHost, qtype: 'AAAA');
        final resAAAA = HostCheckResult.fromApiResponse(
          host: verifyHost,
          response: checkAAAA,
          isOriginal: true,
          qtype: 'AAAA',
          filterNames: filterNames,
          whitelistNames: whitelistNames,
        );
        if (resAAAA.isBlocked) {
          effective = resAAAA;
        }
      }

      if (effective.status == RuleCheckStatus.whitelisted ||
          effective.status == RuleCheckStatus.notBlocked) {
        return ExceptionWriteOutcome(
          writeSucceeded: true,
          verifiedUnblocked: true,
          addedRule: addedRule,
          postCheckResult: effective,
          message: '放行已生效（已断开的旧 SNI 连接无法自动恢复，请重新点击原链接触发新连接）',
        );
      }

      if (effective.isBlocked) {
        if (effective.hasImportantBlock) {
          return ExceptionWriteOutcome(
            writeSucceeded: true,
            verifiedUnblocked: false,
            stillBlockedByImportant: true,
            addedRule: addedRule,
            postCheckResult: effective,
            message: '规则已写入，但原域名仍被带 \$important 优先级规则阻断（普通例外无法覆盖）',
          );
        }
        final topRule =
            effective.rules.isNotEmpty ? effective.rules.first.text : effective.rawReason;
        return ExceptionWriteOutcome(
          writeSucceeded: true,
          verifiedUnblocked: false,
          addedRule: addedRule,
          postCheckResult: effective,
          message: '规则已写入，但实时检测仍被规则阻断：$topRule',
        );
      }

      return ExceptionWriteOutcome(
        writeSucceeded: true,
        verifiedUnblocked: false,
        addedRule: addedRule,
        postCheckResult: effective,
        message: '规则已写入，但写后核验未能确认（${effective.statusLabel}）',
      );
    });
  }

  /// 精准撤销本次操作明确添加的那条例外规则，绝不误删用户此前已有的任何规则。
  Future<({bool ok, String message})> undoAddedException({
    required ApiClientV2 apiClient,
    required String addedRule,
    Future<void> Function()? flushSystemDnsCache,
  }) {
    return _serialized(() async {
      final clean = addedRule.trim();
      final res = await apiClient.getFiltering();
      if (!res.successful || res.content is! Filtering) {
        return (ok: false, message: '读取当前自定义规则失败，未能撤销');
      }
      final current = List<String>.from((res.content as Filtering).userRules);
      // 仅删除最后一次匹配的该条规则（保留任何用户原有规则与顺序）
      final idx = current.lastIndexWhere((r) => r.trim() == clean);
      if (idx < 0) {
        return (ok: true, message: '规则已不存在，无需重复撤销');
      }
      current.removeAt(idx);

      final saveRes = await apiClient.setCustomRules(rules: current);
      if (!saveRes.successful) {
        return (ok: false, message: '撤销保存失败，请重试');
      }
      await apiClient.resetDnsCache();
      if (flushSystemDnsCache != null) {
        await flushSystemDnsCache();
      }
      return (ok: true, message: '已撤销本次新增的例外规则：$clean');
    });
  }

  @visibleForTesting
  static String? safeAnchorForTest(String rule) =>
      WhitelistPlanner.extractSafeAnchorDomain(rule);
}
