import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';

import 'package:adguard_home_manager/models/filtering.dart';
import 'package:adguard_home_manager/models/logs.dart';
import 'package:adguard_home_manager/models/server.dart';
import 'package:adguard_home_manager/services/api_client.dart';
import 'package:adguard_home_manager/services/domain_input_parser.dart';
import 'package:adguard_home_manager/services/manual_rule_provenance_service.dart';

/// 实时规则检测状态（严格区分查询失败/不支持/未知结果、重写与真实放行）。
enum RuleCheckStatus {
  blocked,
  whitelisted,
  rewritten,
  notBlocked,
  failed,
  unsupported,
  unknown,
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
  bool get isUnblockedSuccess =>
      status == RuleCheckStatus.whitelisted ||
      status == RuleCheckStatus.notBlocked;
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
      case RuleCheckStatus.unknown:
        return rawReason.isNotEmpty
            ? '未知检测结果（$rawReason）'
            : '未知检测结果';
      case RuleCheckStatus.failed:
        return errorDetail != null && errorDetail!.isNotEmpty
            ? '查询失败（$errorDetail）'
            : '查询失败／超时／未连接';
    }
  }

  static RuleCheckStatus classifyReason(String reason) {
    switch (reason) {
      case 'FilteredBlackList':
      case 'FilteredBlockList':
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
        return RuleCheckStatus.notBlocked;
      case 'NotFilteredError':
        return RuleCheckStatus.failed;
      default:
        return RuleCheckStatus.unknown;
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

    final status = classifyReason(reason);
    String? reasonDetail;
    if (status == RuleCheckStatus.failed) {
      reasonDetail = '核心返回错误状态 ($reason)';
    } else if (status == RuleCheckStatus.unknown) {
      reasonDetail = '核心返回未知状态 ($reason)';
    }

    return HostCheckResult(
      host: host,
      isOriginal: isOriginal,
      status: status,
      rawReason: reason,
      rules: parsedRules,
      qtype: qtype,
      errorDetail: reasonDetail,
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
    final diffNote = 'A=${originalA.statusLabel}, AAAA=${aaaa.statusLabel}';

    // 任一阻断：优先突出展示被阻断的记录类型与命中规则
    if (originalA.isBlocked) {
      return HostCheckResult(
        host: originalA.host,
        isOriginal: true,
        status: originalA.status,
        rawReason: originalA.rawReason,
        rules: originalA.rules,
        qtype: 'A',
        secondaryQtypeNote: originalA.status == aaaa.status ? null : diffNote,
      );
    }
    if (aaaa.isBlocked) {
      return HostCheckResult(
        host: aaaa.host,
        isOriginal: true,
        status: aaaa.status,
        rawReason: aaaa.rawReason,
        rules: aaaa.rules,
        qtype: 'AAAA',
        secondaryQtypeNote: diffNote,
      );
    }

    // 保留重写独立语义
    if (originalA.status == RuleCheckStatus.rewritten) {
      return HostCheckResult(
        host: originalA.host,
        isOriginal: true,
        status: originalA.status,
        rawReason: originalA.rawReason,
        rules: originalA.rules,
        qtype: 'A',
        secondaryQtypeNote: originalA.status == aaaa.status ? null : diffNote,
      );
    }
    if (aaaa.status == RuleCheckStatus.rewritten) {
      return HostCheckResult(
        host: aaaa.host,
        isOriginal: true,
        status: aaaa.status,
        rawReason: aaaa.rawReason,
        rules: aaaa.rules,
        qtype: 'AAAA',
        secondaryQtypeNote: diffNote,
      );
    }

    // 任一失败、不支持或未知：绝不伪装成完全正常的未阻断
    if (originalA.status == RuleCheckStatus.failed ||
        originalA.status == RuleCheckStatus.unsupported ||
        originalA.status == RuleCheckStatus.unknown) {
      return HostCheckResult(
        host: originalA.host,
        isOriginal: true,
        status: originalA.status,
        rawReason: originalA.rawReason,
        rules: originalA.rules,
        qtype: originalA.qtype,
        errorDetail: originalA.errorDetail,
        secondaryQtypeNote: originalA.status == aaaa.status ? null : diffNote,
      );
    }
    if (aaaa.status == RuleCheckStatus.failed ||
        aaaa.status == RuleCheckStatus.unsupported ||
        aaaa.status == RuleCheckStatus.unknown) {
      return HostCheckResult(
        host: aaaa.host,
        isOriginal: true,
        status: aaaa.status,
        rawReason: aaaa.rawReason,
        rules: aaaa.rules,
        qtype: 'AAAA',
        errorDetail: aaaa.errorDetail,
        secondaryQtypeNote: diffNote,
      );
    }

    if (originalA.status != aaaa.status) {
      return HostCheckResult(
        host: originalA.host,
        isOriginal: true,
        status: originalA.status,
        rawReason: originalA.rawReason,
        rules: originalA.rules,
        qtype: originalA.qtype,
        secondaryQtypeNote: diffNote,
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
    if (trimmed.startsWith('/')) return null;
    final dollarIdx = trimmed.indexOf(r'$');
    final body = dollarIdx >= 0 ? trimmed.substring(0, dollarIdx) : trimmed;
    if (body.contains('*') || body.contains('/')) return null;

    final m = _simpleAnchorRuleRe.firstMatch(trimmed);
    if (m == null) return null;

    final candidate = (m.group(1) ?? '').toLowerCase();
    if (!DomainInputParser.isValidHostname(candidate) ||
        DomainInputParser.isPublicSuffix(candidate)) {
      return null;
    }

    return candidate;
  }

  /// 基于原域名、离线 PSL 边界与实际命中规则生成两级加白方案。
  static WhitelistSuggestion buildSuggestion({
    required String originalHost,
    required List<MatchedRuleInfo> matchedRules,
  }) {
    final cleanHost = originalHost.trim().toLowerCase();
    final hostPsl = DomainInputParser.inspectPublicSuffix(cleanHost);
    final isValidNonSuffixHost = DomainInputParser.isValidHostname(cleanHost) &&
        !DomainInputParser.isPublicSuffix(cleanHost);

    final narrowTarget = isValidNonSuffixHost ? cleanHost : null;
    final narrowRule = narrowTarget != null ? '@@||$narrowTarget^' : null;
    final parentHint = (narrowTarget != null && narrowTarget.contains('.'))
        ? narrowTarget.substring(narrowTarget.indexOf('.') + 1)
        : '上级域名';
    final narrowDesc = narrowTarget != null
        ? '放行此域名及其下级域名，不放行 $parentHint 下的其他兄弟子域名'
        : '当前地址无效、为 IP 或公共后缀，不提供子域名放行规则';

    final matchedImportant = matchedRules.any((r) => r.isImportant);
    String? broadTarget;
    String? broadDisabledReason;

    if (hostPsl == null || !hostPsl.isKnownRule || hostPsl.registrableDomain == null) {
      broadDisabledReason =
          '离线 PSL 无法可靠判定当前域名的可注册边界，已禁用宽范围加白（不回退猜最后两段）';
    } else if (matchedRules.isEmpty) {
      broadDisabledReason = '未检测到可解析的具体阻断规则文本，不能生成宽范围规则放行建议';
    } else {
      final candidates = <String>[];
      for (final r in matchedRules) {
        final ext = extractSafeAnchorDomain(r.text);
        if (ext == null) {
          broadDisabledReason ??=
              '命中的规则含正则、通配符、路径、公共后缀或无效域名 (${r.text})，无法安全解析为单一宽范围域名';
          continue;
        }
        final candPsl = DomainInputParser.inspectPublicSuffix(ext);
        if (candPsl == null || !candPsl.isKnownRule || candPsl.isPublicSuffix) {
          broadDisabledReason ??=
              '命中规则域名 ($ext) 为公共后缀或无法通过 PSL 可靠判定边界，已禁用宽范围放行';
          continue;
        }
        // 严格包含关系校验：目标必须等于原域名或为原域名的祖先（原域名以 "." + cand 结尾）
        final isAncestorOrSame =
            cleanHost == ext || cleanHost.endsWith('.$ext');
        if (!isAncestorOrSame) {
          broadDisabledReason ??=
              '命中规则域名 ($ext) 与当前域名 ($cleanHost) 无层级包含关系，不从无关规则生成宽范围建议';
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
        final others = candidates.where((c) => c != cleanHost).toList();
        if (others.isNotEmpty) {
          // 优先选择最窄的非当前域名规则（长度最长），不主动扩大至可注册根域
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

/// 规则状态与本地变更历史追踪（按服务器隔离的共享写入队列，防止多页面/多协调器互相覆盖）。
/// 说明：同一台服务器上的不同客户端（如 Web UI 或另一台手机）并发修改需依赖核心的
/// `expected_revision` 条件更新检测（旧核心不返回 `user_rules_revision` 时仅做尽力防误删检查）。
class ServerRuleWriteQueue {
  ServerRuleWriteQueue._();

  static final Map<String, _ServerQueueState> _queues =
      <String, _ServerQueueState>{};

  static String serverKeyFor(Server server) {
    final normDomain = server.domain.trim().toLowerCase();
    final normPath = (server.path ?? '').trim();
    return '${server.id}|${server.connectionMethod.toLowerCase()}|$normDomain|${server.port ?? ""}|$normPath';
  }

  static String fingerprintRules(List<String> rules) {
    final buf = StringBuffer('${rules.length}#');
    for (final r in rules) {
      buf
        ..write(r.length)
        ..write(':')
        ..write(r)
        ..write('\n');
    }
    return buf.toString();
  }

  static _ServerQueueState _stateFor(Server server) {
    final key = serverKeyFor(server);
    return _queues.putIfAbsent(key, () => _ServerQueueState());
  }

  /// 在指定服务器的共享串行队列中执行规则读写操作；不同服务器之间完全并发互不阻塞；
  /// 前序任务抛错后队列自动恢复，不会卡死后续任务。
  static Future<T> run<T>(
    Server server,
    Future<T> Function(ServerQueueSession session) fn,
  ) {
    final key = serverKeyFor(server);
    final st = _stateFor(server);
    final completer = Completer<T>();

    st.tail = st.tail.catchError((_) {}).then((_) async {
      try {
        final session = ServerQueueSession._(serverKey: key, state: st);
        completer.complete(await fn(session));
      } catch (e, stTrace) {
        completer.completeError(e, stTrace);
      }
    });

    return completer.future;
  }

  static int currentLocalEpoch(Server server) => _stateFor(server).localEpoch;

  @visibleForTesting
  static void resetForTest() {
    _queues.clear();
  }
}

class _ServerQueueState {
  Future<void> tail = Future<void>.value();
  int localEpoch = 0;
}

class ServerQueueSession {
  final String serverKey;
  final _ServerQueueState _state;

  const ServerQueueSession._({
    required this.serverKey,
    required _ServerQueueState state,
  }) : _state = state;

  int get localEpoch => _state.localEpoch;

  int bumpLocalEpoch() {
    _state.localEpoch++;
    return _state.localEpoch;
  }
}

/// 可核验的例外规则新增凭证：用于撤销前证明目标规则仍属于该次操作而非用户删改后同文本重加。
/// 仅在 Core 返回可靠的提交 `X-User-Rules-Revision` 且回读状态（版本与完整规则逐项指纹）
/// 严格等于本次提交状态时签发。
class ExceptionUndoToken {
  final String serverKey;
  final String rule;
  final int addedIndex;
  final String confirmedRevision;
  final String confirmedRulesFingerprint;
  final int confirmedLocalEpoch;

  const ExceptionUndoToken({
    required this.serverKey,
    required this.rule,
    required this.addedIndex,
    required this.confirmedRevision,
    required this.confirmedRulesFingerprint,
    required this.confirmedLocalEpoch,
  });
}

/// 写入并核验例外的完整结果。
class ExceptionWriteOutcome {
  final bool writeSucceeded;
  final bool verifiedUnblocked;
  final bool stillBlockedByImportant;
  final bool verificationIncomplete;
  final bool cacheFlushFailed;
  final bool conflictDetected;
  final bool provenanceSaveFailed;
  final bool provenanceInterrupted;
  final bool provenanceLegacyUnconfirmed;
  final String? addedRule;
  final ExceptionUndoToken? undoToken;
  final String? undoDisabledReason;
  final HostCheckResult? postCheckResult;
  final HostCheckResult? postCheckA;
  final HostCheckResult? postCheckAAAA;
  final String message;

  const ExceptionWriteOutcome({
    required this.writeSucceeded,
    required this.verifiedUnblocked,
    this.stillBlockedByImportant = false,
    this.verificationIncomplete = false,
    this.cacheFlushFailed = false,
    this.conflictDetected = false,
    this.provenanceSaveFailed = false,
    this.provenanceInterrupted = false,
    this.provenanceLegacyUnconfirmed = false,
    this.addedRule,
    this.undoToken,
    this.undoDisabledReason,
    this.postCheckResult,
    this.postCheckA,
    this.postCheckAAAA,
    required this.message,
  });
}

/// 安全的例外规则写入与撤销协调器：
/// - 通过按服务器隔离的 [ServerRuleWriteQueue] 与普通规则编辑入口共享同一写队列，避免交叉覆盖；
/// - 支持核心 `expected_revision` 条件更新，检测外部客户端并发修改冲突并重新拉取最新规则；
/// - 写后完整核验 A 与 AAAA，区分确认放行 / 仍被阻断 / 核验不完整 / 重写 / 缓存刷新部分失败；
/// - 仅在能够证明归属时执行撤销，绝不猜测删除用户规则。
class ExceptionRuleCoordinator {
  final Map<String, ExceptionUndoToken> _lastTokensByRuleKey =
      <String, ExceptionUndoToken>{};

  static String _tokenKey(String serverKey, String rule) => '$serverKey\x00$rule';

  Future<ExceptionWriteOutcome> applyExceptionAndVerify({
    required ApiClientV2 apiClient,
    required String verifyHost,
    required String exceptionRule,
    FutureOr<Object?> Function()? flushSystemDnsCache,
    Map<int, String> filterNames = const {},
    Map<int, String> whitelistNames = const {},
    String entryPoint = '误杀排错',
    ManualRuleProvenanceService? provenanceService,
  }) {
    return ServerRuleWriteQueue.run(apiClient.server, (session) async {
      final cleanRule = exceptionRule.trim();
      if (cleanRule.isEmpty) {
        return const ExceptionWriteOutcome(
          writeSucceeded: false,
          verifiedUnblocked: false,
          message: '例外规则为空',
        );
      }

      // 1) 排到本服务器写队列后再重读最新规则与版本，绝不使用排队前旧列表
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

      String? addedRule;
      ExceptionUndoToken? undoToken;
      String? undoDisabledReason;
      var provenanceSaveFailed = false;
      var provenanceInterrupted = false;
      var provenanceLegacyUnconfirmed = false;
      final prov = provenanceService ?? ManualRuleProvenanceService.instance;
      if (alreadyExists) {
        await prov.syncWithCoreRules(
          serverKey: session.serverKey,
          coreRules: existingRules,
          currentRevision: filteringData.userRulesRevision,
        );
      } else {
        final updatedRules = List<String>.from(existingRules)..add(cleanRule);
        final expectedSubmittedFp =
            ServerRuleWriteQueue.fingerprintRules(updatedRules);
        final addedIdx = existingRules.length;

        final setRes = await apiClient.setCustomRules(
          rules: updatedRules,
          expectedRevision: filteringData.userRulesRevision,
        );
        if (!setRes.successful) {
          if (setRes.statusCode == 409) {
            // 外部客户端在读写窗口间并发修改了规则：立即重读刷新并同步既有记录状态，绝不覆盖外部修改
            final refreshRes = await apiClient.getFiltering();
            if (refreshRes.successful && refreshRes.content is Filtering) {
              final f = refreshRes.content as Filtering;
              await prov.syncWithCoreRules(
                serverKey: session.serverKey,
                coreRules: f.userRules,
                currentRevision: f.userRulesRevision,
              );
            }
            return const ExceptionWriteOutcome(
              writeSucceeded: false,
              verifiedUnblocked: false,
              conflictDetected: true,
              message: '检测到其他客户端同时修改了自定义规则（版本冲突），已重新读取最新列表，请确认后重试',
            );
          }
          return const ExceptionWriteOutcome(
            writeSucceeded: false,
            verifiedUnblocked: false,
            message: '提交例外规则失败，请重试',
          );
        }

        final committedRev = setRes.userRulesRevisionHeader;
        final newEpoch = session.bumpLocalEpoch();

        // 2) 回读 /filtering/status，严格核对提交 revision、完整规则逐项一致与新增槽位，绝不回滚或覆盖其他客户端修改
        final confirmRes = await apiClient.getFiltering();
        if (!confirmRes.successful || confirmRes.content is! Filtering) {
          undoDisabledReason = '回读确认核心状态失败，无法确认撤销归属，暂不提供自动撤销；未确认写入前不记录手动来源';
        } else {
          final confirmedData = confirmRes.content as Filtering;
          final confirmedRules = List<String>.from(confirmedData.userRules);
          final readbackRev = confirmedData.userRulesRevision?.trim();
          final readbackFp =
              ServerRuleWriteQueue.fingerprintRules(confirmedRules);
          final slotMatches = addedIdx < confirmedRules.length &&
              confirmedRules[addedIdx].trim() == cleanRule;

          // 来源记录严格绑定本次提交快照：仅比较 before -> submitted 且校验 revision + 全量逐项一致。
          final provOut = await prov.applyCommitBoundDiff(
            serverKey: session.serverKey,
            rulesBeforeCommit: existingRules,
            beforeRevision: filteringData.userRulesRevision,
            rulesSubmitted: updatedRules,
            rulesReadback: confirmedRules,
            committedRevision: committedRev,
            readbackRevision: readbackRev,
            entryPoint: entryPoint,
          );
          if (provOut.interruptedByExternalUpdate) {
            provenanceInterrupted = true;
          } else if (provOut.legacyUnconfirmed) {
            provenanceLegacyUnconfirmed = true;
          } else if (provOut.storeSaveFailed) {
            provenanceSaveFailed = true;
          }

          if (committedRev == null || committedRev.isEmpty) {
            // 旧核心不返回提交 revision：保守不签发跨客户端撤销凭证，仍继续实时规则检测
            undoDisabledReason = '当前核心未返回提交版本号，无法证明跨客户端撤销归属，已禁用本次自动撤销';
          } else if (readbackRev == null || readbackRev != committedRev) {
            // 提交与回读之间已被其他操作更新：绝不回滚或覆盖其他规则，仅禁用自动撤销
            undoDisabledReason = '配置已被其他操作更新，无法确认撤销归属';
          } else if (readbackFp != expectedSubmittedFp || !slotMatches) {
            // 即使 revision 字串一致但完整列表不符合预期：同样拒绝签发撤销凭证
            undoDisabledReason = '配置已被其他操作更新，无法确认撤销归属';
          } else {
            addedRule = cleanRule;
            undoToken = ExceptionUndoToken(
              serverKey: session.serverKey,
              rule: cleanRule,
              addedIndex: addedIdx,
              confirmedRevision: committedRev,
              confirmedRulesFingerprint: readbackFp,
              confirmedLocalEpoch: newEpoch,
            );
            _lastTokensByRuleKey[_tokenKey(session.serverKey, cleanRule)] =
                undoToken;
          }
        }
      }

      String withUndoNotice(String baseMessage) {
        var msg = baseMessage;
        if (provenanceInterrupted) {
          msg = '规则操作已提交，但来源确认被其他更新打断。$msg';
        } else if (provenanceSaveFailed) {
          msg = '规则已添加，但来源记录保存失败。$msg';
        } else if (provenanceLegacyUnconfirmed) {
          msg = '旧核心未返回版本信息，来源关联降为待确认。$msg';
        }
        if (undoDisabledReason == null || undoDisabledReason.isEmpty) {
          return msg;
        }
        return '$msg（$undoDisabledReason）';
      }

      // 3) 清理核心 DNS 缓存与 Android 系统缓存（失败按部分完成实报）
      var cacheFlushFailed = false;
      final resetRes = await apiClient.resetDnsCache();
      if (!resetRes.successful) {
        cacheFlushFailed = true;
      }
      if (flushSystemDnsCache != null) {
        try {
          final sysRes = await flushSystemDnsCache();
          if (sysRes == false) {
            cacheFlushFailed = true;
          }
        } catch (_) {
          cacheFlushFailed = true;
        }
      }

      // 4) 分别检查原域名的 A 与 AAAA 记录，任何一项失败/超时/未知/不支持都如实报告核验不完整
      final isIp = InternetAddress.tryParse(verifyHost.trim()) != null;
      final checkA = await apiClient.checkHostFiltered(host: verifyHost, qtype: 'A');
      final resA = HostCheckResult.fromApiResponse(
        host: verifyHost,
        response: checkA,
        isOriginal: true,
        qtype: 'A',
        filterNames: filterNames,
        whitelistNames: whitelistNames,
      );

      HostCheckResult? resAAAA;
      if (!isIp) {
        final checkAAAA =
            await apiClient.checkHostFiltered(host: verifyHost, qtype: 'AAAA');
        resAAAA = HostCheckResult.fromApiResponse(
          host: verifyHost,
          response: checkAAAA,
          isOriginal: true,
          qtype: 'AAAA',
          filterNames: filterNames,
          whitelistNames: whitelistNames,
        );
      }

      final blockedList = <HostCheckResult>[
        if (resA.isBlocked) resA,
        if (resAAAA != null && resAAAA.isBlocked) resAAAA,
      ];
      if (blockedList.isNotEmpty) {
        final blockedTypes = blockedList.map((e) => e.qtype).join(' / ');
        final primary = blockedList.firstWhere(
          (e) => e.hasImportantBlock,
          orElse: () => blockedList.first,
        );
        final topRule = primary.rules.isNotEmpty
            ? primary.rules.first.text
            : primary.rawReason;
        if (blockedList.any((e) => e.hasImportantBlock)) {
          return ExceptionWriteOutcome(
            writeSucceeded: true,
            verifiedUnblocked: false,
            stillBlockedByImportant: true,
            cacheFlushFailed: cacheFlushFailed,
            provenanceSaveFailed: provenanceSaveFailed,
            provenanceInterrupted: provenanceInterrupted,
            provenanceLegacyUnconfirmed: provenanceLegacyUnconfirmed,
            addedRule: addedRule,
            undoToken: undoToken,
            undoDisabledReason: undoDisabledReason,
            postCheckResult: primary,
            postCheckA: resA,
            postCheckAAAA: resAAAA,
            message: withUndoNotice(
                '规则已写入，但 $blockedTypes 仍被带 \$important 优先级规则阻断（$topRule）'),
          );
        }
        return ExceptionWriteOutcome(
          writeSucceeded: true,
          verifiedUnblocked: false,
          cacheFlushFailed: cacheFlushFailed,
          provenanceSaveFailed: provenanceSaveFailed,
          provenanceInterrupted: provenanceInterrupted,
          provenanceLegacyUnconfirmed: provenanceLegacyUnconfirmed,
          addedRule: addedRule,
          undoToken: undoToken,
          undoDisabledReason: undoDisabledReason,
          postCheckResult: primary,
          postCheckA: resA,
          postCheckAAAA: resAAAA,
          message: withUndoNotice('规则已写入，但 $blockedTypes 实时检测仍被阻断：$topRule'),
        );
      }

      if (resA.status == RuleCheckStatus.rewritten ||
          resAAAA?.status == RuleCheckStatus.rewritten) {
        final rw =
            resA.status == RuleCheckStatus.rewritten ? resA : resAAAA!;
        return ExceptionWriteOutcome(
          writeSucceeded: true,
          verifiedUnblocked: false,
          verificationIncomplete: false,
          cacheFlushFailed: cacheFlushFailed,
          provenanceSaveFailed: provenanceSaveFailed,
          provenanceInterrupted: provenanceInterrupted,
          provenanceLegacyUnconfirmed: provenanceLegacyUnconfirmed,
          addedRule: addedRule,
          undoToken: undoToken,
          undoDisabledReason: undoDisabledReason,
          postCheckResult: rw,
          postCheckA: resA,
          postCheckAAAA: resAAAA,
          message: withUndoNotice(
              '规则已提交，但 ${rw.qtype} 命中重写规则处理（${rw.rawReason}），不等于正常放行'),
        );
      }

      final bothConfirmedUnblocked = resA.isUnblockedSuccess &&
          (resAAAA == null || resAAAA.isUnblockedSuccess);
      if (bothConfirmedUnblocked) {
        const caveat =
            '注意：规则检测通过不保证邮件跳转、服务器或日历应用本身一定可用；已断开的 SNI 连接需要重新触发';
        if (cacheFlushFailed) {
          return ExceptionWriteOutcome(
            writeSucceeded: true,
            verifiedUnblocked: true,
            cacheFlushFailed: true,
            provenanceSaveFailed: provenanceSaveFailed,
            provenanceInterrupted: provenanceInterrupted,
            provenanceLegacyUnconfirmed: provenanceLegacyUnconfirmed,
            addedRule: addedRule,
            undoToken: undoToken,
            undoDisabledReason: undoDisabledReason,
            postCheckResult: resA,
            postCheckA: resA,
            postCheckAAAA: resAAAA,
            message: withUndoNotice(
                '规则检测确认放行，但 DNS 缓存刷新失败（部分完成，请稍候或手动切换网络清缓存）。$caveat'),
          );
        }
        return ExceptionWriteOutcome(
          writeSucceeded: true,
          verifiedUnblocked: true,
          cacheFlushFailed: false,
          provenanceSaveFailed: provenanceSaveFailed,
          provenanceInterrupted: provenanceInterrupted,
          provenanceLegacyUnconfirmed: provenanceLegacyUnconfirmed,
          addedRule: addedRule,
          undoToken: undoToken,
          undoDisabledReason: undoDisabledReason,
          postCheckResult: resA,
          postCheckA: resA,
          postCheckAAAA: resAAAA,
          message: withUndoNotice('规则检测确认放行。$caveat'),
        );
      }

      final incompleteRes = !resA.isUnblockedSuccess ? resA : resAAAA!;
      final statusSummary = resAAAA != null
          ? 'A=${resA.statusLabel}，AAAA=${resAAAA.statusLabel}'
          : 'A=${resA.statusLabel}';
      return ExceptionWriteOutcome(
        writeSucceeded: true,
        verifiedUnblocked: false,
        verificationIncomplete: true,
        cacheFlushFailed: cacheFlushFailed,
        provenanceSaveFailed: provenanceSaveFailed,
        provenanceInterrupted: provenanceInterrupted,
        provenanceLegacyUnconfirmed: provenanceLegacyUnconfirmed,
        addedRule: addedRule,
        undoToken: undoToken,
        undoDisabledReason: undoDisabledReason,
        postCheckResult: incompleteRes,
        postCheckA: resA,
        postCheckAAAA: resAAAA,
        message: withUndoNotice('规则已提交，但核验不完整（$statusSummary），请手动确认或重试检测'),
      );
    });
  }

  /// 精准撤销本次操作可证明归属的例外规则；规则状态变化、用户删除后重加或跨服务器均拒绝猜测删除。
  Future<({bool ok, String message})> undoAddedException({
    required ApiClientV2 apiClient,
    required String addedRule,
    ExceptionUndoToken? undoToken,
    FutureOr<Object?> Function()? flushSystemDnsCache,
    ManualRuleProvenanceService? provenanceService,
  }) {
    return ServerRuleWriteQueue.run(apiClient.server, (session) async {
      final clean = addedRule.trim();
      final token = undoToken ??
          _lastTokensByRuleKey[_tokenKey(session.serverKey, clean)];
      if (token == null) {
        return (
          ok: false,
          message: '未找到本次操作的可核验归属记录（可能规则此前已存在或已被消耗），已拒绝猜测删除，请手动检查',
        );
      }
      if (token.serverKey != session.serverKey || token.rule != clean) {
        return (
          ok: false,
          message: '撤销目标与当前服务器或规则记录不匹配，已拒绝修改',
        );
      }

      final res = await apiClient.getFiltering();
      if (!res.successful || res.content is! Filtering) {
        return (ok: false, message: '读取当前自定义规则失败，未能撤销');
      }
      final filteringData = res.content as Filtering;
      final current = List<String>.from(filteringData.userRules);

      if (!current.any((r) => r.trim() == clean)) {
        _lastTokensByRuleKey.remove(_tokenKey(session.serverKey, clean));
        return (
          ok: false,
          message: '规则已不在当前列表中（可能已被手动删除），未修改任何其他规则',
        );
      }

      final currentFp = ServerRuleWriteQueue.fingerprintRules(current);
      final idxInBounds = token.addedIndex >= 0 &&
          token.addedIndex < current.length &&
          current[token.addedIndex].trim() == clean;

      final currentRev = filteringData.userRulesRevision?.trim();
      final ownershipProven = token.confirmedRevision.isNotEmpty &&
          currentRev != null &&
          currentRev == token.confirmedRevision &&
          currentFp == token.confirmedRulesFingerprint &&
          idxInBounds;

      if (!ownershipProven) {
        _lastTokensByRuleKey.remove(_tokenKey(session.serverKey, clean));
        return (
          ok: false,
          message:
              '规则状态在新增后已发生变化（可能被删除后重新添加或外部编辑），无法证明归属，已拒绝猜测删除，请手动检查自定义规则',
        );
      }

      final updated = List<String>.from(current)..removeAt(token.addedIndex);
      final saveRes = await apiClient.setCustomRules(
        rules: updated,
        expectedRevision: filteringData.userRulesRevision,
      );
      if (!saveRes.successful) {
        if (saveRes.statusCode == 409) {
          await apiClient.getFiltering();
          return (
            ok: false,
            message: '撤销时检测到外部客户端并发修改冲突，已刷新最新规则列表，请手动检查',
          );
        }
        return (ok: false, message: '撤销保存失败，请重试');
      }

      session.bumpLocalEpoch();
      _lastTokensByRuleKey.remove(_tokenKey(session.serverKey, clean));

      final prov = provenanceService ?? ManualRuleProvenanceService.instance;
      final afterUndo = await apiClient.getFiltering();
      if (afterUndo.successful && afterUndo.content is Filtering) {
        final confirmedAfter = afterUndo.content as Filtering;
        await prov.applyCommitBoundDiff(
          serverKey: session.serverKey,
          rulesBeforeCommit: current,
          beforeRevision: filteringData.userRulesRevision,
          rulesSubmitted: updated,
          rulesReadback: confirmedAfter.userRules,
          committedRevision: saveRes.userRulesRevisionHeader,
          readbackRevision: confirmedAfter.userRulesRevision,
          entryPoint: '误杀排错-撤销',
        );
      } else {
        await prov.markRuleRemovedFromCore(
          serverKey: session.serverKey,
          ruleText: clean,
          confirmedRevision: saveRes.userRulesRevisionHeader,
        );
      }

      await apiClient.resetDnsCache();
      if (flushSystemDnsCache != null) {
        try {
          await flushSystemDnsCache();
        } catch (_) {}
      }
      return (ok: true, message: '已撤销本次新增的例外规则：$clean');
    });
  }

  @visibleForTesting
  static String? safeAnchorForTest(String rule) =>
      WhitelistPlanner.extractSafeAnchorDomain(rule);
}
