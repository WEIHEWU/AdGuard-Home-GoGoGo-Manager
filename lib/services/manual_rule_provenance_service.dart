import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'package:adguard_home_manager/models/server.dart';
import 'package:adguard_home_manager/services/domain_input_parser.dart';
import 'package:adguard_home_manager/services/host_rule_diagnostics.dart';

/// 手动规则动作分类。
enum ManualRuleAction {
  allow,
  block,
  other;

  String get storageValue => name;

  static ManualRuleAction fromStorage(String? raw) {
    switch (raw) {
      case 'allow':
        return ManualRuleAction.allow;
      case 'block':
        return ManualRuleAction.block;
      default:
        return ManualRuleAction.other;
    }
  }
}

/// 手动规则记录来源。
enum ManualRuleSource {
  manual,
  claimed;

  String get storageValue => name;

  static ManualRuleSource fromStorage(String? raw) {
    return raw == 'claimed'
        ? ManualRuleSource.claimed
        : ManualRuleSource.manual;
  }
}

/// 手动规则与 Core 实时自定义规则的同步状态。
enum ManualRuleSyncStatus {
  present,
  missing,
  unconfirmed,
  duplicateAmbiguous;

  String get storageValue => name;

  static ManualRuleSyncStatus fromStorage(String? raw) {
    switch (raw) {
      case 'missing':
        return ManualRuleSyncStatus.missing;
      case 'unconfirmed':
        return ManualRuleSyncStatus.unconfirmed;
      case 'duplicateAmbiguous':
      case 'duplicate_ambiguous':
        return ManualRuleSyncStatus.duplicateAmbiguous;
      default:
        return ManualRuleSyncStatus.present;
    }
  }
}

/// 单条规则的通用分类结果（不限制固定域名，不改变规则匹配语义）。
class RuleClassification {
  final String normalizedRule;
  final ManualRuleAction action;
  final String scopeSummary;
  final String? extractableHost;
  final bool isImportant;
  final bool isComment;

  const RuleClassification({
    required this.normalizedRule,
    required this.action,
    required this.scopeSummary,
    required this.extractableHost,
    required this.isImportant,
    required this.isComment,
  });

  bool get isCheckHostTestable => extractableHost != null;

  static RuleClassification classify(String rawRule) {
    final trimmed = rawRule.trim();
    if (trimmed.isEmpty ||
        trimmed.startsWith('!') ||
        trimmed.startsWith('#')) {
      return RuleClassification(
        normalizedRule: trimmed,
        action: ManualRuleAction.other,
        scopeSummary: trimmed.isEmpty ? '空规则' : '注释或复杂规则，查看原文',
        extractableHost: null,
        isImportant: false,
        isComment: true,
      );
    }

    final lower = trimmed.toLowerCase();
    final isImportant = _hasImportantModifier(lower);

    // 仅当规则严格等价于简单 `@@||<valid_host>^` 或 `@@||<valid_host>^$important` 时，
    // 才归类为“手动放行”且视为可通过 check_host 做单域名探测。
    final allowMatch = RegExp(
      r'^@@\|\|([^\s/$^*|]+)\^(?:\$important)?$',
      caseSensitive: false,
    ).firstMatch(trimmed);
    if (allowMatch != null) {
      final candidateHost = allowMatch.group(1)!.toLowerCase();
      if (DomainInputParser.isValidHostname(candidateHost)) {
        return RuleClassification(
          normalizedRule: trimmed,
          action: ManualRuleAction.allow,
          scopeSummary: isImportant
              ? '放行 $candidateHost 及子域名（含 \$important）'
              : '放行 $candidateHost 及子域名',
          extractableHost: candidateHost,
          isImportant: isImportant,
          isComment: false,
        );
      }
    }

    // 仅当规则严格等价于简单 `||<valid_host>^` 或 `||<valid_host>^$important` 时，
    // 才归类为“手动拦截”且视为可通过 check_host 做单域名探测。
    final blockMatch = RegExp(
      r'^\|\|([^\s/$^*|]+)\^(?:\$important)?$',
      caseSensitive: false,
    ).firstMatch(trimmed);
    if (blockMatch != null) {
      final candidateHost = blockMatch.group(1)!.toLowerCase();
      if (DomainInputParser.isValidHostname(candidateHost)) {
        return RuleClassification(
          normalizedRule: trimmed,
          action: ManualRuleAction.block,
          scopeSummary: isImportant
              ? '拦截 $candidateHost 及子域名（含 \$important）'
              : '拦截 $candidateHost 及子域名',
          extractableHost: candidateHost,
          isImportant: isImportant,
          isComment: false,
        );
      }
    }

    return RuleClassification(
      normalizedRule: trimmed,
      action: ManualRuleAction.other,
      scopeSummary: '复杂规则，查看原文',
      extractableHost: null,
      isImportant: isImportant,
      isComment: false,
    );
  }

  static bool _hasImportantModifier(String lowerRule) {
    final dollarIdx = lowerRule.indexOf('\$');
    if (dollarIdx < 0) return false;
    final modifiers = lowerRule.substring(dollarIdx + 1).split(',');
    return modifiers.any((m) => m.trim() == 'important');
  }
}

/// 多重集合逐行比对结果，避免靠顺序猜测编辑配对。
class RuleListDiffResult {
  /// 新增的（ruleText -> 新增条数）
  final Map<String, int> addedCounts;

  /// 删除的（ruleText -> 删除条数）
  final Map<String, int> removedCounts;

  /// 目标列表中存在重复相同原文的规则及其出现次数
  final Map<String, int> afterDuplicates;

  const RuleListDiffResult({
    required this.addedCounts,
    required this.removedCounts,
    required this.afterDuplicates,
  });

  static RuleListDiffResult diff(List<String> before, List<String> after) {
    final beforeCounts = countExactRules(before);
    final afterCounts = countExactRules(after);

    final added = <String, int>{};
    final removed = <String, int>{};
    final duplicates = <String, int>{};

    for (final entry in afterCounts.entries) {
      if (entry.value > 1) {
        duplicates[entry.key] = entry.value;
      }
      final prev = beforeCounts[entry.key] ?? 0;
      if (entry.value > prev) {
        added[entry.key] = entry.value - prev;
      }
    }
    for (final entry in beforeCounts.entries) {
      final next = afterCounts[entry.key] ?? 0;
      if (entry.value > next) {
        removed[entry.key] = entry.value - next;
      }
    }

    return RuleListDiffResult(
      addedCounts: added,
      removedCounts: removed,
      afterDuplicates: duplicates,
    );
  }

  static Map<String, int> countExactRules(List<String> rules) {
    final counts = <String, int>{};
    for (final raw in rules) {
      final clean = raw.trim();
      if (clean.isEmpty) continue;
      counts[clean] = (counts[clean] ?? 0) + 1;
    }
    return counts;
  }
}

/// 持久化手动规则记录。
class ManualRuleRecord {
  final String recordId;
  final String serverKey;
  final String ruleText;
  final ManualRuleAction action;
  final ManualRuleSource source;
  final String entryPoint;
  final DateTime? createdAt;
  final DateTime? claimedAt;
  final DateTime updatedAt;
  final String? note;
  final String? confirmedRevision;
  final ManualRuleSyncStatus syncStatus;

  const ManualRuleRecord({
    required this.recordId,
    required this.serverKey,
    required this.ruleText,
    required this.action,
    required this.source,
    required this.entryPoint,
    required this.createdAt,
    required this.claimedAt,
    required this.updatedAt,
    required this.note,
    required this.confirmedRevision,
    required this.syncStatus,
  });

  RuleClassification get classification =>
      RuleClassification.classify(ruleText);

  String get primaryLabel {
    if (syncStatus == ManualRuleSyncStatus.duplicateAmbiguous) {
      return '归属未确认';
    }
    if (syncStatus == ManualRuleSyncStatus.unconfirmed) {
      return '来源未确认';
    }
    if (source == ManualRuleSource.claimed) {
      return '用户认领';
    }
    switch (action) {
      case ManualRuleAction.allow:
        return '手动放行';
      case ManualRuleAction.block:
        return '手动拦截';
      case ManualRuleAction.other:
        return '手动规则';
    }
  }

  DateTime get sortTimestamp => createdAt ?? claimedAt ?? updatedAt;

  ManualRuleRecord copyWith({
    String? recordId,
    String? serverKey,
    String? ruleText,
    ManualRuleAction? action,
    ManualRuleSource? source,
    String? entryPoint,
    DateTime? createdAt,
    bool clearCreatedAt = false,
    DateTime? claimedAt,
    bool clearClaimedAt = false,
    DateTime? updatedAt,
    String? note,
    bool clearNote = false,
    String? confirmedRevision,
    bool clearConfirmedRevision = false,
    ManualRuleSyncStatus? syncStatus,
  }) {
    return ManualRuleRecord(
      recordId: recordId ?? this.recordId,
      serverKey: serverKey ?? this.serverKey,
      ruleText: ruleText ?? this.ruleText,
      action: action ?? this.action,
      source: source ?? this.source,
      entryPoint: entryPoint ?? this.entryPoint,
      createdAt: clearCreatedAt ? null : (createdAt ?? this.createdAt),
      claimedAt: clearClaimedAt ? null : (claimedAt ?? this.claimedAt),
      updatedAt: updatedAt ?? this.updatedAt,
      note: clearNote ? null : (note ?? this.note),
      confirmedRevision: clearConfirmedRevision
          ? null
          : (confirmedRevision ?? this.confirmedRevision),
      syncStatus: syncStatus ?? this.syncStatus,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'record_id': recordId,
      'server_key': serverKey,
      'rule_text': ruleText,
      'action': action.storageValue,
      'source': source.storageValue,
      'entry_point': entryPoint,
      'created_at': createdAt?.toUtc().toIso8601String(),
      'claimed_at': claimedAt?.toUtc().toIso8601String(),
      'updated_at': updatedAt.toUtc().toIso8601String(),
      'note': note,
      'confirmed_revision': confirmedRevision,
      'sync_status': syncStatus.storageValue,
    };
  }

  static ManualRuleRecord fromJson(Map<String, dynamic> json) {
    final recordId = (json['record_id'] ?? '').toString().trim();
    final serverKey = (json['server_key'] ?? '').toString().trim();
    final ruleText = (json['rule_text'] ?? '').toString().trim();
    if (recordId.isEmpty || serverKey.isEmpty || ruleText.isEmpty) {
      throw const FormatException('记录缺少必要标识或规则原文');
    }

    final actionRaw = json['action']?.toString();
    final classification = RuleClassification.classify(ruleText);
    final action = actionRaw != null
        ? ManualRuleAction.fromStorage(actionRaw)
        : classification.action;

    final source = ManualRuleSource.fromStorage(json['source']?.toString());
    final entryPoint = (json['entry_point'] ?? '未知入口').toString().trim();

    DateTime? parseOptDate(dynamic raw) {
      if (raw == null) return null;
      final str = raw.toString().trim();
      if (str.isEmpty) return null;
      return DateTime.parse(str);
    }

    final createdAt = source == ManualRuleSource.claimed
        ? null
        : parseOptDate(json['created_at']);
    final claimedAt = source == ManualRuleSource.claimed
        ? (parseOptDate(json['claimed_at']) ?? DateTime.now().toUtc())
        : null;
    final updatedAt = parseOptDate(json['updated_at']) ??
        createdAt ??
        claimedAt ??
        DateTime.now().toUtc();

    final noteRaw = json['note']?.toString();
    final revRaw = json['confirmed_revision']?.toString();

    return ManualRuleRecord(
      recordId: recordId,
      serverKey: serverKey,
      ruleText: ruleText,
      action: action,
      source: source,
      entryPoint: entryPoint.isEmpty ? '未知入口' : entryPoint,
      createdAt: createdAt,
      claimedAt: claimedAt,
      updatedAt: updatedAt,
      note: (noteRaw == null || noteRaw.isEmpty) ? null : noteRaw,
      confirmedRevision:
          (revRaw == null || revRaw.trim().isEmpty) ? null : revRaw.trim(),
      syncStatus:
          ManualRuleSyncStatus.fromStorage(json['sync_status']?.toString()),
    );
  }
}

/// UI 统一来源徽章展示模型。
class RuleSourceDisplay {
  final String label;
  final String? secondaryHint;
  final ManualRuleRecord? record;
  final bool isManualOrigin;
  final bool isClaimedOrigin;
  final bool isSubscriptionOrigin;
  final bool isUnrecordedCustom;
  final bool isUnconfirmedOrAmbiguous;
  final bool isDuplicateAmbiguous;

  const RuleSourceDisplay({
    required this.label,
    this.secondaryHint,
    this.record,
    this.isManualOrigin = false,
    this.isClaimedOrigin = false,
    this.isSubscriptionOrigin = false,
    this.isUnrecordedCustom = false,
    this.isUnconfirmedOrAmbiguous = false,
    this.isDuplicateAmbiguous = false,
  });
}

/// 导入备份统计结果。
class ProvenanceImportResult {
  final int importedCount;
  final int updatedCount;
  final int skippedCount;

  const ProvenanceImportResult({
    required this.importedCount,
    required this.updatedCount,
    required this.skippedCount,
  });
}

/// 本地读取/写入存储接口，便于单元测试与 Android 应用私有目录切换。
abstract class ManualRuleProvenanceStoreBackend {
  Future<String?> readRaw();
  Future<void> writeRawAtomic(String content);
  Future<String> get storageDescription;
}

/// Android / 本地文件系统原子持久化后端（filesDir，临时文件写入 + flush + rename）。
class FileManualRuleProvenanceStoreBackend
    implements ManualRuleProvenanceStoreBackend {
  static const MethodChannel _diagChannel =
      MethodChannel('com.wu.adgogogo/diagnostics');
  static const String defaultFileName = 'manual_rule_provenance_v1.json';

  final Future<Directory> Function()? _directoryResolver;
  Directory? _cachedDir;
  int _tmpSeq = 0;

  FileManualRuleProvenanceStoreBackend({
    Future<Directory> Function()? directoryResolver,
  }) : _directoryResolver = directoryResolver;

  Future<Directory> _resolveDir() async {
    if (_cachedDir != null) return _cachedDir!;
    if (_directoryResolver != null) {
      _cachedDir = await _directoryResolver();
      return _cachedDir!;
    }
    if (Platform.isAndroid) {
      final path = await _diagChannel.invokeMethod<String>('getAppFilesDir');
      if (path != null && path.trim().isNotEmpty) {
        final dir = Directory(path.trim());
        if (!await dir.exists()) {
          await dir.create(recursive: true);
        }
        _cachedDir = dir;
        return dir;
      }
      throw const FileSystemException('无法解析 Android filesDir，拒绝回退到临时缓存目录');
    }
    final fallbackDir = Directory(
      '${Directory.systemTemp.path}/agh_manager_provenance',
    );
    if (!await fallbackDir.exists()) {
      await fallbackDir.create(recursive: true);
    }
    _cachedDir = fallbackDir;
    return fallbackDir;
  }

  Future<File> _targetFile() async {
    final dir = await _resolveDir();
    return File('${dir.path}/$defaultFileName');
  }

  @override
  Future<String> get storageDescription async {
    final f = await _targetFile();
    return f.path;
  }

  @override
  Future<String?> readRaw() async {
    final file = await _targetFile();
    if (!await file.exists()) {
      return null;
    }
    return file.readAsString(encoding: utf8);
  }

  @override
  Future<void> writeRawAtomic(String content) async {
    final dir = await _resolveDir();
    if (!await dir.exists()) {
      await dir.create(recursive: true);
    }
    final target = File('${dir.path}/$defaultFileName');
    _tmpSeq += 1;
    final tmpFile = File(
      '${dir.path}/.$defaultFileName.$pid.$_tmpSeq.tmp',
    );
    final raf = await tmpFile.open(mode: FileMode.writeOnly);
    try {
      await raf.writeString(content, encoding: utf8);
      await raf.flush();
    } finally {
      await raf.close();
    }
    await tmpFile.rename(target.path);
  }
}

/// 内存持久化后端，供单元测试及不依赖平台通道的场景使用。
class InMemoryManualRuleProvenanceStoreBackend
    implements ManualRuleProvenanceStoreBackend {
  String? rawContent;
  bool failNextRead;
  bool failNextWrite;

  InMemoryManualRuleProvenanceStoreBackend({
    this.rawContent,
    this.failNextRead = false,
    this.failNextWrite = false,
  });

  @override
  Future<String> get storageDescription async => 'memory://manual_rule_provenance_v1';

  @override
  Future<String?> readRaw() async {
    if (failNextRead) {
      failNextRead = false;
      throw const FileSystemException('模拟存储读取失败');
    }
    return rawContent;
  }

  @override
  Future<void> writeRawAtomic(String content) async {
    if (failNextWrite) {
      failNextWrite = false;
      throw const FileSystemException('模拟存储写入失败');
    }
    rawContent = content;
  }
}

/// 通用手动规则来源记录与“我的手动规则”管理服务（单一全局实例，支持测试注入）。
class ManualRuleProvenanceService extends ChangeNotifier {
  static const int currentSchemaVersion = 1;
  static const MethodChannel _diagChannel =
      MethodChannel('com.wu.adgogogo/diagnostics');

  static ManualRuleProvenanceService _instance = ManualRuleProvenanceService();

  static ManualRuleProvenanceService get instance => _instance;

  /// 测试期替换为独立服务实例（不影响正式包单例）。
  @visibleForTesting
  static void setInstanceForTest(ManualRuleProvenanceService testInstance) {
    _instance = testInstance;
  }

  @visibleForTesting
  static void resetInstanceForTest() {
    _instance = ManualRuleProvenanceService();
  }

  final ManualRuleProvenanceStoreBackend _backend;
  final DateTime Function() _nowProvider;

  bool _loaded = false;
  bool _corruptedOrReadError = false;
  String? _storageErrorDetail;
  final Map<String, List<ManualRuleRecord>> _recordsByServer = {};
  Future<void> _serialQueue = Future.value();
  Future<void>? _loadFuture;
  int _idCounter = 0;

  ManualRuleProvenanceService({
    ManualRuleProvenanceStoreBackend? backend,
    DateTime Function()? nowProvider,
  })  : _backend = backend ?? FileManualRuleProvenanceStoreBackend(),
        _nowProvider = nowProvider ?? (() => DateTime.now().toUtc());

  bool get isLoaded => _loaded;
  bool get hasStorageError => _corruptedOrReadError;
  String? get storageErrorDetail => _storageErrorDetail;
  ManualRuleProvenanceStoreBackend get backend => _backend;

  static String? serverKeyForNullable(Server? server) {
    if (server == null) return null;
    return ServerRuleWriteQueue.serverKeyFor(server);
  }

  /// 确保已从本地存储加载；若损坏或读取失败，仅标记 `hasStorageError`，绝不丢弃或篡改 Core 规则。
  Future<void> ensureLoaded() async {
    if (_loaded) return;
    _loadFuture ??= _runSerialized(_loadUnlocked);
    try {
      await _loadFuture;
    } finally {
      _loadFuture = null;
    }
  }

  /// 强制重新从存储介质加载（可用于恢复验证）。
  Future<void> reloadFromDisk() {
    _loaded = false;
    return ensureLoaded();
  }

  Future<T> _runSerialized<T>(Future<T> Function() action) {
    final completer = Completer<T>();
    _serialQueue = _serialQueue.then((_) async {
      try {
        final result = await action();
        if (!completer.isCompleted) {
          completer.complete(result);
        }
      } catch (e, st) {
        if (!completer.isCompleted) {
          completer.completeError(e, st);
        }
      }
    });
    return completer.future;
  }

  Future<void> _loadUnlocked() async {
    try {
      final raw = await _backend.readRaw();
      _recordsByServer.clear();
      _corruptedOrReadError = false;
      _storageErrorDetail = null;

      if (raw == null || raw.trim().isEmpty) {
        _loaded = true;
        return;
      }

      final decoded = jsonDecode(raw);
      if (decoded is! Map<String, dynamic>) {
        throw const FormatException('根节点必须是 JSON 对象');
      }
      final schema = decoded['schema_version'];
      if (schema != currentSchemaVersion) {
        throw FormatException('不支持的 provenance schema_version: $schema');
      }
      final byServer = decoded['records_by_server'];
      if (byServer is! Map) {
        throw const FormatException('records_by_server 必须是对象');
      }

      for (final entry in byServer.entries) {
        final srvKey = entry.key.toString();
        final listRaw = entry.value;
        if (listRaw is! List) {
          throw FormatException('服务器 $srvKey 下的记录列表格式错误');
        }
        final list = <ManualRuleRecord>[];
        for (final item in listRaw) {
          if (item is! Map) {
            throw const FormatException('规则记录必须是 JSON 对象');
          }
          list.add(
            ManualRuleRecord.fromJson(Map<String, dynamic>.from(item)),
          );
        }
        if (list.isNotEmpty) {
          _recordsByServer[srvKey] = list;
        }
      }
      _loaded = true;
    } catch (e) {
      _recordsByServer.clear();
      _corruptedOrReadError = true;
      _storageErrorDetail = e.toString();
      _loaded = true;
    }
    notifyListeners();
  }

  Future<bool> _persistUnlocked() async {
    // 若磁盘文件已损坏且用户尚未清除或备份恢复，禁止用空内存覆盖原损坏文件以免丢失恢复机会。
    if (_corruptedOrReadError) {
      return false;
    }
    try {
      final payload = _serializeStorePayload(_recordsByServer);
      await _backend.writeRawAtomic(jsonEncode(payload));
      return true;
    } catch (e) {
      _storageErrorDetail = e.toString();
      return false;
    }
  }

  Map<String, dynamic> _serializeStorePayload(
    Map<String, List<ManualRuleRecord>> source,
  ) {
    final encodedServers = <String, dynamic>{};
    for (final entry in source.entries) {
      if (entry.value.isEmpty) continue;
      encodedServers[entry.key] = entry.value.map((r) => r.toJson()).toList();
    }
    return {
      'schema_version': currentSchemaVersion,
      'updated_at': _nowProvider().toUtc().toIso8601String(),
      'records_by_server': encodedServers,
    };
  }

  String _nextRecordId() {
    _idCounter += 1;
    final micros = _nowProvider().toUtc().microsecondsSinceEpoch;
    return 'mr_${micros}_$_idCounter';
  }

  List<ManualRuleRecord> recordsForServer(String serverKey) {
    final list = _recordsByServer[serverKey];
    if (list == null) return const [];
    return List<ManualRuleRecord>.unmodifiable(list);
  }

  /// 查找指定服务器和精确规则文本的最新记录；如果存在多条冲突记录，返回 null 以便展示未确认状态。
  List<ManualRuleRecord> findRecordsForRule(String serverKey, String rawRule) {
    final clean = rawRule.trim();
    if (clean.isEmpty) return const [];
    final list = _recordsByServer[serverKey];
    if (list == null) return const [];
    return list.where((r) => r.ruleText == clean).toList(growable: false);
  }

  bool hasActiveManualRecord(String serverKey, String rawRule) {
    final matches = findRecordsForRule(serverKey, rawRule);
    return matches.any((r) => r.syncStatus != ManualRuleSyncStatus.missing);
  }

  /// 按规则显示要求解析单个“自定义规则列表行”的来源标签（filter_list_id == 0）。
  RuleSourceDisplay resolveCustomListRowDisplay({
    required String? serverKey,
    required String rawRule,
    int duplicateCountInCore = 1,
  }) {
    if (_corruptedOrReadError) {
      return const RuleSourceDisplay(
        label: '来源未确认',
        secondaryHint: '本地来源记录文件读取异常',
        isUnconfirmedOrAmbiguous: true,
      );
    }
    if (serverKey == null || serverKey.isEmpty) {
      return const RuleSourceDisplay(
        label: '来源未记录',
        isUnrecordedCustom: true,
      );
    }
    final clean = rawRule.trim();
    final matches = findRecordsForRule(serverKey, clean);
    final active = matches
        .where((r) => r.syncStatus != ManualRuleSyncStatus.missing)
        .toList();

    if (duplicateCountInCore > 1) {
      return RuleSourceDisplay(
        label: '归属未确认',
        secondaryHint: 'Core 中存在 $duplicateCountInCore 条相同规则，无法安全区分单条归属',
        record: active.length == 1 ? active.first : null,
        isUnconfirmedOrAmbiguous: true,
        isDuplicateAmbiguous: true,
      );
    }

    if (active.isEmpty) {
      // 如果存在被标记 missing 的旧记录且规则如今又在 Core 中出现（例如外部删后重建）
      if (matches.any((r) => r.syncStatus == ManualRuleSyncStatus.missing)) {
        return RuleSourceDisplay(
          label: '来源未确认',
          secondaryHint: '历史记录曾显示该规则消失，后又在 Core 中重新出现',
          record: matches.last,
          isUnconfirmedOrAmbiguous: true,
        );
      }
      return const RuleSourceDisplay(
        label: '来源未记录',
        isUnrecordedCustom: true,
      );
    }

    if (active.length > 1) {
      return const RuleSourceDisplay(
        label: '归属未确认',
        secondaryHint: '存在多条冲突的本地来源记录',
        isUnconfirmedOrAmbiguous: true,
        isDuplicateAmbiguous: true,
      );
    }

    final rec = active.first;
    if (rec.syncStatus == ManualRuleSyncStatus.duplicateAmbiguous) {
      return RuleSourceDisplay(
        label: '归属未确认',
        secondaryHint: '存在重复规则文本，无法安全认定归属',
        record: rec,
        isUnconfirmedOrAmbiguous: true,
        isDuplicateAmbiguous: true,
      );
    }
    if (rec.syncStatus == ManualRuleSyncStatus.unconfirmed) {
      return RuleSourceDisplay(
        label: '来源未确认',
        secondaryHint: '外部变更后重新出现或未完成确认',
        record: rec,
        isUnconfirmedOrAmbiguous: true,
      );
    }
    return RuleSourceDisplay(
      label: rec.primaryLabel,
      record: rec,
      isManualOrigin: rec.source == ManualRuleSource.manual,
      isClaimedOrigin: rec.source == ManualRuleSource.claimed,
    );
  }

  /// 按规则显示要求解析“check_host / 日志命中规则”的来源标签。
  /// 规则：
  /// 1. 当 `filterListId != 0` 时，始终主展示订阅名称，绝不把订阅或模块预设标为手动规则；
  ///    若本地还存在完全相同的有效手动规则，附加次要提示 `同时存在相同手动规则`。
  /// 2. 当 `filterListId == 0` 时，严格查来源库，绝不凭 `@@` 前缀猜“手动”。
  RuleSourceDisplay resolveMatchedRuleDisplay({
    required String? serverKey,
    required String ruleText,
    required int filterListId,
    required String subscriptionDisplayName,
    int duplicateCountInCore = 1,
  }) {
    if (filterListId != 0) {
      final hasCoexistingManual = serverKey != null &&
          serverKey.isNotEmpty &&
          !_corruptedOrReadError &&
          hasActiveManualRecord(serverKey, ruleText);
      return RuleSourceDisplay(
        label: subscriptionDisplayName.trim().isNotEmpty
            ? subscriptionDisplayName.trim()
            : '订阅 #$filterListId',
        secondaryHint: hasCoexistingManual ? '同时存在相同手动规则' : null,
        isSubscriptionOrigin: true,
      );
    }
    return resolveCustomListRowDisplay(
      serverKey: serverKey,
      rawRule: ruleText,
      duplicateCountInCore: duplicateCountInCore,
    );
  }

  /// 记录由用户在 Manager 中明确新增的规则。
  /// 若规则写入前已在 Core 中存在，调用方不应传入该方法；若遇到重复规则文本，自动标为 duplicateAmbiguous。
  Future<bool> recordManualAdditions({
    required String serverKey,
    required List<String> addedRules,
    required String entryPoint,
    String? confirmedRevision,
    String? note,
    Map<String, int>? coreCountsAfterWrite,
  }) async {
    await ensureLoaded();
    return _runSerialized(() async {
      if (_corruptedOrReadError) return false;
      final cleanList = addedRules
          .map((r) => r.trim())
          .where((r) => r.isNotEmpty)
          .toList();
      if (cleanList.isEmpty) return true;

      final now = _nowProvider().toUtc();
      final bucket = _recordsByServer.putIfAbsent(serverKey, () => []);

      for (final rule in cleanList) {
        final cls = RuleClassification.classify(rule);
        final coreDup = (coreCountsAfterWrite?[rule] ?? 1) > 1;
        final syncStatus = coreDup
            ? ManualRuleSyncStatus.duplicateAmbiguous
            : ManualRuleSyncStatus.present;

        // 清理已消失/同文历史单条记录后写入新手动记录（若此前就是当前规则且未缺失，不应重复追加冲突记录）
        final existingIdx = bucket.indexWhere((r) => r.ruleText == rule);
        final nextRec = ManualRuleRecord(
          recordId: existingIdx >= 0 ? bucket[existingIdx].recordId : _nextRecordId(),
          serverKey: serverKey,
          ruleText: rule,
          action: cls.action,
          source: ManualRuleSource.manual,
          entryPoint: entryPoint,
          createdAt: now,
          claimedAt: null,
          updatedAt: now,
          note: (note != null && note.trim().isNotEmpty)
              ? note.trim()
              : (existingIdx >= 0 ? bucket[existingIdx].note : null),
          confirmedRevision: confirmedRevision ??
              (existingIdx >= 0 ? bucket[existingIdx].confirmedRevision : null),
          syncStatus: syncStatus,
        );
        if (existingIdx >= 0) {
          bucket[existingIdx] = nextRec;
        } else {
          bucket.add(nextRec);
        }
      }

      final saved = await _persistUnlocked();
      notifyListeners();
      return saved;
    });
  }

  /// 应用“批量编辑 / 日志改写 / 自定义列表变更”的多重集合差异：
  /// - 仅对 genuinely 新增（净增加）的规则新建手动记录；
  /// - 仅对被移除（不再存在于 Core）的已管理记录标为 `missing`；
  /// - 保持未改动规则原有来源不变（从未记录的仍然来源未记录）。
  Future<bool> applyRuleListMutationDiff({
    required String serverKey,
    required List<String> rulesBefore,
    required List<String> rulesAfter,
    required String entryPoint,
    String? confirmedRevision,
  }) async {
    await ensureLoaded();
    return _runSerialized(() async {
      if (_corruptedOrReadError) return false;
      final diff = RuleListDiffResult.diff(rulesBefore, rulesAfter);
      final afterCounts = RuleListDiffResult.countExactRules(rulesAfter);
      final now = _nowProvider().toUtc();
      final bucket = _recordsByServer.putIfAbsent(serverKey, () => []);
      var changed = false;

      // 1) 已被本次操作彻底从 Core 列表移除的原记录标为 missing
      for (var i = 0; i < bucket.length; i++) {
        final rec = bucket[i];
        final remaining = afterCounts[rec.ruleText] ?? 0;
        if (remaining == 0 && rec.syncStatus != ManualRuleSyncStatus.missing) {
          bucket[i] = rec.copyWith(
            syncStatus: ManualRuleSyncStatus.missing,
            updatedAt: now,
          );
          changed = true;
        } else if (remaining > 1 &&
            rec.syncStatus != ManualRuleSyncStatus.duplicateAmbiguous) {
          bucket[i] = rec.copyWith(
            syncStatus: ManualRuleSyncStatus.duplicateAmbiguous,
            updatedAt: now,
          );
          changed = true;
        }
      }

      // 2) 为净新增规则创建记录（如果 Core 中已经出现重复相同行，标为 duplicateAmbiguous）
      for (final entry in diff.addedCounts.entries) {
        final rule = entry.key;
        final totalNow = afterCounts[rule] ?? entry.value;
        final beforeCount =
            RuleListDiffResult.countExactRules(rulesBefore)[rule] ?? 0;
        if (beforeCount > 0 && totalNow > 1) {
          // 在已有相同行基础上又加了一行，形成重复规则歧义
          final idx = bucket.indexWhere((r) => r.ruleText == rule);
          if (idx >= 0) {
            bucket[idx] = bucket[idx].copyWith(
              syncStatus: ManualRuleSyncStatus.duplicateAmbiguous,
              updatedAt: now,
              confirmedRevision: confirmedRevision ?? bucket[idx].confirmedRevision,
            );
          } else {
            final cls = RuleClassification.classify(rule);
            bucket.add(ManualRuleRecord(
              recordId: _nextRecordId(),
              serverKey: serverKey,
              ruleText: rule,
              action: cls.action,
              source: ManualRuleSource.manual,
              entryPoint: entryPoint,
              createdAt: now,
              claimedAt: null,
              updatedAt: now,
              note: null,
              confirmedRevision: confirmedRevision,
              syncStatus: ManualRuleSyncStatus.duplicateAmbiguous,
            ));
          }
          changed = true;
          continue;
        }

        final cls = RuleClassification.classify(rule);
        final status = totalNow > 1
            ? ManualRuleSyncStatus.duplicateAmbiguous
            : ManualRuleSyncStatus.present;
        final idx = bucket.indexWhere((r) => r.ruleText == rule);
        final rec = ManualRuleRecord(
          recordId: idx >= 0 ? bucket[idx].recordId : _nextRecordId(),
          serverKey: serverKey,
          ruleText: rule,
          action: cls.action,
          source: ManualRuleSource.manual,
          entryPoint: entryPoint,
          createdAt: now,
          claimedAt: null,
          updatedAt: now,
          note: idx >= 0 ? bucket[idx].note : null,
          confirmedRevision: confirmedRevision ??
              (idx >= 0 ? bucket[idx].confirmedRevision : null),
          syncStatus: status,
        );
        if (idx >= 0) {
          bucket[idx] = rec;
        } else {
          bucket.add(rec);
        }
        changed = true;
      }

      if (!changed) return true;
      final saved = await _persistUnlocked();
      notifyListeners();
      return saved;
    });
  }

  /// 由 Manager 成功移除某条规则（单条删除 / 撤销）后更新状态，不删历史管理记录除非用户选仅移除记录。
  Future<bool> markRuleRemovedFromCore({
    required String serverKey,
    required String ruleText,
    String? confirmedRevision,
  }) async {
    await ensureLoaded();
    return _runSerialized(() async {
      if (_corruptedOrReadError) return false;
      final clean = ruleText.trim();
      final bucket = _recordsByServer[serverKey];
      if (bucket == null || clean.isEmpty) return true;

      final now = _nowProvider().toUtc();
      var changed = false;
      for (var i = 0; i < bucket.length; i++) {
        if (bucket[i].ruleText == clean &&
            bucket[i].syncStatus != ManualRuleSyncStatus.missing) {
          bucket[i] = bucket[i].copyWith(
            syncStatus: ManualRuleSyncStatus.missing,
            updatedAt: now,
            confirmedRevision: confirmedRevision ?? bucket[i].confirmedRevision,
          );
          changed = true;
        }
      }
      if (!changed) return true;
      final saved = await _persistUnlocked();
      notifyListeners();
      return saved;
    });
  }

  /// 使用从 Core `/filtering/status` 读取到的最新规则快照同步当前服务器的管理状态。
  /// 严禁把外部或已有未管理规则自动改成手动来源；仅同步既有记录的在位/缺失/重复/外部重建未确认状态。
  Future<void> syncWithCoreRules({
    required String serverKey,
    required List<String> coreRules,
  }) async {
    await ensureLoaded();
    await _runSerialized(() async {
      if (_corruptedOrReadError) return;
      final bucket = _recordsByServer[serverKey];
      if (bucket == null || bucket.isEmpty) return;

      final counts = RuleListDiffResult.countExactRules(coreRules);
      final now = _nowProvider().toUtc();
      var changed = false;

      for (var i = 0; i < bucket.length; i++) {
        final rec = bucket[i];
        final c = counts[rec.ruleText] ?? 0;
        ManualRuleSyncStatus nextStatus = rec.syncStatus;

        if (c == 0) {
          if (rec.syncStatus != ManualRuleSyncStatus.missing) {
            nextStatus = ManualRuleSyncStatus.missing;
          }
        } else if (c > 1) {
          if (rec.syncStatus != ManualRuleSyncStatus.duplicateAmbiguous) {
            nextStatus = ManualRuleSyncStatus.duplicateAmbiguous;
          }
        } else {
          // c == 1
          if (rec.syncStatus == ManualRuleSyncStatus.missing ||
              rec.syncStatus == ManualRuleSyncStatus.duplicateAmbiguous) {
            // 规则此前已缺失或处于重复歧义，之后在 Core 中以单条形态重新出现：无法确认外部变更后归属，标为未确认。
            nextStatus = ManualRuleSyncStatus.unconfirmed;
          }
        }

        if (nextStatus != rec.syncStatus) {
          bucket[i] = rec.copyWith(
            syncStatus: nextStatus,
            updatedAt: now,
          );
          changed = true;
        }
      }

      if (changed) {
        await _persistUnlocked();
        notifyListeners();
      }
    });
  }

  /// 用户主动将已有规则（例如升级前手动添加或外部添加规则）纳入“用户认领”管理：
  /// 严格置 `source = claimed`、`createdAt = null`、`claimedAt = now`，不伪造原始添加时间。
  Future<bool> claimExistingRule({
    required String serverKey,
    required String ruleText,
    required List<String> latestCoreRules,
    String entryPoint = '自定义规则-主动认领',
    String? confirmedRevision,
    String? note,
  }) async {
    await ensureLoaded();
    return _runSerialized(() async {
      if (_corruptedOrReadError) return false;
      final clean = ruleText.trim();
      if (clean.isEmpty) return false;

      final counts = RuleListDiffResult.countExactRules(latestCoreRules);
      final occurrences = counts[clean] ?? 0;
      if (occurrences == 0) return false;

      final now = _nowProvider().toUtc();
      final bucket = _recordsByServer.putIfAbsent(serverKey, () => []);
      final cls = RuleClassification.classify(clean);
      final status = occurrences > 1
          ? ManualRuleSyncStatus.duplicateAmbiguous
          : ManualRuleSyncStatus.present;

      final idx = bucket.indexWhere((r) => r.ruleText == clean);
      final next = ManualRuleRecord(
        recordId: idx >= 0 ? bucket[idx].recordId : _nextRecordId(),
        serverKey: serverKey,
        ruleText: clean,
        action: cls.action,
        source: ManualRuleSource.claimed,
        entryPoint: entryPoint,
        createdAt: null,
        claimedAt: now,
        updatedAt: now,
        note: (note != null && note.trim().isNotEmpty)
            ? note.trim()
            : (idx >= 0 ? bucket[idx].note : null),
        confirmedRevision: confirmedRevision ??
            (idx >= 0 ? bucket[idx].confirmedRevision : null),
        syncStatus: status,
      );
      if (idx >= 0) {
        bucket[idx] = next;
      } else {
        bucket.add(next);
      }

      final saved = await _persistUnlocked();
      notifyListeners();
      return saved;
    });
  }

  /// 仅更新某条记录的备注（绝不触发对 Core 规则的任何网络请求）。
  Future<bool> updateNote({
    required String serverKey,
    required String recordId,
    required String? note,
  }) async {
    await ensureLoaded();
    return _runSerialized(() async {
      if (_corruptedOrReadError) return false;
      final bucket = _recordsByServer[serverKey];
      if (bucket == null) return false;
      final idx = bucket.indexWhere((r) => r.recordId == recordId);
      if (idx < 0) return false;

      final trimmedNote = note?.trim();
      bucket[idx] = bucket[idx].copyWith(
        note: (trimmedNote == null || trimmedNote.isEmpty) ? null : trimmedNote,
        clearNote: trimmedNote == null || trimmedNote.isEmpty,
        updatedAt: _nowProvider().toUtc(),
      );
      final saved = await _persistUnlocked();
      notifyListeners();
      return saved;
    });
  }

  /// 仅移除管理记录（保留 Core 里的实际规则不受影响）。
  Future<bool> removeProvenanceRecordOnly({
    required String serverKey,
    required String recordId,
  }) async {
    await ensureLoaded();
    return _runSerialized(() async {
      if (_corruptedOrReadError) return false;
      final bucket = _recordsByServer[serverKey];
      if (bucket == null) return false;
      final beforeLen = bucket.length;
      bucket.removeWhere((r) => r.recordId == recordId);
      if (bucket.length == beforeLen) return false;
      if (bucket.isEmpty) {
        _recordsByServer.remove(serverKey);
      }
      final saved = await _persistUnlocked();
      notifyListeners();
      return saved;
    });
  }

  /// 导出备份 JSON（仅来源记录与备注，不含服务器密码、Token 等敏感凭据）。
  Future<String> exportBackupJson({String? onlyServerKey}) async {
    await ensureLoaded();
    final map = <String, List<ManualRuleRecord>>{};
    if (onlyServerKey != null) {
      final list = _recordsByServer[onlyServerKey];
      if (list != null && list.isNotEmpty) {
        map[onlyServerKey] = List<ManualRuleRecord>.from(list);
      }
    } else {
      for (final entry in _recordsByServer.entries) {
        if (entry.value.isNotEmpty) {
          map[entry.key] = List<ManualRuleRecord>.from(entry.value);
        }
      }
    }
    const encoder = JsonEncoder.withIndent('  ');
    return encoder.convert(_serializeStorePayload(map));
  }

  /// 通过 Android 系统分享面板分享纯来源记录备份文件（写入 cache backup dir 并调用 FileProvider 分享）。
  Future<File?> prepareAndShareBackupJson({String? onlyServerKey}) async {
    final jsonText = await exportBackupJson(onlyServerKey: onlyServerKey);
    Directory backupDir;
    if (Platform.isAndroid) {
      final dirPath =
          await _diagChannel.invokeMethod<String>('getCacheBackupDir');
      if (dirPath == null || dirPath.trim().isEmpty) {
        throw const FileSystemException('无法获取共享备份缓存目录');
      }
      backupDir = Directory(dirPath.trim());
    } else {
      backupDir = Directory('${Directory.systemTemp.path}/manual_backups');
    }
    if (!await backupDir.exists()) {
      await backupDir.create(recursive: true);
    }
    final ts = _nowProvider()
        .toUtc()
        .toIso8601String()
        .replaceAll(':', '')
        .replaceAll('-', '')
        .split('.')
        .first;
    final outFile = File(
      '${backupDir.path}/adguard_manual_rules_backup_$ts.json',
    );
    await outFile.writeAsString(jsonText, encoding: utf8, flush: true);

    if (Platform.isAndroid) {
      await _diagChannel.invokeMethod<void>('shareBackupFile', {
        'filePath': outFile.path,
        'title': '分享手动规则来源备份（不含密码或凭据）',
      });
    }
    return outFile;
  }

  /// 导入并严格校验 schema v1 备份 JSON（仅更新本地管理记录，绝不自动向 Core 提交或改写任何过滤规则）。
  Future<ProvenanceImportResult> importBackupJson(
    String rawJson, {
    String? importIntoServerKey,
    bool overwriteStorageIfCorrupted = false,
  }) async {
    await ensureLoaded();
    return _runSerialized(() async {
      if (_corruptedOrReadError && !overwriteStorageIfCorrupted) {
        throw const FormatException('当前本地存储处于读取异常状态，请确认覆盖或修复后再导入');
      }

      final dynamic decoded = jsonDecode(rawJson);
      if (decoded is! Map<String, dynamic>) {
        throw const FormatException('备份文件格式错误：根节点必须是 JSON 对象');
      }
      if (decoded['schema_version'] != currentSchemaVersion) {
        throw FormatException(
          '不支持的备份版本号: ${decoded['schema_version']}',
        );
      }
      final byServerRaw = decoded['records_by_server'];
      if (byServerRaw is! Map) {
        throw const FormatException('备份缺少 records_by_server 字段');
      }

      final parsedByServer = <String, List<ManualRuleRecord>>{};
      for (final entry in byServerRaw.entries) {
        final rawSrvKey = entry.key.toString().trim();
        final listRaw = entry.value;
        if (listRaw is! List) {
          throw FormatException('服务器 $rawSrvKey 记录格式无效');
        }
        final targetSrvKey = importIntoServerKey?.trim().isNotEmpty == true
            ? importIntoServerKey!.trim()
            : rawSrvKey;
        if (targetSrvKey.isEmpty) continue;

        final targetList = parsedByServer.putIfAbsent(targetSrvKey, () => []);
        for (final rawItem in listRaw) {
          if (rawItem is! Map) {
            throw const FormatException('存在非对象格式的规则记录');
          }
          final rawMap = Map<String, dynamic>.from(rawItem);
          rawMap['server_key'] = targetSrvKey;
          final rec = ManualRuleRecord.fromJson(rawMap);
          targetList.add(rec);
        }
      }

      if (overwriteStorageIfCorrupted) {
        _corruptedOrReadError = false;
        _storageErrorDetail = null;
      }

      var importedCount = 0;
      var updatedCount = 0;
      var skippedCount = 0;
      final now = _nowProvider().toUtc();

      for (final entry in parsedByServer.entries) {
        final bucket = _recordsByServer.putIfAbsent(entry.key, () => []);
        for (final incoming in entry.value) {
          final existingIdx =
              bucket.indexWhere((r) => r.ruleText == incoming.ruleText);
          if (existingIdx < 0) {
            // 新导入记录等待与 Core 实际规则核对前先以 unconfirmed 还是保留 present？
            // 若能与 Core 同步则会立刻校正；先保留备份记录但更新 updatedAt
            bucket.add(incoming.copyWith(updatedAt: now));
            importedCount += 1;
          } else {
            final existing = bucket[existingIdx];
            if (incoming.updatedAt.isAfter(existing.updatedAt) ||
                (existing.note == null && incoming.note != null)) {
              bucket[existingIdx] = incoming.copyWith(
                recordId: existing.recordId,
                updatedAt: now,
              );
              updatedCount += 1;
            } else {
              skippedCount += 1;
            }
          }
        }
      }

      final saved = await _persistUnlocked();
      if (!saved) {
        throw FileSystemException(
          '导入后写入存储失败',
          await _backend.storageDescription,
        );
      }
      notifyListeners();
      return ProvenanceImportResult(
        importedCount: importedCount,
        updatedCount: updatedCount,
        skippedCount: skippedCount,
      );
    });
  }

  /// 仅测试或用户明确选择重置损坏的本地来源库时使用（不改动 Core 规则）。
  Future<void> resetCorruptedStoreForRecovery() async {
    await ensureLoaded();
    await _runSerialized(() async {
      _recordsByServer.clear();
      _corruptedOrReadError = false;
      _storageErrorDetail = null;
      await _persistUnlocked();
      notifyListeners();
    });
  }
}
