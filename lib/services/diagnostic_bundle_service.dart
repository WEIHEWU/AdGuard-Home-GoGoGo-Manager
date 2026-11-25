import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'diagnostic_redactor.dart';
import 'diagnostic_zip_builder.dart';
import 'module_config_service.dart';
import '../providers/app_config_provider.dart';

class DiagnosticCancelToken {
  bool _cancelled = false;
  bool get isCancelled => _cancelled;
  void cancel() {
    _cancelled = true;
  }
}

class DiagnosticItemStatus {
  final String key;
  final String fileName;
  final String title;
  final String status; // ok | partial | missing | timeout | failed | truncated | skipped
  final int elapsedMs;
  final int bytes;
  final String note;

  const DiagnosticItemStatus({
    required this.key,
    required this.fileName,
    required this.title,
    required this.status,
    required this.elapsedMs,
    required this.bytes,
    this.note = '',
  });

  Map<String, dynamic> toJson() => <String, dynamic>{
        'key': key,
        'file': fileName,
        'title': title,
        'status': status,
        'elapsed_ms': elapsedMs,
        'bytes': bytes,
        'note': note,
      };
}

class DiagnosticBundleResult {
  final bool succeeded;
  final bool cancelled;
  final bool partialSuccess;
  final String zipPath;
  final String savedDisplayPath;
  final bool savedToPublicDownloads;
  final String fileName;
  final int zipBytes;
  final String bundleId;
  final DateTime generatedAtUtc;
  final DateTime? generatedAtLocal;
  final List<DiagnosticItemStatus> items;
  final String previewText;
  final String summaryText;
  final String errorMessage;

  const DiagnosticBundleResult({
    required this.succeeded,
    this.cancelled = false,
    this.partialSuccess = false,
    this.zipPath = '',
    this.savedDisplayPath = '',
    this.savedToPublicDownloads = false,
    this.fileName = '',
    this.zipBytes = 0,
    this.bundleId = '',
    required this.generatedAtUtc,
    this.generatedAtLocal,
    this.items = const <DiagnosticItemStatus>[],
    this.previewText = '',
    this.summaryText = '',
    this.errorMessage = '',
  });
}

typedef DiagCacheDirProvider = Future<String?> Function();
typedef DiagShareInvoker = Future<bool> Function(String filePath, String title);
typedef DiagDownloadsSaver
    = Future<({bool saved, String displayPath, bool isPublicDownload})>
        Function(String filePath, String fileName);
typedef DiagNowProvider = DateTime Function();

class DiagnosticBundleService {
  static const int maxZipBytes = 2 * 1024 * 1024; // 2 MiB
  static const int maxCachedBundles = 3;
  static const Duration maxCacheAge = Duration(hours: 24);
  static const Duration totalCollectionBudget = Duration(seconds: 20);
  static const Duration defaultItemTimeout = Duration(seconds: 4);

  static const MethodChannel _diagChannel =
      MethodChannel('com.wu.adgogogo/diagnostics');

  static Future<DiagnosticBundleResult>? _activeExport;

  static bool get isExporting => _activeExport != null;

  @visibleForTesting
  static void resetTestState() {
    _activeExport = null;
  }

  /// 将 DateTime 格式化为带本地时区偏移的 ISO-8601 字符串（如 +11:00）
  static String formatIso8601WithOffset(DateTime dt) {
    final y = dt.year.toString().padLeft(4, '0');
    final mo = dt.month.toString().padLeft(2, '0');
    final d = dt.day.toString().padLeft(2, '0');
    final h = dt.hour.toString().padLeft(2, '0');
    final mi = dt.minute.toString().padLeft(2, '0');
    final s = dt.second.toString().padLeft(2, '0');
    final ms = dt.millisecond.toString().padLeft(3, '0');
    if (dt.isUtc) {
      return '$y-$mo-${d}T$h:$mi:$s.${ms}Z';
    }
    final offset = dt.timeZoneOffset;
    final sign = offset.isNegative ? '-' : '+';
    final absMin = offset.inMinutes.abs();
    final offH = (absMin ~/ 60).toString().padLeft(2, '0');
    final offM = (absMin % 60).toString().padLeft(2, '0');
    return '$y-$mo-${d}T$h:$mi:$s.$ms$sign$offH:$offM';
  }

  final ModuleConfigService _moduleService;
  final DiagCacheDirProvider _cacheDirProvider;
  final DiagShareInvoker _shareInvoker;
  final DiagDownloadsSaver _downloadsSaver;
  final DiagNowProvider _nowProvider;
  final Duration _itemTimeout;
  final Duration _totalBudget;

  DiagnosticBundleService({
    ModuleConfigService? moduleService,
    DiagCacheDirProvider? cacheDirProvider,
    DiagShareInvoker? shareInvoker,
    DiagDownloadsSaver? downloadsSaver,
    DiagNowProvider? nowProvider,
    Duration itemTimeout = defaultItemTimeout,
    Duration totalBudget = totalCollectionBudget,
  })  : _moduleService = moduleService ?? ModuleConfigService(),
        _cacheDirProvider = cacheDirProvider ?? _defaultCacheDirProvider,
        _shareInvoker = shareInvoker ?? _defaultShareInvoker,
        _downloadsSaver = downloadsSaver ?? _defaultDownloadsSaver,
        _nowProvider = nowProvider ?? DateTime.now,
        _itemTimeout = itemTimeout,
        _totalBudget = totalBudget;

  static Future<String?> _defaultCacheDirProvider() async {
    try {
      return await _diagChannel.invokeMethod<String>('getCacheDiagDir');
    } catch (_) {
      return null;
    }
  }

  static Future<bool> _defaultShareInvoker(
      String filePath, String title) async {
    try {
      final res = await _diagChannel.invokeMethod<bool>(
        'shareDiagBundle',
        <String, dynamic>{'filePath': filePath, 'title': title},
      );
      return res ?? false;
    } catch (_) {
      return false;
    }
  }

  static Future<({bool saved, String displayPath, bool isPublicDownload})>
      _defaultDownloadsSaver(String filePath, String fileName) async {
    try {
      final raw = await _diagChannel.invokeMethod<Map<Object?, Object?>>(
        'saveDiagBundleToDownloads',
        <String, dynamic>{'filePath': filePath, 'fileName': fileName},
      );
      if (raw != null && raw['saved'] == true) {
        final displayPath = (raw['displayPath'] as String?) ?? '';
        final isPublic = raw['isPublicDownload'] == true;
        if (displayPath.isNotEmpty) {
          return (
            saved: true,
            displayPath: displayPath,
            isPublicDownload: isPublic,
          );
        }
      }
    } catch (_) {}
    return (saved: true, displayPath: filePath, isPublicDownload: false);
  }

  /// 清理过期（>24h）及超出保留上限（最多 3 份）的缓存 ZIP，不删除刚生成或正在分享的包
  Future<void> pruneOldBundles(
    Directory dir, {
    String? keepPath,
    int targetMaxFiles = maxCachedBundles,
  }) async {
    try {
      if (!await dir.exists()) return;
      final now = DateTime.now();
      final files = <File>[];
      await for (final entity in dir.list(followLinks: false)) {
        if (entity is! File) continue;
        final name = entity.uri.pathSegments.isEmpty
            ? ''
            : entity.uri.pathSegments.last;
        if (!name.startsWith('agh_diag_') || !name.endsWith('.zip')) continue;
        if (keepPath != null && entity.path == keepPath) continue;
        try {
          final stat = await entity.stat();
          if (now.difference(stat.modified) > maxCacheAge) {
            await entity.delete();
            continue;
          }
          files.add(entity);
        } catch (_) {}
      }

      if (files.length <= targetMaxFiles) return;
      final stats = <File, DateTime>{};
      for (final f in files) {
        try {
          stats[f] = (await f.stat()).modified;
        } catch (_) {
          stats[f] = DateTime.fromMillisecondsSinceEpoch(0);
        }
      }
      files.sort((a, b) => stats[a]!.compareTo(stats[b]!));
      var toDelete = files.length - targetMaxFiles;
      for (final f in files) {
        if (toDelete <= 0) break;
        try {
          await f.delete();
          toDelete--;
        } catch (_) {}
      }
    } catch (_) {}
  }

  Future<bool> shareBundle(
    String zipPath, {
    String title = '分享 AdGuard Home GoGoGo 诊断包',
  }) async {
    if (zipPath.isEmpty) return false;
    final f = File(zipPath);
    if (!await f.exists()) return false;
    // 绝不在此处或返回后立即删除文件，避免接收应用尚在读取 content:// URI
    return _shareInvoker(zipPath, title);
  }

  /// 生成脱敏诊断包（单飞互斥：连续点击合并等待同一任务）
  Future<DiagnosticBundleResult> exportBundle({
    DiagnosticCancelToken? cancelToken,
    String appVersion = AppConfigProvider.appVersion,
  }) {
    final existing = _activeExport;
    if (existing != null) {
      return existing;
    }
    final future = _performExport(
      cancelToken: cancelToken,
      appVersion: appVersion,
    );
    _activeExport = future;
    future.whenComplete(() {
      if (identical(_activeExport, future)) {
        _activeExport = null;
      }
    });
    return future;
  }

  Future<DiagnosticBundleResult> _performExport({
    DiagnosticCancelToken? cancelToken,
    required String appVersion,
  }) async {
    final totalSw = Stopwatch()..start();
    final localNow = _nowProvider();
    final utcNow = localNow.toUtc();
    final localIso = formatIso8601WithOffset(localNow);
    final randHex =
        Random().nextInt(0xFFFF).toRadixString(16).padLeft(4, '0');
    final stamp =
        '${localNow.year.toString().padLeft(4, '0')}'
        '${localNow.month.toString().padLeft(2, '0')}'
        '${localNow.day.toString().padLeft(2, '0')}_'
        '${localNow.hour.toString().padLeft(2, '0')}'
        '${localNow.minute.toString().padLeft(2, '0')}'
        '${localNow.second.toString().padLeft(2, '0')}';
    final bundleId = 'diag_${stamp}_$randHex';
    final fileName = 'agh_$bundleId.zip';

    final cacheDirPath = await _cacheDirProvider();
    if (cacheDirPath == null || cacheDirPath.isEmpty) {
      return DiagnosticBundleResult(
        succeeded: false,
        bundleId: bundleId,
        generatedAtUtc: utcNow,
        generatedAtLocal: localNow,
        errorMessage: '无法访问应用私有缓存目录',
      );
    }

    final cacheDir = Directory(cacheDirPath);
    if (!await cacheDir.exists()) {
      await cacheDir.create(recursive: true);
    }
    // 写入新包前先修剪旧缓存，确保落盘后总数不超过 maxCachedBundles (3)
    await pruneOldBundles(cacheDir, targetMaxFiles: maxCachedBundles - 1);

    final ctx = RedactionContext();
    final itemStatuses = <DiagnosticItemStatus>[];
    final entries = <String, String>{};

    final hasRoot = await _moduleService.hasRoot();

    Duration remainingBudget() {
      final rem = _totalBudget - totalSw.elapsed;
      return rem.isNegative ? Duration.zero : rem;
    }

    // 各独立采集项：任一项失败、缺失或超时均继续采集其余项，绝不获取生命周期锁
    Future<void> collectStep({
      required String key,
      required String entryFile,
      required String title,
      required Future<({String status, String content, String note})> Function(
              Duration timeout)
          collector,
    }) async {
      if (cancelToken?.isCancelled == true) {
        itemStatuses.add(DiagnosticItemStatus(
          key: key,
          fileName: entryFile,
          title: title,
          status: 'skipped',
          elapsedMs: 0,
          bytes: 0,
          note: '用户已取消导出',
        ));
        return;
      }
      final remaining = remainingBudget();
      if (remaining <= const Duration(milliseconds: 250)) {
        final msg =
            '已超过总采集预算 (${_totalBudget.inSeconds}s，含 Root 探测与准备耗时)，跳过本项采集。';
        entries[entryFile] = msg;
        itemStatuses.add(DiagnosticItemStatus(
          key: key,
          fileName: entryFile,
          title: title,
          status: 'timeout',
          elapsedMs: 0,
          bytes: utf8.encode(msg).length,
          note: '超出总时间预算',
        ));
        return;
      }
      final stepTimeout =
          remaining < _itemTimeout ? remaining : _itemTimeout;
      final sw = Stopwatch()..start();
      try {
        final collected = await collector(stepTimeout);
        sw.stop();
        final redacted = DiagnosticRedactor.redact(
          collected.content,
          context: ctx,
        );
        final outContent = redacted.isEmpty ? '(无输出)' : redacted;
        entries[entryFile] = outContent;
        itemStatuses.add(DiagnosticItemStatus(
          key: key,
          fileName: entryFile,
          title: title,
          status: collected.status,
          elapsedMs: sw.elapsedMilliseconds,
          bytes: utf8.encode(outContent).length,
          note: collected.note,
        ));
      } catch (e) {
        sw.stop();
        final errBody = DiagnosticRedactor.redact(
          '采集异常: $e',
          context: ctx,
        );
        entries[entryFile] = errBody;
        itemStatuses.add(DiagnosticItemStatus(
          key: key,
          fileName: entryFile,
          title: title,
          status: 'failed',
          elapsedMs: sw.elapsedMilliseconds,
          bytes: utf8.encode(errBody).length,
          note: '采集异常',
        ));
      }
    }

    await collectStep(
      key: 'module_logs',
      entryFile: '01_module_logs.txt',
      title: '模块运行日志 (当前与上一份)',
      collector: (timeout) => _collectModuleLogs(hasRoot, timeout),
    );

    await collectStep(
      key: 'core_crash_log',
      entryFile: '02_core_crash_log.txt',
      title: '核心崩溃日志',
      collector: (timeout) => _collectCoreCrashLog(hasRoot, timeout),
    );

    await collectStep(
      key: 'module_state',
      entryFile: '03_module_state_and_rules_digest.txt',
      title: '模块运行状态与规则摘要',
      collector: (timeout) => _collectModuleStateAndDigest(hasRoot, timeout),
    );

    await collectStep(
      key: 'lock_diagnostics',
      entryFile: '04_lock_diagnostics.txt',
      title: '锁状态快照 (不获取正式锁)',
      collector: (timeout) => _collectLockDiagnostics(hasRoot, timeout),
    );

    await collectStep(
      key: 'lock_flock_selfcheck',
      entryFile: '04b_lock_flock_selfcheck.txt',
      title: '锁语义自检 (--diag-flock)',
      collector: (timeout) => _collectLockFlockSelfCheck(hasRoot, timeout),
    );

    await collectStep(
      key: 'firewall_summary',
      entryFile: '05_firewall_summary.txt',
      title: '防火墙摘要 (仅模块自有链)',
      collector: (timeout) => _collectFirewallSummary(hasRoot, timeout),
    );

    await collectStep(
      key: 'resource_snapshot',
      entryFile: '06_resource_snapshot.txt',
      title: '资源快照',
      collector: (timeout) => _collectResourceSnapshot(hasRoot, timeout),
    );

    await collectStep(
      key: 'manager_operations',
      entryFile: '07_manager_operations.txt',
      title: '管理器近期操作记录',
      collector: (_) => _collectManagerOperations(),
    );

    if (cancelToken?.isCancelled == true) {
      return DiagnosticBundleResult(
        succeeded: false,
        cancelled: true,
        bundleId: bundleId,
        generatedAtUtc: utcNow,
        generatedAtLocal: localNow,
        items: itemStatuses,
        errorMessage: '已取消诊断包生成',
      );
    }

    final partial = itemStatuses.any(
      (s) => s.status != 'ok' && s.status != 'missing',
    );

    void rebuildManifestAndReadme({String extraNote = ''}) {
      final manifestMap = <String, dynamic>{
        'bundle_id': bundleId,
        'generated_at_utc': utcNow.toIso8601String(),
        'generated_at_local': localIso,
        'manager_version': appVersion,
        'has_root': hasRoot,
        'partial_success': partial,
        'privacy_notice': '已按默认规则脱敏，但仍请检查内容后再分享。',
        'excluded_by_policy': const <String>[
          'DNS query history (querylog.json)',
          'Full AdGuardHome.yaml configuration',
          'Filter rule contents (only count & SHA-256 digests)',
          'Installed package list / full system ps / full logcat / bugreport',
          'Third-party proxy configs & .orig/.meta backups',
          '/proc/<pid>/environ & passwords/tokens/cookies/keys',
        ],
        if (extraNote.isNotEmpty) 'size_guard_note': extraNote,
        'items': itemStatuses.map((e) => e.toJson()).toList(),
      };
      entries['manifest.json'] =
          const JsonEncoder.withIndent('  ').convert(manifestMap);

      final readmeBuf = StringBuffer()
        ..writeln('AdGuard Home GoGoGo 诊断包 ($bundleId)')
        ..writeln('生成时间 (本地): $localIso')
        ..writeln('生成时间 (UTC): ${utcNow.toIso8601String()}')
        ..writeln('管理器版本: $appVersion')
        ..writeln('Root 权限可用: ${hasRoot ? "是" : "否 (部分诊断包)"}')
        ..writeln('隐私声明: 已按默认规则脱敏，但仍请检查内容后再分享。')
        ..writeln('')
        ..writeln('=== 各采集项状态 ===');
      for (final item in itemStatuses) {
        final noteSuffix = item.note.isEmpty ? '' : ' (${item.note})';
        readmeBuf.writeln(
          '- [${item.status.toUpperCase()}] ${item.title} -> ${item.fileName} (${item.bytes} B, ${item.elapsedMs} ms)$noteSuffix',
        );
      }
      if (extraNote.isNotEmpty) {
        readmeBuf
          ..writeln('')
          ..writeln('大小保护: $extraNote');
      }
      entries['00_README_AND_MANIFEST.txt'] = readmeBuf.toString();
    }

    rebuildManifestAndReadme();

    // 写入磁盘之前全程均为已脱敏文本，再压缩编码并检查 2 MiB 硬上限
    var orderedEntries = <String, String>{
      '00_README_AND_MANIFEST.txt': entries['00_README_AND_MANIFEST.txt'] ?? '',
      'manifest.json': entries['manifest.json'] ?? '{}',
      for (final k in entries.keys)
        if (k != '00_README_AND_MANIFEST.txt' && k != 'manifest.json')
          k: entries[k]!,
    };
    var zipBytes = DiagnosticZipBuilder.buildZip(orderedEntries);

    if (zipBytes.length > maxZipBytes) {
      // 超出 2 MiB 限制时截断大日志尾部/头端，保留尾部关键故障上下文并重新生成 Manifest
      const capChars = 128 * 1024;
      for (final largeKey in const <String>[
        '01_module_logs.txt',
        '02_core_crash_log.txt',
      ]) {
        final val = orderedEntries[largeKey];
        if (val != null && val.length > capChars) {
          orderedEntries[largeKey] =
              '[...为满足 2 MiB 包大小上限已截断较早记录...]\n'
              '${val.substring(val.length - capChars)}';
        }
      }
      rebuildManifestAndReadme(
        extraNote: '部分日志已按 2 MiB 上限截断，保留最近关键上下文。',
      );
      orderedEntries['00_README_AND_MANIFEST.txt'] =
          entries['00_README_AND_MANIFEST.txt'] ?? '';
      orderedEntries['manifest.json'] = entries['manifest.json'] ?? '{}';
      zipBytes = DiagnosticZipBuilder.buildZip(orderedEntries);
    }

    final zipFile = File('${cacheDir.path}/$fileName');
    final tmpFile = File('${cacheDir.path}/.$fileName.tmp');
    await tmpFile.writeAsBytes(zipBytes, flush: true);
    await tmpFile.rename(zipFile.path);

    // 默认同步保存到系统公共 Download 目录（Android 10+ 走 MediaStore.Downloads），同时保留缓存副本供 FileProvider 分享
    final dlSave = await _downloadsSaver(zipFile.path, fileName);
    final displayPath =
        dlSave.displayPath.isNotEmpty ? dlSave.displayPath : zipFile.path;

    final previewBuf = StringBuffer()
      ..writeln('【已按默认规则脱敏，但仍请检查内容后再分享。】')
      ..writeln('')
      ..writeln(orderedEntries['00_README_AND_MANIFEST.txt'] ?? '')
      ..writeln('=== 04_lock_diagnostics.txt ===')
      ..writeln(_truncatePreview(orderedEntries['04_lock_diagnostics.txt'] ?? ''))
      ..writeln('')
      ..writeln('=== 04b_lock_flock_selfcheck.txt ===')
      ..writeln(
          _truncatePreview(orderedEntries['04b_lock_flock_selfcheck.txt'] ?? ''))
      ..writeln('')
      ..writeln('=== 03_module_state_and_rules_digest.txt ===')
      ..writeln(_truncatePreview(
          orderedEntries['03_module_state_and_rules_digest.txt'] ?? ''))
      ..writeln('')
      ..writeln('=== 07_manager_operations.txt ===')
      ..writeln(_truncatePreview(orderedEntries['07_manager_operations.txt'] ?? ''))
      ..writeln('')
      ..writeln('=== 01_module_logs.txt (尾部摘要) ===')
      ..writeln(_tailPreview(orderedEntries['01_module_logs.txt'] ?? '', 4000));

    final redactedPreview = DiagnosticRedactor.redact(
      previewBuf.toString(),
      context: ctx,
    );
    final redactedSummary = DiagnosticRedactor.redact(
      orderedEntries['00_README_AND_MANIFEST.txt'] ?? '',
      context: ctx,
    );

    return DiagnosticBundleResult(
      succeeded: true,
      partialSuccess: partial || !hasRoot,
      zipPath: zipFile.path,
      savedDisplayPath: displayPath,
      savedToPublicDownloads: dlSave.isPublicDownload,
      fileName: fileName,
      zipBytes: zipBytes.length,
      bundleId: bundleId,
      generatedAtUtc: utcNow,
      generatedAtLocal: localNow,
      items: itemStatuses,
      previewText: redactedPreview,
      summaryText: redactedSummary,
    );
  }

  static String _truncatePreview(String text, [int maxChars = 2500]) {
    if (text.length <= maxChars) return text;
    return '${text.substring(0, maxChars)}\n[...预览已省略...]';
  }

  static String _tailPreview(String text, [int maxChars = 4000]) {
    if (text.length <= maxChars) return text;
    return '[...较早日志在包内完整保存...]\n${text.substring(text.length - maxChars)}';
  }

  ({String status, String content, String note}) _evaluateCommandResult(
    ProcessResult res, {
    required String itemLabel,
    required String timeoutEmptyMsg,
    String? missingMsg,
  }) {
    final partialOut = res.stdout.toString().trim();
    final stderrText = res.stderr.toString();
    final unconfirmed = stderrText.contains('unconfirmed_exit');
    if (res.exitCode == 124) {
      final statusNote = unconfirmed ? 'timeout;unconfirmed_exit' : 'timeout';
      if (partialOut.isEmpty) {
        final msg = unconfirmed
            ? '$timeoutEmptyMsg（子进程退出尚未确认）'
            : timeoutEmptyMsg;
        return (status: 'timeout', content: msg, note: statusNote);
      }
      final banner = unconfirmed
          ? '采集超时（子进程退出尚未确认），以下为部分输出'
          : '采集超时，以下为部分输出';
      return (
        status: 'timeout',
        content: '=== $banner ===\n$partialOut',
        note: statusNote,
      );
    }
    if (res.exitCode != 0) {
      if (partialOut.isNotEmpty) {
        return (
          status: 'partial',
          content:
              '=== 读取$itemLabel异常退出 (exit=${res.exitCode})，以下为部分输出 ===\n$partialOut',
          note: 'exit_${res.exitCode}',
        );
      }
      return (
        status: 'failed',
        content: '读取$itemLabel失败 (exit=${res.exitCode})',
        note: 'exit_${res.exitCode}',
      );
    }
    if (missingMsg != null &&
        (partialOut.isEmpty || partialOut == '__MISSING__')) {
      return (status: 'missing', content: missingMsg, note: 'missing');
    }
    return (status: 'ok', content: partialOut, note: '');
  }

  Future<({String status, String content, String note})> _collectModuleLogs(
    bool hasRoot,
    Duration timeout,
  ) async {
    if (!hasRoot) {
      return (status: 'failed', content: '无 Root 权限，未能读取模块运行日志。', note: 'no_root');
    }
    const cmd = '''
found=0
if [ -f /data/adb/agh/agh.log ]; then
  found=1
  echo "=== /data/adb/agh/agh.log ==="
  tail -n 1500 /data/adb/agh/agh.log 2>/dev/null
fi
if [ -f /data/adb/agh/agh.log.1 ]; then
  found=1
  echo "=== /data/adb/agh/agh.log.1 ==="
  tail -n 1500 /data/adb/agh/agh.log.1 2>/dev/null
fi
[ "\$found" -eq 1 ] || echo "__MISSING__"
''';
    final res = await _moduleService.runSuTimed(cmd, timeout: timeout);
    return _evaluateCommandResult(
      res,
      itemLabel: '模块日志',
      timeoutEmptyMsg: '读取模块日志超时。',
      missingMsg: '当前未找到模块运行日志 (/data/adb/agh/agh.log)。',
    );
  }

  Future<({String status, String content, String note})> _collectCoreCrashLog(
    bool hasRoot,
    Duration timeout,
  ) async {
    if (!hasRoot) {
      return (status: 'failed', content: '无 Root 权限，未能检查核心崩溃日志。', note: 'no_root');
    }
    const cmd = '''
found=0
for f in /data/adb/agh/core_crash.log /data/adb/agh/crash.log /data/adb/agh/bin/AdGuardHome.log; do
  if [ -s "\$f" ]; then
    found=1
    echo "=== \$f (tail 32KiB) ==="
    tail -c 32768 "\$f" 2>/dev/null
  fi
done
[ "\$found" -eq 1 ] || echo "__MISSING__"
''';
    final res = await _moduleService.runSuTimed(cmd, timeout: timeout);
    return _evaluateCommandResult(
      res,
      itemLabel: '核心崩溃日志',
      timeoutEmptyMsg: '读取核心崩溃日志超时。',
      missingMsg: '未发现核心崩溃日志文件。',
    );
  }

  Future<({String status, String content, String note})>
      _collectModuleStateAndDigest(bool hasRoot, Duration timeout) async {
    if (!hasRoot) {
      return (
        status: 'failed',
        content: '无 Root 权限，未能读取模块目录状态与规则摘要。',
        note: 'no_root'
      );
    }
    // 严格白名单字段：不输出 PROXY_URL 原值、不读取 AdGuardHome.yaml 正文、不读取规则正文、不读取 querylog.json
    const cmd = '''
echo "=== module.prop ==="
grep -E '^(id|name|version|versionCode)=' /data/adb/modules/AdGuardHome/module.prop 2>/dev/null || true
echo "=== config.prop (allowed summary keys only) ==="
grep -E '^(RUN_MODE|redir_port|ENABLE_SNI|VPN_DNS_TAKEOVER)=' /data/adb/agh/scripts/config.prop 2>/dev/null || true
echo "=== diag.conf ==="
cat /data/adb/agh/diag.conf 2>/dev/null || echo "missing"
echo "=== AdGuardHome core & watchdog state ==="
core_pid=\$(pidof AdGuardHome 2>/dev/null | awk '{print \$1}')
echo "core_pid_pidof=\${core_pid:-none}"
echo "core_pid_file=\$(cat /data/adb/agh/bin/AdGuardHome.pid 2>/dev/null || echo none)"
echo "vpn_mode_status=\$(cat /data/adb/agh/vpn_mode_status 2>/dev/null || echo none)"
if [ -f /data/adb/agh/bin/AdGuardHome.yaml ]; then
  y_sz=\$(wc -c < /data/adb/agh/bin/AdGuardHome.yaml 2>/dev/null | tr -d ' ')
  y_sha=\$(sha256sum /data/adb/agh/bin/AdGuardHome.yaml 2>/dev/null | awk '{print \$1}')
  echo "yaml_present=1 bytes=\${y_sz:-0} sha256=\${y_sha:-unavailable}"
else
  echo "yaml_present=0"
fi
echo "=== rules digest (count & hashes only, no rule text) ==="
f_cnt=0
for rf in /data/adb/agh/bin/data/filters/*.txt; do
  [ -f "\$rf" ] || continue
  f_cnt=\$((f_cnt + 1))
  r_sz=\$(wc -c < "\$rf" 2>/dev/null | tr -d ' ')
  r_sha=\$(sha256sum "\$rf" 2>/dev/null | awk '{print \$1}')
  echo "filter file=\${rf##*/} bytes=\${r_sz:-0} sha256=\${r_sha:-unavailable}"
done
echo "filters_total_count=\$f_cnt"
''';
    final res = await _moduleService.runSuTimed(cmd, timeout: timeout);
    return _evaluateCommandResult(
      res,
      itemLabel: '模块状态',
      timeoutEmptyMsg: '读取模块状态超时。',
    );
  }

  Future<({String status, String content, String note})>
      _collectLockDiagnostics(bool hasRoot, Duration timeout) async {
    if (!hasRoot) {
      return (
        status: 'failed',
        content: '无 Root 权限，未能收集锁状态快照。',
        note: 'no_root'
      );
    }
    // 严格只读快速快照：不获取 agh_op.flock / agh_watchdog.flock / agh_log.flock，不修复/停止/清理/重置锁，不读 environ
    const cmd = '''
echo "note=导出过程不获取生命周期操作锁，不修改/删除/释放任何正式锁文件"
echo "diag_pid_disclaimer=诊断PID仅作为排查线索，不能单独证明当前内核锁的真实持有者"
for pf in /dev/shm/agh_op.pid /data/adb/agh/run/agh_op.pid /dev/shm/agh_watchdog.pid /data/adb/agh/run/agh_watchdog.pid /dev/shm/agh_manual_stop /data/adb/agh/run/agh_manual_stop; do
  if [ -e "\$pf" ]; then
    echo "state_file=\$pf value=\$(cat "\$pf" 2>/dev/null | tr -d '\\r\\n' | head -c 64)"
  fi
done
echo "=== lock file inodes ==="
for lf in /dev/shm/agh_op.flock /data/adb/agh/run/agh_op.flock /dev/shm/agh_watchdog.flock /data/adb/agh/run/agh_watchdog.flock /dev/shm/agh_log.flock /data/adb/agh/run/agh_log.flock; do
  [ -e "\$lf" ] && ls -li "\$lf" 2>/dev/null || true
done
echo "=== targeted /proc/<pid> status & fd summary (module PIDs only, no environ) ==="
cand_pids=""
for pf in /dev/shm/agh_op.pid /data/adb/agh/run/agh_op.pid /dev/shm/agh_watchdog.pid /data/adb/agh/run/agh_watchdog.pid /data/adb/agh/bin/AdGuardHome.pid; do
  if [ -r "\$pf" ]; then
    p=\$(cat "\$pf" 2>/dev/null | tr -cd '0-9')
    [ -n "\$p" ] && cand_pids="\$cand_pids \$p"
  fi
done
c_pid=\$(pidof AdGuardHome 2>/dev/null | awk '{print \$1}')
[ -n "\$c_pid" ] && cand_pids="\$cand_pids \$c_pid"
seen=""
for p in \$cand_pids; do
  case " \$seen " in *" \$p "*) continue ;; esac
  seen="\$seen \$p"
  if [ -d "/proc/\$p" ]; then
    echo "--- pid=\$p comm=\$(cat /proc/\$p/comm 2>/dev/null || echo unknown) ---"
    grep -E '^(Name|State|Pid|PPid|Gid|VmRSS|Threads):' "/proc/\$p/status" 2>/dev/null || true
    for fdl in /proc/\$p/fd/*; do
      [ -L "\$fdl" ] || continue
      tgt=\$(readlink "\$fdl" 2>/dev/null || true)
      case "\$tgt" in
        *agh_*|*flock*) echo "  fd=\${fdl##*/} -> \$tgt" ;;
      esac
    done
  else
    echo "--- pid=\$p state=not_in_proc ---"
  fi
done
''';
    final res = await _moduleService.runSuTimed(cmd, timeout: timeout);
    return _evaluateCommandResult(
      res,
      itemLabel: '锁状态快照',
      timeoutEmptyMsg: '锁状态快照采集超时（未阻塞导出）。',
    );
  }

  Future<({String status, String content, String note})>
      _collectLockFlockSelfCheck(bool hasRoot, Duration timeout) async {
    if (!hasRoot) {
      return (
        status: 'failed',
        content: '无 Root 权限，未能执行 --diag-flock 锁自检。',
        note: 'no_root'
      );
    }
    const cmd = '''
echo "=== --diag-flock (brief temp probe test only, never alters official locks) ==="
if [ -f /data/adb/modules/AdGuardHome/service.sh ]; then
  /system/bin/sh /data/adb/modules/AdGuardHome/service.sh --diag-flock 2>&1 || true
else
  echo "service.sh missing"
fi
''';
    final res = await _moduleService.runSuTimed(cmd, timeout: timeout);
    return _evaluateCommandResult(
      res,
      itemLabel: '锁语义自检',
      timeoutEmptyMsg: '--diag-flock 自检超时（快速锁状态快照已独立保存）。',
    );
  }

  Future<({String status, String content, String note})>
      _collectFirewallSummary(bool hasRoot, Duration timeout) async {
    if (!hasRoot) {
      return (
        status: 'failed',
        content: '无 Root 权限，未能读取防火墙规则摘要。',
        note: 'no_root'
      );
    }
    const cmd = '''
echo "ipv6_dns_mode=\$(cat /dev/shm/agh_ipv6_dns_mode /data/adb/agh/run/agh_ipv6_dns_mode 2>/dev/null | head -n 1)"
echo "sni_fw_mode=\$(cat /dev/shm/agh_sni_fw_mode /data/adb/agh/run/agh_sni_fw_mode 2>/dev/null | head -n 1)"
echo "=== nat OUTPUT jumps (ADGUARD only) ==="
iptables -w 2 -t nat -S OUTPUT 2>/dev/null | grep -E '^-P|^-A OUTPUT -j ADGUARD\$' || true
echo "=== nat ADGUARD ==="
iptables -w 2 -t nat -S ADGUARD 2>/dev/null || echo "chain_absent"
echo "=== filter OUTPUT/INPUT jumps (module chains only) ==="
iptables -w 2 -t filter -S OUTPUT 2>/dev/null | grep -E '^-P|^-A OUTPUT -j ADGUARD_DOT\$' || true
iptables -w 2 -t filter -S INPUT 2>/dev/null | grep -E '^-P|^-A INPUT -j AGH_INPUT\$' || true
echo "=== mangle OUTPUT jump & AGH_SNI ==="
iptables -w 2 -t mangle -S OUTPUT 2>/dev/null | grep -E '^-P|^-A OUTPUT -j AGH_SNI\$' || true
iptables -w 2 -t mangle -S AGH_SNI 2>/dev/null || echo "chain_absent"
''';
    final res = await _moduleService.runSuTimed(cmd, timeout: timeout);
    return _evaluateCommandResult(
      res,
      itemLabel: '防火墙摘要',
      timeoutEmptyMsg: '读取防火墙摘要超时。',
    );
  }

  Future<({String status, String content, String note})>
      _collectResourceSnapshot(bool hasRoot, Duration timeout) async {
    if (!hasRoot) {
      return (
        status: 'failed',
        content: '无 Root 权限，未能读取系统与核心资源快照。',
        note: 'no_root'
      );
    }
    const cmd = '''
echo "uptime=\$(cat /proc/uptime 2>/dev/null || echo unavailable)"
echo "loadavg=\$(cat /proc/loadavg 2>/dev/null || echo unavailable)"
grep -E '^(MemTotal|MemAvailable):' /proc/meminfo 2>/dev/null || true
c_pid=\$(pidof AdGuardHome 2>/dev/null | awk '{print \$1}')
if [ -n "\$c_pid" ] && [ -r "/proc/\$c_pid/status" ]; then
  echo "=== core /proc/\$c_pid/status ==="
  grep -E '^(Name|State|Pid|Gid|VmRSS|VmSize|Threads):' "/proc/\$c_pid/status" 2>/dev/null || true
  ps -p "\$c_pid" -o pid,etime,comm 2>/dev/null || true
else
  echo "core_process=not_running"
fi
''';
    final res = await _moduleService.runSuTimed(cmd, timeout: timeout);
    return _evaluateCommandResult(
      res,
      itemLabel: '资源快照',
      timeoutEmptyMsg: '读取资源快照超时。',
    );
  }

  Future<({String status, String content, String note})>
      _collectManagerOperations() async {
    final ops = ModuleConfigService.recentOperations;
    if (ops.isEmpty) {
      return (status: 'ok', content: '本次会话尚无管理器操作记录。', note: 'empty');
    }
    final buf = StringBuffer();
    for (final op in ops) {
      buf.writeln(op.toSummaryLine());
    }
    return (status: 'ok', content: buf.toString().trimRight(), note: '');
  }
}
