import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

typedef SuProcessRunner = Future<ProcessResult> Function(
  String executable,
  List<String> arguments,
);

typedef SuProcessStarter = Future<Process> Function(
  String executable,
  List<String> arguments,
);

typedef SuProbeCandidateRunner = Future<ProcessResult?> Function(
  String executable,
  Duration timeout,
);

/// 结构化防火墙重载/自愈修复结果
class FirewallReloadResult {
  final bool succeeded;
  final bool unconfirmed;
  final String branch;
  final String stage;
  final bool systemDnsFlushed;
  final bool capabilityConfirmed;
  final String message;

  const FirewallReloadResult({
    required this.succeeded,
    this.unconfirmed = false,
    this.branch = 'unknown',
    this.stage = 'unknown',
    this.systemDnsFlushed = false,
    this.capabilityConfirmed = false,
    this.message = '',
  });

  factory FirewallReloadResult.fromScriptOutput({
    required int exitCode,
    required String stdoutText,
  }) {
    for (final rawLine in stdoutText.split('\n').reversed) {
      final line = rawLine.trim();
      if (!line.startsWith('AGH_REPAIR_RESULT ')) continue;
      final fields = <String, String>{};
      for (final token in line.substring('AGH_REPAIR_RESULT '.length).split(' ')) {
        final eq = token.indexOf('=');
        if (eq > 0) {
          fields[token.substring(0, eq).trim()] = token.substring(eq + 1).trim();
        }
      }
      final status = fields['status'] ?? '';
      final stage = fields['stage'] ?? 'unknown';
      final branch = fields['branch'] ?? 'unknown';
      final dnsFlushed = fields['dns_flushed'] == '1';
      final ok = exitCode == 0 && status == 'ok';
      return FirewallReloadResult(
        succeeded: ok,
        unconfirmed: status == 'pending',
        branch: branch,
        stage: stage,
        systemDnsFlushed: dnsFlushed,
        capabilityConfirmed: true,
        message: ok
            ? '已修复并验证规则生效'
            : (status == 'pending' ? '停止请求已记录，当前操作尚未结束' : '修复失败 ($stage)'),
      );
    }
    final ok = exitCode == 0;
    return FirewallReloadResult(
      succeeded: ok,
      unconfirmed: false,
      branch: 'legacy_unconfirmed',
      stage: ok ? 'completed' : 'failed',
      systemDnsFlushed: false,
      capabilityConfirmed: false,
      message: ok ? '操作已执行' : '操作失败',
    );
  }
}

/// 结构化运行模式切换结果
class ModeSwitchResult {
  final bool succeeded;
  final bool unconfirmed;
  final String stage;
  final String mode;
  final String targetMode;
  final String message;
  final String? opId;
  final int? httpPort;
  final int? dnsPort;
  /// 模块脚本自身从启动到返回的总耗时（与管理器侧计时分开）
  final int? totalMs;
  /// 管理器队列等待耗时（Stopwatch 测量）
  final int? managerQueueWaitMs;
  /// 管理器等待 su/switch_mode.sh 返回耗时（Stopwatch 测量）
  final int? managerScriptWaitMs;

  int? get scriptTotalMs => totalMs;

  const ModeSwitchResult({
    required this.succeeded,
    this.unconfirmed = false,
    this.stage = 'unknown',
    this.mode = 'overseas',
    String? targetMode,
    this.message = '',
    this.opId,
    this.httpPort,
    this.dnsPort,
    this.totalMs,
    this.managerQueueWaitMs,
    this.managerScriptWaitMs,
  }) : targetMode = targetMode ?? mode;

  factory ModeSwitchResult.fromScriptOutput({
    required int exitCode,
    required String stdoutText,
    required String targetMode,
    String? fallbackOpId,
    int? managerQueueWaitMs,
    int? managerScriptWaitMs,
  }) {
    for (final rawLine in stdoutText.split('\n').reversed) {
      final line = rawLine.trim();
      if (!line.startsWith('AGH_SWITCH_RESULT ')) continue;
      final fields = <String, String>{};
      for (final token in line.substring('AGH_SWITCH_RESULT '.length).split(' ')) {
        final eq = token.indexOf('=');
        if (eq > 0) {
          fields[token.substring(0, eq).trim()] = token.substring(eq + 1).trim();
        }
      }
      final status = fields['status'] ?? '';
      final stage = fields['stage'] ?? 'unknown';
      final mode = fields['mode'] ?? targetMode;
      final ok = exitCode == 0 && status == 'ok';
      return ModeSwitchResult(
        succeeded: ok,
        unconfirmed: false,
        stage: stage,
        mode: mode,
        targetMode: targetMode,
        message: ok ? '已成功切换模式' : '模式切换失败 ($stage)',
        opId: fields['op_id'] ?? fallbackOpId,
        httpPort: int.tryParse(fields['http_port'] ?? ''),
        dnsPort: int.tryParse(fields['dns_port'] ?? ''),
        totalMs: int.tryParse(fields['total_ms'] ?? ''),
        managerQueueWaitMs: managerQueueWaitMs,
        managerScriptWaitMs: managerScriptWaitMs,
      );
    }
    final ok = exitCode == 0;
    return ModeSwitchResult(
      succeeded: ok,
      unconfirmed: false,
      stage: ok ? 'completed' : 'failed',
      mode: targetMode,
      targetMode: targetMode,
      message: ok ? '已成功切换模式' : '模式切换失败',
      opId: fallbackOpId,
      managerQueueWaitMs: managerQueueWaitMs,
      managerScriptWaitMs: managerScriptWaitMs,
    );
  }
}

class ModuleOperationRecord {
  /// 模块最近操作记录（内存环形缓冲，最多 20 条，不含 URL/密码/规则原文）
  final DateTime timestamp;
  final String type;
  final String opId;
  final String target;
  final String stage;
  final int exitCode;
  final bool succeeded;
  final bool unconfirmed;
  final int? elapsedMs;

  const ModuleOperationRecord({
    required this.timestamp,
    required this.type,
    required this.opId,
    required this.target,
    required this.stage,
    required this.exitCode,
    required this.succeeded,
    this.unconfirmed = false,
    this.elapsedMs,
  });

  String toSummaryLine() {
    final ts = timestamp.toUtc().toIso8601String();
    final msPart = elapsedMs != null ? ' elapsed=${elapsedMs}ms' : '';
    final uncPart = unconfirmed ? ' unconfirmed=1' : '';
    return '$ts type=$type op_id=$opId target=$target stage=$stage exit=$exitCode ok=$succeeded$uncPart$msPart';
  }
}

/// 详细调试日志开关配置（独立存储于 /data/adb/agh/diag.conf，默认关闭）
class DebugLogConfig {
  static const int defaultDurationMinutes = 30;
  static const List<int> selectableDurationsMinutes = <int>[15, 30, 60, 180];

  final bool enabled;
  final int expireEpochSeconds;
  final bool readable;

  const DebugLogConfig({
    this.enabled = false,
    this.expireEpochSeconds = 0,
    this.readable = true,
  });

  bool isActiveAt(DateTime now) {
    if (!enabled || expireEpochSeconds <= 0) return false;
    final nowSec = now.millisecondsSinceEpoch ~/ 1000;
    return nowSec > 0 && nowSec < expireEpochSeconds;
  }

  bool get isActive => isActiveAt(DateTime.now());

  int remainingMinutesAt(DateTime now) {
    if (!isActiveAt(now)) return 0;
    final nowSec = now.millisecondsSinceEpoch ~/ 1000;
    return ((expireEpochSeconds - nowSec + 59) ~/ 60).clamp(1, 9999);
  }
}

class _ModeSwitchQueueEntry {
  final String targetMode;
  final Stopwatch enqueuedAt;
  final Future<ModeSwitchResult> Function(int queueWaitMs) executor;
  final Completer<ModeSwitchResult> completer = Completer<ModeSwitchResult>();
  bool started = false;

  _ModeSwitchQueueEntry({
    required this.targetMode,
    required this.enqueuedAt,
    required this.executor,
  });
}

/// 规则搜索单飞与最新待执行队列协调器：
/// - 保证同一时间最多只有 1 个底层规则扫描在执行 (`searchInFlight`)
/// - 扫描期间到达的新请求仅覆盖 `latestPendingRequest`，不并发派生 `su grep`
/// - 按递增 `requestGeneration` 校验回填结果，彻底杜绝 `A -> B -> A` 时旧的 `A` 覆盖新的 `A`
class RuleSearchCoordinator {
  final Future<List<Map<String, String>>> Function(String keyword) _executor;
  final Duration taskTimeout;
  final void Function(
    int generation,
    String keyword,
    List<Map<String, String>> matches,
    bool stillSearching,
  )? onResult;

  bool searchInFlight = false;
  ({String keyword, int generation})? latestPendingRequest;
  int requestGeneration = 0;
  bool _disposed = false;

  RuleSearchCoordinator({
    required Future<List<Map<String, String>>> Function(String keyword) executor,
    this.taskTimeout = const Duration(seconds: 8),
    this.onResult,
  }) : _executor = executor;

  bool get isDisposed => _disposed;

  /// 当输入清空或少于最小长度时调用：清空待执行队列并递增代数，使在途旧结果全部失效
  int invalidatePending() {
    latestPendingRequest = null;
    return ++requestGeneration;
  }

  /// 提交一次防抖后的规则检索请求
  Future<void> submitSearch(String keyword) async {
    if (_disposed) return;
    final gen = ++requestGeneration;
    final req = (keyword: keyword, generation: gen);
    if (searchInFlight) {
      latestPendingRequest = req;
      return;
    }
    await _drainQueue(req);
  }

  Future<void> _drainQueue(({String keyword, int generation}) initialReq) async {
    searchInFlight = true;
    var current = initialReq;
    try {
      while (!_disposed) {
        List<Map<String, String>> matches = const [];
        try {
          matches = await _executor(current.keyword).timeout(
            taskTimeout,
            onTimeout: () => <Map<String, String>>[],
          );
        } catch (_) {
          matches = const [];
        }
        if (_disposed) break;

        final pending = latestPendingRequest;
        if (pending != null) {
          latestPendingRequest = null;
          current = pending;
          continue;
        }

        if (current.generation == requestGeneration) {
          onResult?.call(current.generation, current.keyword, matches, false);
        }
        break;
      }
    } finally {
      searchInFlight = false;
    }
  }

  void dispose() {
    _disposed = true;
    latestPendingRequest = null;
    requestGeneration++;
  }
}

class ModuleConfigService {
  static const String moduleConfigPath = '/data/adb/agh/scripts/config.prop';
  static const String moduleYamlPath = '/data/adb/agh/bin/AdGuardHome.yaml';
  static const String diagConfigPath = '/data/adb/agh/diag.conf';
  static const String diagLogHelperPath = '/data/adb/agh/scripts/diag_log.sh';
  static const MethodChannel _installedAppsChannel =
      MethodChannel('com.wu.adgogogo/installed_apps');

  static const List<String> _suCandidates = <String>[
    'su',
    '/sbin/su',
    '/system/bin/su',
    '/system/xbin/su',
    '/debug_ramdisk/su',
  ];

  static Map<String, dynamic>? _cachedDiag;
  static DateTime? _cachedDiagTime;
  static String? _cachedProxyUrl;
  static DateTime? _cachedProxyUrlTime;
  static List<Map<String, dynamic>>? _cachedApps;
  static DateTime? _cachedAppsTime;
  static String? _cachedSuBin;
  static Future<String?>? _inFlightSuProbe;
  static Future<FirewallReloadResult>? _inFlightRepairOp;
  static final List<_ModeSwitchQueueEntry> _modeSwitchQueue =
      <_ModeSwitchQueueEntry>[];
  static bool _drainingModeSwitchQueue = false;
  static final List<ModuleOperationRecord> _operationHistory =
      <ModuleOperationRecord>[];
  static const int _maxOperationHistory = 20;

  static List<ModuleOperationRecord> get recentOperations =>
      List<ModuleOperationRecord>.unmodifiable(_operationHistory);

  static void recordOperation(ModuleOperationRecord record) {
    _operationHistory.add(record);
    if (_operationHistory.length > _maxOperationHistory) {
      _operationHistory.removeRange(
        0,
        _operationHistory.length - _maxOperationHistory,
      );
    }
  }

  final SuProcessRunner _processRunner;
  final SuProcessStarter? _processStarter;
  final SuProbeCandidateRunner? _probeCandidateRunner;
  final Duration _suProbeTimeout;
  final Duration _mutationWaitTimeout;
  final Duration _mutationSuTimeout;
  final bool? _isAndroidOverride;

  ModuleConfigService({
    SuProcessRunner? processRunner,
    SuProcessStarter? processStarter,
    SuProbeCandidateRunner? probeCandidateRunner,
    Duration suProbeTimeout = const Duration(seconds: 3),
    Duration mutationWaitTimeout = const Duration(seconds: 25),
    Duration mutationSuTimeout = const Duration(seconds: 25),
    bool? isAndroidOverride,
  })  : _processRunner = processRunner ?? Process.run,
        _processStarter = processStarter,
        _probeCandidateRunner = probeCandidateRunner,
        _suProbeTimeout = suProbeTimeout,
        _mutationWaitTimeout = mutationWaitTimeout,
        _mutationSuTimeout = mutationSuTimeout,
        _isAndroidOverride = isAndroidOverride;

  bool get _isAndroid => _isAndroidOverride ?? Platform.isAndroid;

  @visibleForTesting
  static void resetTestState() {
    _cachedDiag = null;
    _cachedDiagTime = null;
    _cachedProxyUrl = null;
    _cachedProxyUrlTime = null;
    _cachedApps = null;
    _cachedAppsTime = null;
    _cachedSuBin = null;
    _inFlightSuProbe = null;
    _inFlightRepairOp = null;
    _modeSwitchQueue.clear();
    _drainingModeSwitchQueue = false;
    _operationHistory.clear();
  }

  static const String _pathPrefix =
      'export PATH="/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:\$PATH"; ';

  /// 使用受控子进程捕获 stdout/stderr 并在超时后按 SIGTERM -> SIGKILL 终止且释放流订阅
  static Future<
      ({
        int pid,
        int exitCode,
        String stdout,
        String stderr,
        bool timedOut,
        bool exitConfirmed,
        bool truncated,
      })> _executeProcessBounded(
    Process process, {
    required Duration timeout,
    required int maxOutputBytes,
    int maxErrBytes = 8192,
  }) async {
    final outBuf = StringBuffer();
    final errBuf = StringBuffer();
    var truncated = false;

    final outDone = Completer<void>();
    final errDone = Completer<void>();

    late final StreamSubscription<String> outSub;
    late final StreamSubscription<String> errSub;

    outSub = process.stdout
        .transform(const Utf8Decoder(allowMalformed: true))
        .listen(
          (chunk) {
            if (outBuf.length < maxOutputBytes) {
              final remain = maxOutputBytes - outBuf.length;
              outBuf.write(
                chunk.length <= remain ? chunk : chunk.substring(0, remain),
              );
            } else {
              truncated = true;
            }
          },
          onError: (_) {
            if (!outDone.isCompleted) outDone.complete();
          },
          onDone: () {
            if (!outDone.isCompleted) outDone.complete();
          },
          cancelOnError: true,
        );

    errSub = process.stderr
        .transform(const Utf8Decoder(allowMalformed: true))
        .listen(
          (chunk) {
            if (errBuf.length < maxErrBytes) {
              final remain = maxErrBytes - errBuf.length;
              errBuf.write(
                chunk.length <= remain ? chunk : chunk.substring(0, remain),
              );
            }
          },
          onError: (_) {
            if (!errDone.isCompleted) errDone.complete();
          },
          onDone: () {
            if (!errDone.isCompleted) errDone.complete();
          },
          cancelOnError: true,
        );

    var exitCode = 1;
    var timedOut = false;
    var exitConfirmed = false;

    try {
      try {
        exitCode = await process.exitCode.timeout(timeout);
        exitConfirmed = true;
      } on TimeoutException {
        timedOut = true;
        exitCode = 124;
        try {
          process.kill(ProcessSignal.sigterm);
        } catch (_) {}
        try {
          await process.exitCode.timeout(const Duration(milliseconds: 200));
          exitConfirmed = true;
        } on TimeoutException {
          try {
            process.kill(ProcessSignal.sigkill);
          } catch (_) {}
          try {
            await process.exitCode.timeout(const Duration(milliseconds: 500));
            exitConfirmed = true;
          } on TimeoutException {
            exitConfirmed = false;
          } catch (_) {
            exitConfirmed = false;
          }
        } catch (_) {
          exitConfirmed = false;
        }
      } catch (_) {
        exitCode = 1;
      }

      final drainWait = timedOut
          ? const Duration(milliseconds: 150)
          : const Duration(milliseconds: 200);
      await Future.wait([outDone.future, errDone.future]).timeout(
        drainWait,
        onTimeout: () => const <void>[],
      );
    } finally {
      await Future.wait([
        Future.sync(() => outSub.cancel())
            .timeout(const Duration(milliseconds: 100), onTimeout: () {}),
        Future.sync(() => errSub.cancel())
            .timeout(const Duration(milliseconds: 100), onTimeout: () {}),
      ]);
      if (!outDone.isCompleted) outDone.complete();
      if (!errDone.isCompleted) errDone.complete();
    }

    return (
      pid: process.pid,
      exitCode: exitCode,
      stdout: outBuf.toString(),
      stderr: errBuf.toString(),
      timedOut: timedOut,
      exitConfirmed: exitConfirmed,
      truncated: truncated,
    );
  }

  /// 使用可控 Process.start 执行只读 su 探测，并发消费 stdout/stderr 并在超时后终止且回收子进程
  static Future<ProcessResult?> defaultSuProbeCandidate(
    String su,
    Duration timeout,
  ) async {
    Process? process;
    try {
      process = await Process.start(su, const ['-c', 'id -u']);
    } catch (_) {
      return null;
    }

    final res = await _executeProcessBounded(
      process,
      timeout: timeout,
      maxOutputBytes: 256,
      maxErrBytes: 512,
    );
    if (res.timedOut) {
      return null;
    }
    return ProcessResult(res.pid, res.exitCode, res.stdout, '');
  }

  Future<ProcessResult?> _runSingleSuProbe(String su) async {
    final probeRunner = _probeCandidateRunner;
    if (probeRunner != null) {
      return probeRunner(su, _suProbeTimeout);
    }
    if (!identical(_processRunner, Process.run)) {
      try {
        return await _processRunner(su, const ['-c', 'id -u'])
            .timeout(_suProbeTimeout);
      } on TimeoutException {
        return null;
      } catch (_) {
        return null;
      }
    }
    return defaultSuProbeCandidate(su, _suProbeTimeout);
  }

  Future<String?> _resolveSuBin({
    bool forceRefresh = false,
    String? excludeSu,
  }) async {
    if (!forceRefresh &&
        _cachedSuBin != null &&
        _cachedSuBin != excludeSu) {
      return _cachedSuBin;
    }

    // 无论是否 forceRefresh，只要已有在途探测任务则先复用等待，绝不并发启动多个 su 探测
    while (_inFlightSuProbe != null) {
      final existing = _inFlightSuProbe;
      if (existing == null) break;
      final existingResult = await existing;
      if (!forceRefresh &&
          existingResult != null &&
          existingResult != excludeSu) {
        return existingResult;
      }
      if (forceRefresh &&
          existingResult != null &&
          existingResult != excludeSu &&
          _cachedSuBin == existingResult) {
        return existingResult;
      }
      if (identical(_inFlightSuProbe, existing)) {
        break;
      }
    }

    if (forceRefresh) {
      _cachedSuBin = null;
    }

    final probeFuture = _probeSuBin(excludeSu: excludeSu);
    _inFlightSuProbe = probeFuture;
    try {
      return await probeFuture;
    } finally {
      if (identical(_inFlightSuProbe, probeFuture)) {
        _inFlightSuProbe = null;
      }
    }
  }

  Future<String?> _probeSuBin({String? excludeSu}) async {
    final first = _cachedSuBin;
    final ordered = first != null
        ? <String>[first, ..._suCandidates.where((e) => e != first)]
        : _suCandidates;
    for (final su in ordered) {
      if (excludeSu != null && su == excludeSu) continue;
      try {
        final probe = await _runSingleSuProbe(su);
        if (probe != null &&
            probe.exitCode == 0 &&
            probe.stdout.toString().trim().split('\n').first.trim() == '0') {
          _cachedSuBin = su;
          return su;
        }
      } catch (_) {
        // Candidate binary unavailable; try next candidate
      }
    }
    _cachedSuBin = null;
    return null;
  }

  Future<ProcessResult> _runSu(
    String command, {
    Duration timeout = const Duration(seconds: 8),
    int maxOutputBytes = 393216,
  }) async {
    var su = await _resolveSuBin();
    if (su == null) {
      return ProcessResult(0, 1, '', 'su unavailable');
    }
    final args = <String>['-c', '$_pathPrefix$command'];

    final starter = _processStarter;
    if (starter == null && !identical(_processRunner, Process.run)) {
      try {
        return await _processRunner(su, args).timeout(timeout);
      } on TimeoutException {
        return ProcessResult(0, 124, '', 'command_timeout');
      } catch (_) {
        final failedSu = su;
        _cachedSuBin = null;
        su = await _resolveSuBin(forceRefresh: true, excludeSu: failedSu);
        if (su == null) {
          return ProcessResult(0, 1, '', 'su unavailable');
        }
        try {
          return await _processRunner(su, args).timeout(timeout);
        } on TimeoutException {
          return ProcessResult(0, 124, '', 'command_timeout');
        } catch (e) {
          return ProcessResult(0, 1, '', e.toString());
        }
      }
    }

    Process process;
    try {
      process = await (starter ?? Process.start)(su, args);
    } catch (_) {
      final failedSu = su;
      _cachedSuBin = null;
      su = await _resolveSuBin(forceRefresh: true, excludeSu: failedSu);
      if (su == null) {
        return ProcessResult(0, 1, '', 'su unavailable');
      }
      try {
        process = await (starter ?? Process.start)(su, args);
      } catch (e) {
        return ProcessResult(0, 1, '', e.toString());
      }
    }

    final res = await _executeProcessBounded(
      process,
      timeout: timeout,
      maxOutputBytes: maxOutputBytes,
    );
    final capturedOut = res.truncated && res.stdout.isNotEmpty
        ? '${res.stdout}\n[...truncated...]'
        : res.stdout;

    if (res.timedOut) {
      final errTag = res.exitConfirmed
          ? 'command_timeout'
          : 'command_timeout;unconfirmed_exit';
      return ProcessResult(res.pid, 124, capturedOut, errTag);
    }
    return ProcessResult(res.pid, res.exitCode, capturedOut, res.stderr);
  }

  Future<bool> hasRoot() async {
    if (!_isAndroid) return false;
    try {
      final su = await _resolveSuBin();
      return su != null;
    } catch (_) {
      return false;
    }
  }

  /// 带严格超时的只读诊断 Root 执行器（超时后主动 SIGTERM/SIGKILL 子进程、有界确认退出并释放流订阅）
  Future<ProcessResult> runSuTimed(
    String command, {
    Duration timeout = const Duration(seconds: 4),
    int maxOutputBytes = 393216,
  }) async {
    if (!_isAndroid) {
      return ProcessResult(0, 1, '', 'not_android');
    }
    final su = await _resolveSuBin();
    if (su == null) {
      return ProcessResult(0, 127, '', 'su_unavailable');
    }
    final args = <String>['-c', '$_pathPrefix$command'];
    final starter = _processStarter;
    if (starter == null && !identical(_processRunner, Process.run)) {
      try {
        return await _processRunner(su, args).timeout(timeout);
      } on TimeoutException {
        return ProcessResult(0, 124, '', 'command_timeout');
      } catch (e) {
        return ProcessResult(0, 1, '', e.toString());
      }
    }

    Process? process;
    try {
      process = await (starter ?? Process.start)(su, args);
    } catch (e) {
      return ProcessResult(0, 1, '', e.toString());
    }

    final res = await _executeProcessBounded(
      process,
      timeout: timeout,
      maxOutputBytes: maxOutputBytes,
    );
    final capturedOut = res.truncated && res.stdout.isNotEmpty
        ? '${res.stdout}\n[...truncated...]'
        : res.stdout;

    if (res.timedOut) {
      final errTag = res.exitConfirmed
          ? 'command_timeout'
          : 'command_timeout;unconfirmed_exit';
      return ProcessResult(res.pid, 124, capturedOut, errTag);
    }
    return ProcessResult(res.pid, res.exitCode, capturedOut, res.stderr);
  }

  /// 读取独立详细调试日志开关（严格逐行键值解析，未设置或解析/时间异常按关闭返回）
  Future<DebugLogConfig> readDebugLogConfig() async {
    if (!_isAndroid) {
      return const DebugLogConfig(enabled: false, expireEpochSeconds: 0, readable: false);
    }
    try {
      final result = await runSuTimed(
        'if [ -f $diagConfigPath ]; then cat $diagConfigPath 2>/dev/null; else echo "__MISSING__"; fi',
        timeout: const Duration(seconds: 3),
      );
      if (result.exitCode != 0) {
        return const DebugLogConfig(enabled: false, expireEpochSeconds: 0, readable: false);
      }
      final raw = result.stdout.toString();
      if (raw.trim() == '__MISSING__' || raw.trim().isEmpty) {
        return const DebugLogConfig(enabled: false, expireEpochSeconds: 0, readable: true);
      }
      var enabled = false;
      var expireEpoch = 0;
      var invalid = false;
      for (final rawLine in raw.split('\n')) {
        final line = rawLine.trim();
        if (line.isEmpty || line.startsWith('#')) continue;
        final eq = line.indexOf('=');
        if (eq <= 0) continue;
        final key = line.substring(0, eq).trim();
        final val = line.substring(eq + 1).trim();
        if (key == 'debug_enabled') {
          if (val == '1') {
            enabled = true;
          } else if (val == '0') {
            enabled = false;
          } else {
            invalid = true;
          }
        } else if (key == 'debug_expire_epoch') {
          if (!RegExp(r'^[0-9]+$').hasMatch(val)) {
            invalid = true;
          } else {
            expireEpoch = int.tryParse(val) ?? 0;
          }
        }
      }
      if (invalid) {
        return const DebugLogConfig(enabled: false, expireEpochSeconds: 0, readable: true);
      }
      final cfg = DebugLogConfig(
        enabled: enabled,
        expireEpochSeconds: expireEpoch,
        readable: true,
      );
      if (!cfg.isActive) {
        return DebugLogConfig(
          enabled: false,
          expireEpochSeconds: expireEpoch,
          readable: true,
        );
      }
      return cfg;
    } catch (_) {
      return const DebugLogConfig(enabled: false, expireEpochSeconds: 0, readable: false);
    }
  }

  /// 保存详细调试日志开关（原子写 diag.conf，不重启核心、不重挂防火墙）
  Future<DebugLogConfig?> setDebugLogConfig({
    required bool enabled,
    int durationMinutes = DebugLogConfig.defaultDurationMinutes,
  }) async {
    if (!_isAndroid) return null;
    final safeMinutes = durationMinutes.clamp(1, 1440);
    final expireEpoch = enabled
        ? (DateTime.now().millisecondsSinceEpoch ~/ 1000) + safeMinutes * 60
        : 0;
    final enVal = enabled ? 1 : 0;
    try {
      final result = await runSuTimed(
        'if [ -f $diagLogHelperPath ]; then '
        '  . $diagLogHelperPath && agh_diag_write_conf $enVal $expireEpoch; '
        'else '
        '  mkdir -p /data/adb/agh 2>/dev/null && '
        '  t="$diagConfigPath.tmp.\$\$" && '
        '  printf "debug_enabled=%s\\ndebug_expire_epoch=%s\\n" "$enVal" "$expireEpoch" > "\$t" && '
        '  chmod 0600 "\$t" 2>/dev/null && mv -f "\$t" $diagConfigPath && chmod 0600 $diagConfigPath 2>/dev/null; '
        'fi',
        timeout: const Duration(seconds: 3),
      );
      recordOperation(ModuleOperationRecord(
        timestamp: DateTime.now(),
        type: 'debug_log_toggle',
        opId: 'dbg_${DateTime.now().millisecondsSinceEpoch}',
        target: enabled ? '${safeMinutes}m' : 'off',
        stage: result.exitCode == 0 ? 'saved' : 'failed',
        exitCode: result.exitCode,
        succeeded: result.exitCode == 0,
      ));
      if (result.exitCode != 0) return null;
      return DebugLogConfig(
        enabled: enabled,
        expireEpochSeconds: expireEpoch,
        readable: true,
      );
    } catch (_) {
      return null;
    }
  }

  Future<String?> readAdGuardYaml() async {
    if (!_isAndroid) return null;
    try {
      final result = await _runSu('cat $moduleYamlPath');
      if (result.exitCode != 0) {
        return null;
      }
      return result.stdout.toString();
    } catch (_) {
      return null;
    }
  }

  String? parseHttpAddress(String yamlText) {
    final lines = yamlText.split('\n');
    var inHttp = false;
    for (final rawLine in lines) {
      final line = rawLine.trimRight();
      final trimmed = line.trimLeft();
      if (trimmed.startsWith('http:')) {
        inHttp = true;
        continue;
      }
      if (inHttp) {
        if (trimmed.isNotEmpty && !line.startsWith(' ')) {
          inHttp = false;
        }
        if (trimmed.startsWith('address:')) {
          final value = trimmed.substring('address:'.length).trim();
          return value.replaceAll('"', '').replaceAll("'", '');
        }
      }
    }
    return null;
  }

  Future<String?> readHttpAddress() async {
    final yaml = await readAdGuardYaml();
    if (yaml == null) return null;
    return parseHttpAddress(yaml);
  }

  Future<String> readProxyUrl({bool forceRefresh = false}) async {
    if (!_isAndroid) return '';
    if (!forceRefresh &&
        _cachedProxyUrl != null &&
        _cachedProxyUrlTime != null &&
        DateTime.now().difference(_cachedProxyUrlTime!) <
            const Duration(seconds: 30)) {
      return _cachedProxyUrl!;
    }
    try {
      final result = await _runSu('cat $moduleConfigPath');
      if (result.exitCode != 0) {
        return '';
      }
      final content = result.stdout.toString();
      final line = content.split('\n').firstWhere(
            (line) => line.trimLeft().startsWith('PROXY_URL='),
            orElse: () => '',
          );
      if (line.isEmpty) {
        _cachedProxyUrl = '';
        _cachedProxyUrlTime = DateTime.now();
        return '';
      }
      final parsed = line
          .substring(line.indexOf('PROXY_URL=') + 'PROXY_URL='.length)
          .replaceAll('"', '')
          .replaceAll("'", '')
          .trim();
      _cachedProxyUrl = parsed;
      _cachedProxyUrlTime = DateTime.now();
      return parsed;
    } catch (_) {
      return '';
    }
  }

  Future<bool> saveProxyUrl(String proxyUrl) async {
    if (!_isAndroid) return false;
    try {
      final readResult = await _runSu('cat $moduleConfigPath');
      if (readResult.exitCode != 0) return false;

      final value = proxyUrl.trim();
      final lines = readResult.stdout.toString().split('\n');
      final updatedLines = <String>[];
      var replaced = false;

      for (final line in lines) {
        if (line.trimLeft().startsWith('PROXY_URL=')) {
          replaced = true;
          updatedLines
              .add(value.isNotEmpty ? 'PROXY_URL="$value"' : 'PROXY_URL=" "');
          continue;
        }
        updatedLines.add(line);
      }
      if (!replaced) {
        updatedLines
            .add(value.isNotEmpty ? 'PROXY_URL="$value"' : 'PROXY_URL=" "');
      }
      final content = updatedLines.join('\n');
      final escaped = content.replaceAll("'", "'\\''");

      final writeResult = await _runSu(
        "printf '%s' '$escaped' > $moduleConfigPath && "
        "{ sh /data/adb/agh/scripts/ProxyConfig.sh --once >/dev/null 2>&1 & }",
      );
      if (writeResult.exitCode == 0) {
        _cachedProxyUrl = value;
        _cachedProxyUrlTime = DateTime.now();
        return true;
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  Future<Map<String, dynamic>> getModuleDiagnostics({
    bool forceRefresh = false,
  }) async {
    if (!_isAndroid) {
      return {
        'running': false,
        'pid': '',
        'dnsPort': '',
        'natOk': false,
        'sniEnabled': true,
        'sniOk': false,
        'vpnMode': 'off',
        'rssMb': '',
        'allowlistCount': 0,
        'runMode': 'overseas',
      };
    }
    if (!forceRefresh &&
        _cachedDiag != null &&
        _cachedDiagTime != null &&
        DateTime.now().difference(_cachedDiagTime!) <
            const Duration(seconds: 30)) {
      return Map<String, dynamic>.from(_cachedDiag!);
    }
    try {
      const cmd = '''
pid=\$(pidof AdGuardHome 2>/dev/null | awk '{print \$1}')
if [ -z "\$pid" ] && [ -f /data/adb/agh/bin/AdGuardHome.pid ]; then
  cand=\$(cat /data/adb/agh/bin/AdGuardHome.pid 2>/dev/null)
  if [ -n "\$cand" ] && kill -0 "\$cand" 2>/dev/null && [ "\$(cat "/proc/\$cand/comm" 2>/dev/null)" = "AdGuardHome" ]; then
    pid="\$cand"
  fi
fi
dns_port=\$(sed -n 's/^redir_port=//p' /data/adb/agh/scripts/config.prop 2>/dev/null | head -n 1)
run_mode=\$(sed -n 's/^RUN_MODE=//p' /data/adb/agh/scripts/config.prop 2>/dev/null | head -n 1)
enable_sni=\$(sed -n 's/^ENABLE_SNI=//p' /data/adb/agh/scripts/config.prop 2>/dev/null | tr -d '[:space:]' | head -n 1)
[ -z "\$enable_sni" ] && enable_sni=1
iptables -w 2 -t nat -C OUTPUT -j ADGUARD >/dev/null 2>&1 && nat_ok=1 || nat_ok=0
if [ "\$enable_sni" = "1" ]; then
  if iptables -w 2 -t mangle -C OUTPUT -j AGH_SNI >/dev/null 2>&1 &&
     iptables -w 2 -t mangle -S AGH_SNI 2>/dev/null | grep -q -- "-j NFQUEUE"; then
    sni_ok=1
  else
    sni_ok=0
  fi
else
  sni_ok=1
fi
vpn_mode=\$(cat /data/adb/agh/vpn_mode_status 2>/dev/null | head -n 1)
rss_kb=""
[ -n "\$pid" ] && rss_kb=\$(awk '/^VmRSS:/ {print \$2}' "/proc/\$pid/status" 2>/dev/null)
allow_cnt=0
[ -s /data/adb/agh/app-allow.txt ] && allow_cnt=\$(grep -cvE '^[[:space:]]*(#|\$)' /data/adb/agh/app-allow.txt 2>/dev/null || echo 0)
echo "PID=\$pid"
echo "PORT=\$dns_port"
echo "MODE=\$run_mode"
echo "NAT=\$nat_ok"
echo "SNI_EN=\$enable_sni"
echo "SNI=\$sni_ok"
echo "VPN=\$vpn_mode"
echo "RSS=\$rss_kb"
echo "ALLOW=\$allow_cnt"
''';
      final result = await _runSu(cmd);
      if (result.exitCode != 0) {
        return {
          'running': false,
          'pid': '',
          'dnsPort': '',
          'natOk': false,
          'sniEnabled': true,
          'sniOk': false,
          'vpnMode': 'off',
          'rssMb': '',
          'allowlistCount': 0,
          'runMode': 'overseas',
        };
      }
      String pid = '';
      String dnsPort = '';
      String runMode = 'overseas';
      bool natOk = false;
      bool sniEnabled = true;
      bool sniOk = false;
      String vpnMode = 'off';
      String rssKb = '';
      int allowlistCount = 0;
      for (final line in result.stdout.toString().split('\n')) {
        final t = line.trim();
        if (t.startsWith('PID=')) pid = t.substring(4).trim();
        if (t.startsWith('PORT=')) dnsPort = t.substring(5).trim();
        if (t.startsWith('MODE=')) {
          final m = t.substring(5).trim().toLowerCase();
          runMode = (m == 'cn') ? 'cn' : 'overseas';
        }
        if (t.startsWith('NAT=')) natOk = t.substring(4).trim() == '1';
        if (t.startsWith('SNI_EN=')) {
          sniEnabled = t.substring(7).trim() != '0';
        }
        if (t.startsWith('SNI=')) sniOk = t.substring(4).trim() == '1';
        if (t.startsWith('VPN=')) vpnMode = t.substring(4).trim();
        if (t.startsWith('RSS=')) rssKb = t.substring(4).trim();
        if (t.startsWith('ALLOW=')) {
          allowlistCount = int.tryParse(t.substring(6).trim()) ?? 0;
        }
      }
      String rssMb = '';
      final kb = int.tryParse(rssKb);
      if (kb != null && kb > 0) {
        rssMb = '${(kb / 1024).toStringAsFixed(1)} MB';
      }
      final running = pid.isNotEmpty;
      final diag = {
        'running': running,
        'pid': pid,
        'dnsPort': dnsPort,
        'natOk': running && natOk,
        'sniEnabled': sniEnabled,
        'sniOk': !sniEnabled || (running && sniOk),
        'vpnMode': vpnMode.isEmpty ? 'off' : vpnMode,
        'rssMb': rssMb,
        'allowlistCount': allowlistCount,
        'runMode': runMode,
      };
      _cachedDiag = diag;
      _cachedDiagTime = DateTime.now();
      return Map<String, dynamic>.from(diag);
    } catch (_) {
      return {
        'running': false,
        'pid': '',
        'dnsPort': '',
        'natOk': false,
        'sniEnabled': true,
        'sniOk': false,
        'vpnMode': 'off',
        'rssMb': '',
        'allowlistCount': 0,
        'runMode': 'overseas',
      };
    }
  }

  Future<String> readRunMode() async {
    if (!_isAndroid) return 'overseas';
    try {
      final result = await _runSu(
        "sed -n 's/^RUN_MODE=//p' /data/adb/agh/scripts/config.prop 2>/dev/null | head -n 1",
      );
      if (result.exitCode != 0) return 'overseas';
      final mode = result.stdout.toString().trim().toLowerCase();
      return mode == 'cn' ? 'cn' : 'overseas';
    } catch (_) {
      return 'overseas';
    }
  }

  /// 结构化模式切换：
  /// - 相同目标的并发切换可共享同一个任务 Future
  /// - 不同目标不得共享同一个操作结果，按请求顺序排队串行执行，确保最终完成的模式与最后一个有效用户请求一致
  /// - 若等待超时则标记为 unconfirmed，且在底层进程真正结束前不释放互斥、不并发启动下一项修改
  Future<ModeSwitchResult> switchRunModeDetailed(String targetMode) async {
    final normalized =
        targetMode.trim().toLowerCase() == 'cn' ? 'cn' : 'overseas';
    if (!_isAndroid) {
      return ModeSwitchResult(
        succeeded: false,
        stage: 'not_android',
        mode: normalized,
        targetMode: normalized,
        message: '当前非 Android 环境',
      );
    }

    _ModeSwitchQueueEntry entry;
    if (_modeSwitchQueue.isNotEmpty &&
        _modeSwitchQueue.last.targetMode == normalized) {
      entry = _modeSwitchQueue.last;
    } else {
      final opId = 'mgr_${DateTime.now().millisecondsSinceEpoch}';
      final enqueuedAt = Stopwatch()..start();
      entry = _ModeSwitchQueueEntry(
        targetMode: normalized,
        enqueuedAt: enqueuedAt,
        executor: (queueWaitMs) => _performSwitchRunMode(
          normalized,
          opId: opId,
          queueWaitMs: queueWaitMs,
        ),
      );
      _modeSwitchQueue.add(entry);
      if (!_drainingModeSwitchQueue) {
        unawaited(_drainModeSwitchQueue());
      }
    }

    try {
      return await entry.completer.future.timeout(_mutationWaitTimeout);
    } on TimeoutException {
      _cachedDiag = null;
      _cachedDiagTime = null;
      return ModeSwitchResult(
        succeeded: false,
        unconfirmed: true,
        stage: 'timeout_unconfirmed',
        mode: normalized,
        targetMode: normalized,
        message: '执行结果未确认',
      );
    }
  }

  Future<void> _drainModeSwitchQueue() async {
    if (_drainingModeSwitchQueue) return;
    _drainingModeSwitchQueue = true;
    try {
      while (_modeSwitchQueue.isNotEmpty) {
        final current = _modeSwitchQueue.first;
        current.started = true;
        current.enqueuedAt.stop();
        final queueWaitMs = current.enqueuedAt.elapsedMilliseconds;
        final result = await current.executor(queueWaitMs);
        if (_modeSwitchQueue.isNotEmpty &&
            identical(_modeSwitchQueue.first, current)) {
          _modeSwitchQueue.removeAt(0);
        } else {
          _modeSwitchQueue.remove(current);
        }
        if (!current.completer.isCompleted) {
          current.completer.complete(result);
        }
      }
    } finally {
      _drainingModeSwitchQueue = false;
    }
  }

  Future<bool> switchRunMode(String targetMode) async {
    final res = await switchRunModeDetailed(targetMode);
    return res.succeeded;
  }

  Future<ModeSwitchResult> _performSwitchRunMode(
    String normalized, {
    String? opId,
    int? queueWaitMs,
  }) async {
    final scriptWaitSw = Stopwatch()..start();
    try {
      final envParts = <String>[];
      if (opId != null &&
          opId.isNotEmpty &&
          RegExp(r'^[A-Za-z0-9_.-]+$').hasMatch(opId)) {
        envParts.add('AGH_SWITCH_OP_ID=$opId');
      }
      if (queueWaitMs != null && queueWaitMs >= 0) {
        envParts.add('AGH_QUEUE_WAIT_MS=$queueWaitMs');
      }
      final envPrefix = envParts.isEmpty ? '' : '${envParts.join(' ')} ';
      final result = await _runSu(
        'rm -f /dev/shm/agh_manual_stop /data/adb/agh/run/agh_manual_stop /data/adb/agh/manual_stop /data/adb/agh/stopped /data/adb/agh/app_pause_active 2>/dev/null; '
        '$envPrefix/system/bin/sh /data/adb/agh/scripts/switch_mode.sh $normalized 2>&1',
        timeout: _mutationSuTimeout,
      );
      scriptWaitSw.stop();
      _cachedDiag = null;
      _cachedDiagTime = null;
      final res = ModeSwitchResult.fromScriptOutput(
        exitCode: result.exitCode,
        stdoutText: result.stdout.toString(),
        targetMode: normalized,
        fallbackOpId: opId,
        managerQueueWaitMs: queueWaitMs,
        managerScriptWaitMs: scriptWaitSw.elapsedMilliseconds,
      );
      recordOperation(ModuleOperationRecord(
        timestamp: DateTime.now(),
        type: 'mode_switch',
        opId: res.opId ?? opId ?? 'unknown',
        target: normalized,
        stage: res.stage,
        exitCode: result.exitCode,
        succeeded: res.succeeded,
        elapsedMs: res.managerScriptWaitMs,
      ));
      return res;
    } catch (_) {
      scriptWaitSw.stop();
      recordOperation(ModuleOperationRecord(
        timestamp: DateTime.now(),
        type: 'mode_switch',
        opId: opId ?? 'unknown',
        target: normalized,
        stage: 'exception',
        exitCode: -1,
        succeeded: false,
        elapsedMs: scriptWaitSw.elapsedMilliseconds,
      ));
      return ModeSwitchResult(
        succeeded: false,
        stage: 'exception',
        mode: normalized,
        targetMode: normalized,
        message: '模式切换异常',
        opId: opId,
        managerQueueWaitMs: queueWaitMs,
        managerScriptWaitMs: scriptWaitSw.elapsedMilliseconds,
      );
    }
  }

  /// 按需向模块日志追加管理器侧 Stopwatch 耗时（正常仅在开启详细调试日志时记录；失败/异常仍记录）
  Future<void> recordManagerModeSwitchTimings({
    required String opId,
    int? managerScriptWaitMs,
    int? managerRefreshMs,
    String status = 'ok',
  }) async {
    if (!_isAndroid || opId.isEmpty) return;
    if (!RegExp(r'^[A-Za-z0-9_.-]+$').hasMatch(opId) ||
        !RegExp(r'^[A-Za-z0-9_.-]+$').hasMatch(status)) {
      return;
    }
    final lines = <String>[];
    if (managerScriptWaitMs != null) {
      final safeWait = managerScriptWaitMs < 0 ? 0 : managerScriptWaitMs;
      lines.add(
        'echo "\$(date \'+%F %T\') [TIMING] op_id=$opId stage=manager_script_wait status=$status elapsed_ms=$safeWait"',
      );
    }
    if (managerRefreshMs != null) {
      final safeRef = managerRefreshMs < 0 ? 0 : managerRefreshMs;
      lines.add(
        'echo "\$(date \'+%F %T\') [TIMING] op_id=$opId stage=manager_refresh status=$status elapsed_ms=$safeRef"',
      );
    }
    if (lines.isEmpty) return;
    final gateExpr = status != 'ok'
        ? ''
        : 'if [ ! -f $diagLogHelperPath ]; then exit 0; fi; . $diagLogHelperPath; agh_diag_debug_active || exit 0; ';
    try {
      await _runSu('$gateExpr{ ${lines.join('; ')}; } >> /data/adb/agh/agh.log 2>/dev/null');
    } catch (_) {
      // ignore telemetry write failures
    }
  }

  Future<String> readModuleLogs({int maxLines = 150}) async {
    if (!_isAndroid) return '';
    try {
      final result = await _runSu(
        'tail -n $maxLines /data/adb/agh/agh.log 2>/dev/null',
      );
      if (result.exitCode != 0) return '';
      return result.stdout.toString().trim();
    } catch (_) {
      return '';
    }
  }

  Future<bool> clearModuleLogs() async {
    if (!_isAndroid) return false;
    try {
      final result = await _runSu(
        ': > /data/adb/agh/agh.log 2>/dev/null; rm -f /data/adb/agh/agh.log.1 2>/dev/null',
      );
      return result.exitCode == 0;
    } catch (_) {
      return false;
    }
  }

  /// 结构化防火墙规则修复/重载：
  /// - 返回是否成功、实际执行分支、是否已确认完成系统 DNS 缓存刷新
  /// - 若等待超时则标记为 unconfirmed，且在底层脚本进程真正退出前保持在途互斥，不允许重复触发同类修改
  Future<FirewallReloadResult> reloadFirewallRulesDetailed() async {
    if (!_isAndroid) {
      return const FirewallReloadResult(
        succeeded: false,
        branch: 'not_android',
        stage: 'not_android',
        message: '当前非 Android 环境',
      );
    }
    var activeFuture = _inFlightRepairOp;
    if (activeFuture == null) {
      final started = _performReloadFirewallRules();
      _inFlightRepairOp = started;
      started.whenComplete(() {
        if (identical(_inFlightRepairOp, started)) {
          _inFlightRepairOp = null;
        }
      });
      activeFuture = started;
    }

    try {
      return await activeFuture.timeout(_mutationWaitTimeout);
    } on TimeoutException {
      _cachedDiag = null;
      _cachedDiagTime = null;
      return const FirewallReloadResult(
        succeeded: false,
        unconfirmed: true,
        branch: 'timeout',
        stage: 'timeout_unconfirmed',
        systemDnsFlushed: false,
        capabilityConfirmed: false,
        message: '执行结果未确认',
      );
    }
  }

  Future<bool> reloadFirewallRules() async {
    final res = await reloadFirewallRulesDetailed();
    return res.succeeded;
  }

  Future<FirewallReloadResult> _performReloadFirewallRules() async {
    try {
      final result = await _runSu(
        'rm -f /dev/shm/agh_manual_stop /data/adb/agh/run/agh_manual_stop /data/adb/agh/manual_stop /data/adb/agh/stopped /data/adb/agh/app_pause_active 2>/dev/null; '
        'if [ -f /data/adb/modules/AdGuardHome/service.sh ]; then '
        '  /system/bin/sh /data/adb/modules/AdGuardHome/service.sh --repair 2>&1; '
        'else '
        '  /system/bin/sh /data/adb/agh/scripts/iptables.sh --reload 2>&1; '
        'fi',
        timeout: _mutationSuTimeout,
      );
      _cachedDiag = null;
      _cachedDiagTime = null;
      final res = FirewallReloadResult.fromScriptOutput(
        exitCode: result.exitCode,
        stdoutText: result.stdout.toString(),
      );
      recordOperation(ModuleOperationRecord(
        timestamp: DateTime.now(),
        type: 'firewall_reload',
        opId: 'repair_${DateTime.now().millisecondsSinceEpoch}',
        target: res.branch,
        stage: res.stage,
        exitCode: result.exitCode,
        succeeded: res.succeeded,
      ));
      return res;
    } catch (_) {
      recordOperation(ModuleOperationRecord(
        timestamp: DateTime.now(),
        type: 'firewall_reload',
        opId: 'repair_${DateTime.now().millisecondsSinceEpoch}',
        target: 'exception',
        stage: 'exception',
        exitCode: -1,
        succeeded: false,
      ));
      return const FirewallReloadResult(
        succeeded: false,
        branch: 'exception',
        stage: 'exception',
        message: '操作执行异常',
      );
    }
  }

  /// 检查真实退出码的系统 DNS 缓存刷新（至少一条 resolver 刷新命令返回 0 才算成功）
  Future<bool> flushSystemDnsCache() async {
    if (!_isAndroid) return false;
    try {
      final result = await _runSu(
        'flushed=0; '
        'if command -v ndc >/dev/null 2>&1; then '
        '  ndc resolver flushenv >/dev/null 2>&1 && flushed=1; '
        '  ndc resolver flushdefaultif >/dev/null 2>&1 && flushed=1; '
        'fi; '
        'if command -v cmd >/dev/null 2>&1; then '
        '  cmd netd resolver flushdefaultif >/dev/null 2>&1 && flushed=1; '
        'fi; '
        '[ "\$flushed" -eq 1 ]',
      );
      return result.exitCode == 0;
    } catch (_) {
      return false;
    }
  }

  Future<bool> cleanAppAdCaches() async {
    if (!_isAndroid) return false;
    try {
      final result = await _runSu(
        'rm -f /data/adb/agh/last_clean_time && rmdir /data/adb/agh/cache_clean.lock 2>/dev/null; '
        'if grep -q -- "--daemon" /data/adb/agh/scripts/NoAdsService.sh 2>/dev/null; then '
        '  sh /data/adb/agh/scripts/NoAdsService.sh --once >/dev/null 2>&1; '
        'else '
        '  sh /data/adb/agh/scripts/NoAdsService.sh >/dev/null 2>&1 & '
        'fi',
      );
      return result.exitCode == 0;
    } catch (_) {
      return false;
    }
  }

  static const List<String> _privacyEnhancementRules = [
    r'# --- [隐私增强 1] Cookie 横幅与 GDPR 弹窗同意管理平台 (Consent / CMP) ---',
    r'||cookiebot.com^$important',
    r'||cookielaw.org^$important',
    r'||optanon.blob.core.windows.net^$important',
    r'||onetrust.com^$important',
    r'||onetrust.io^$important',
    r'||privacy-mgmt.com^$important',
    r'||consensu.org^$important',
    r'||wrapper-api.sp-prod.net^$important',
    r'||cmp.quantcast.com^$important',
    r'||trustarc.com^$important',
    r'||betrad.com^$important',
    r'||didomi.io^$important',
    r'||privacy-center.org^$important',
    r'||usercentrics.eu^$important',
    r'||rlcdn.com^$important',
    r'||privacymanager.io^$important',
    r'||consent-api.exponential.com^$important',
    r'# --- [隐私增强 2] A/B 测试与特征开关遥测 (A/B Testing & Feature Flags) ---',
    r'||optimizely.com^$important',
    r'||split.io^$important',
    r'||launchdarkly.com^$important',
    r'||vwo.com^$important',
    r'||visualwebsiteoptimizer.com^$important',
    r'||abtasty.com^$important',
    r'||abtest.ai^$important',
    r'||kameleoon.eu^$important',
    r'||kameleoon.com^$important',
    r'||kameleoon.io^$important',
    r'||statsigapi.net^$important',
    r'||featuregates.org^$important',
    r'||flagsmith.com^$important',
    r'||configcat.com^$important',
    r'# --- [隐私增强 3] 错误监控、崩溃上报与前端录屏遥测 (Error Monitoring) ---',
    r'||sentry-cdn.com^$important',
    r'||getsentry.com^$important',
    r'||ravenjs.com^$important',
    r'||bugsnag.com^$important',
    r'||d2wy8f7a9ursnm.cloudfront.net^$important',
    r'||rollbar.com^$important',
    r'||raygun.io^$important',
    r'||honeybadger.io^$important',
    r'||logrocket.io^$important',
    r'||lr-ingest.com^$important',
    r'||trackjs.com^$important',
    r'||airbrake.io^$important',
    r'||nr-data.net^$important',
    r'||js-agent.newrelic.com^$important',
    r'# --- [隐私增强 4] 邮件打开像素与营销链接追踪 (Email Tracking Pixels) ---',
    r'||mailchimp.com^$important',
    r'||list-manage.com^$important',
    r'||convertkit.com^$important',
    r'||track.customer.io^$important',
    r'||customeriomail.com^$important',
    r'||dripemail2.com^$important',
    r'||getdrip.com^$important',
    r'||sendinblue.com^$important',
    r'||sibautomation.com^$important',
    r'||mailerlite.com^$important',
    r'||aweber.com^$important',
    r'||getresponse.com^$important',
    r'||activecampaign.com^$important',
    r'||trackcmp.net^$important',
    r'||pardot.com^$important',
    r'||email.mailgun.net^$important',
    r'||track.mailgun.org^$important',
    r'||mandrillapp.com^$important',
    r'||track.constantcontact.com^$important',
    r'||hubspotemail.net^$important',
    r'||track.hubspot.com^$important',
    r'||sendgrid.net^$important',
    r'# --- [隐私增强 5] 联盟营销网络与返利追踪 (Affiliate Networks) ---',
    r'||googleadservices.com^$important',
    r'||commission-junction.com^$important',
    r'||emjcd.com^$important',
    r'||anrdoezrs.net^$important',
    r'||apmebf.com^$important',
    r'||jdoqocy.com^$important',
    r'||tkqlhce.com^$important',
    r'||lduhtrp.net^$important',
    r'||awltovhc.com^$important',
    r'||ftjcfx.com^$important',
    r'||tqlkg.com^$important',
    r'||dpbolvw.net^$important',
    r'||kqzyfj.com^$important',
    r'||qksrv.net^$important',
    r'||afcyhf.com^$important',
    r'||shareasale.com^$important',
    r'||shareasale-analytics.com^$important',
    r'||shrsl.com^$important',
    r'||impact.com^$important',
    r'||impactradius-event.com^$important',
    r'||skimresources.com^$important',
    r'||ad.admitad.com^$important',
    r'||gdeslon.ru^$important',
    r'||awin1.com^$important',
    r'||dwin1.com^$important',
    r'||linksynergy.com^$important',
    r'||amazon-adsystem.com^$important',
    r'# --- [隐私增强 6] 社交追踪器与外嵌跟踪组件 (Social Trackers) ---',
    r'||facebook.net^$important',
    r'||pixel.facebook.com^$important',
    r'||an.facebook.com^$important',
    r'||staticxx.facebook.com^$important',
    r'||platform.twitter.com^$important',
    r'||syndication.twitter.com^$important',
    r'||ads-twitter.com^$important',
    r'||ads-api.twitter.com^$important',
    r'||analytics.twitter.com^$important',
    r'||platform.linkedin.com^$important',
    r'||snap.licdn.com^$important',
    r'||px.ads.linkedin.com^$important',
    r'||analytics.pointdrive.linkedin.com^$important',
    r'||ads.linkedin.com^$important',
    r'||ads.pinterest.com^$important',
    r'||log.pinterest.com^$important',
    r'||analytics.pinterest.com^$important',
    r'||ct.pinterest.com^$important',
    r'||trk.pinterest.com^$important',
    r'||widgets.pinterest.com^$important',
    r'||events.reddit.com^$important',
    r'||redditmedia.com^$important',
    r'||d.reddit.com^$important',
    r'||ads.tiktok.com^$important',
    r'||ads-api.tiktok.com^$important',
    r'||analytics.tiktok.com^$important',
    r'||ads-sg.tiktok.com^$important',
    r'||byteoversea.com^$important',
    r'||business-api.tiktok.com^$important',
    r'||analytics-sg.tiktok.com^$important',
    r'||ads.youtube.com^$important',
    r'||plus.google.com^$important',
    r'||platform.instagram.com^$important',
    r'||badges.instagram.com^$important',
    r'||addtoany.com^$important',
    r'||addthis.com^$important',
    r'||sharethis.com^$important',
    r'||st-widget.s3.amazonaws.com^$important',
    r'# --- [隐私增强 7] 跨站追踪与归因分析 (Cross-site Tracking) ---',
    r'||bat.bing.com^$important',
    r'||clarity.ms^$important',
    r'||c.bing.com^$important',
    r'||tr.snapchat.com^$important',
    r'||adsapi.snapchat.com^$important',
    r'||adjust.com^$important',
    r'||appsflyer.com^$important',
    r'||branch.io^$important',
    r'||app.link^$important',
    r'||bnc.lt^$important',
    r'||kochava.com^$important',
    r'||singular.net^$important',
    r'||adsrvr.org^$important',
    r'||tiqcdn.com^$important',
    r'||krxd.net^$important',
    r'||advertising.com^$important',
    r'||rubiconproject.com^$important',
    r'||id5-sync.com^$important',
    r'||liadm.com^$important',
    r'||revcontent.com^$important',
    r'||lijit.com^$important',
    r'||siteimproveanalytics.com^$important',
    r'||device-metrics-us.amazon.com^$important',
    r'||unagi-na.amazon.com^$important',
    r'||media.net^$important',
    r'# --- [隐私增强 8] 行为分析与热力图遥测 (Analytics & Heatmaps) ---',
    r'||google-analytics.com^$important',
    r'||analytics.google.com^$important',
    r'||googletagmanager.com^$important',
    r'||tagmanager.google.com^$important',
    r'||mc.yandex.ru^$important',
    r'||metrika.yandex.ru^$important',
    r'||mc.yandex.com^$important',
    r'||metrika.yandex.com^$important',
    r'||informer.yandex.ru^$important',
    r'||webvisor.com^$important',
    r'||hotjar.io^$important',
    r'||mouseflow.com^$important',
    r'||luckyorange.com^$important',
    r'||luckyorange.net^$important',
    r'||segment.com^$important',
    r'||segment.io^$important',
    r'||amplitude.com^$important',
    r'||mxpnl.com^$important',
    r'||mixpanel.com^$important',
    r'||heapanalytics.com^$important',
    r'||fullstory.com^$important',
    r'||pendo.io^$important',
    r'||matomo.cloud^$important',
    r'||piwik.pro^$important',
    r'||freshmarketer.com^$important',
    r'||stats.wp.com^$important',
    r'||pixel.wp.com^$important',
    r'||chartbeat.com^$important',
    r'||alexametrics.com^$important',
    r'||quantserve.com^$important',
    r'# --- [隐私增强 9] 视频贴片广告与流媒体遥测 (Video Ads) ---',
    r'||imasdk.googleapis.com^$important',
    r'||2mdn.net^$important',
    r'||pagead2.googlevideo.com^$important',
    r'||springserve.com^$important',
    r'||spotxcdn.com^$important',
    r'||spotxchange.com^$important',
    r'||teads.tv^$important',
    r'||jwpltx.com^$important',
    r'||cdn.jwplayer.com^$important',
    r'||bcvp0rtal.com^$important',
    r'||bcovlive.io^$important',
    r'||fresnel.vimeocdn.com^$important',
    r'||f.vimeocdn.com^$important',
    r'||dm.gg^$important',
    r'||ads.dailymotion.com^$important',
    r'||connatix.com^$important',
    r'||video-ads.twitter.com^$important',
    r'# --- [隐私增强 10] 厂商与系统级遥测补充 (OEM Telemetry) ---',
    r'||iadsdk.apple.com^$important',
    r'||metrics.icloud.com^$important',
    r'||metrics.mzstatic.com^$important',
    r'||api-adservices.apple.com^$important',
    r'||books-analytics-events.apple.com^$important',
    r'||weather-analytics-events.apple.com^$important',
    r'||notes-analytics-events.apple.com^$important',
    r'||xp.apple.com^$important',
    r'||supportmetrics.apple.com^$important',
    r'||settings-win.data.microsoft.com^$important',
    r'||vortex.data.microsoft.com^$important',
    r'||telemetry.microsoft.com^$important',
    r'||survey.watson.microsoft.com^$important',
    r'||app-measurement.com^$important',
    r'||firebaselogging.googleapis.com^$important',
    r'||samsungads.com^$important',
    r'||smetrics.samsung.com^$important',
    r'||nmetrics.samsung.com^$important',
    r'||samsunghealthcn.com^$important',
    r'||samsungadhub.com^$important',
    r'||samsung-com.112.2o7.net^$important',
    r'||api.ad.xiaomi.com^$important',
    r'||data.mistat.xiaomi.com^$important',
    r'||data.mistat.india.xiaomi.com^$important',
    r'||data.mistat.rus.xiaomi.com^$important',
    r'||sdkconfig.ad.xiaomi.com^$important',
    r'||sdkconfig.ad.intl.xiaomi.com^$important',
    r'||tracking.rus.miui.com^$important',
    r'||adsfs.oppomobile.com^$important',
    r'||adx.ads.oppomobile.com^$important',
    r'||ck.ads.oppomobile.com^$important',
    r'||data.ads.oppomobile.com^$important',
    r'||iot-eu-logser.realme.com^$important',
    r'||iot-logser.realme.com^$important',
    r'||bdapi-ads.realmemobile.com^$important',
    r'||bdapi-in-ads.realmemobile.com^$important',
    r'||metrics.data.hicloud.com^$important',
    r'||metrics2.data.hicloud.com^$important',
    r'||logservice.hicloud.com^$important',
    r'||logservice1.hicloud.com^$important',
    r'||logbak.hicloud.com^$important',
    r'||click.oneplus.cn^$important',
    r'||open.oneplus.net^$important',
    r'||ads-mas-us.vivobrowser.com^$important',
    r'||ads-mas.vivobrowser.com^$important',
    r'# --- [隐私增强 11] 浏览器加密货币挖矿脚本 (Crypto Mining) ---',
    r'||coinhive.com^$important',
    r'||coin-hive.com^$important',
    r'||authedmine.com^$important',
    r'||coinhive-proxy.com^$important',
    r'||coin-hive-proxy.com^$important',
    r'||crypto-loot.com^$important',
    r'||cryptoloot.pro^$important',
    r'||cryptoloot.org^$important',
    r'||minero.cc^$important',
    r'||minero-proxy.com^$important',
    r'||webmine.cz^$important',
    r'||webminepool.com^$important',
    r'||monerominer.rocks^$important',
    r'||ppoi.org^$important',
    r'||coinimp.com^$important',
    r'||coinerra.com^$important',
    r'||coin-have.com^$important',
    r'||jsecoin.com^$important',
    r'||hashforcash.us^$important',
    r'||hashing.win^$important',
    r'||bitcoinplus.com^$important',
    r'||fastpool.xyz^$important',
    r'||xmr.omine.org^$important',
    r'||minergate.com^$important',
    r'||coinhiveproxy.com^$important',
    r'||cnhv.co^$important',
    r'||afminer.com^$important',
    r'||minemytraffic.com^$important',
    r'||cpu.js.org^$important',
    r'||webminerpool.com^$important',
    r'# --- [隐私增强 12] 国际与区域广告联盟补充 (Ads Networks) ---',
    r'||pagead2.googlesyndication.com^$important',
    r'||adservice.google.com^$important',
    r'||afs.googlesyndication.com^$important',
    r'||fundingchoicesmessages.google.com^$important',
    r'||tpc.googlesyndication.com^$important',
    r'||adtago.s3.amazonaws.com^$important',
    r'||analyticsengine.s3.amazonaws.com^$important',
    r'||advice-ads.s3.amazonaws.com^$important',
    r'||aan.amazon.com^$important',
    r'||aax-eu.amazon.com^$important',
    r'||mads.amazon.com^$important',
    r'||adcolony.com^$important',
    r'||taboola.com^$important',
    r'||outbrain.com^$important',
    r'||adnxs.com^$important',
    r'||criteo.net^$important',
    r'||criteo.com^$important',
    r'||turn.com^$important',
    r'||pubmatic.com^$important',
    r'||smartadserver.com^$important',
    r'||yadro.ru^$important',
    r'||an.yandex.ru^$important',
    r'||advertising.yandex.ru^$important',
    r'||adriver.ru^$important',
    r'||adfox.ru^$important',
    r'||openx.net^$important',
  ];

  static const Set<String> deprecatedFactoryRules = {
    r'@@||googleapis.com^$important',
    r'@@||app-measurement.com^$important',
    r'@@||crashlytics.com^$important',
    r'@@||xp.apple.com^$important',
    r'||oschina.net^$important',
  };

  Future<List<String>> readFactoryUserRules() async {
    if (!_isAndroid) return [];
    try {
      const cmd = r'''
if [ -s /data/adb/agh/bin/default_user_rules.txt ]; then
  cat /data/adb/agh/bin/default_user_rules.txt
elif [ -s /data/adb/agh/backup/AdGuardHome.yaml ]; then
  awk '/^user_rules:/{f=1;next} f&&/^[a-zA-Z_]+:/{exit} f{print}' /data/adb/agh/backup/AdGuardHome.yaml | sed "s/^[[:space:]]*-[[:space:]]*//; s/^'//; s/'$//; s/^\"//; s/\"$//"
elif [ -s /data/adb/agh/bin/AdGuardHome.yaml ]; then
  awk '/^user_rules:/{f=1;next} f&&/^[a-zA-Z_]+:/{exit} f{print}' /data/adb/agh/bin/AdGuardHome.yaml | sed "s/^[[:space:]]*-[[:space:]]*//; s/^'//; s/'$//; s/^\"//; s/\"$//"
fi
''';
      final result = await _runSu(cmd);
      if (result.exitCode != 0) return [];
      final rawLines = result.stdout
          .toString()
          .split('\n')
          .map((e) => e.trimRight())
          .where((e) => e.trim().isNotEmpty)
          .toList();
      final List<String> cleaned = [];
      final Set<String> seen = {};
      bool hasGoogleapisAllow = false;
      for (var line in rawLines) {
        final t = line.trim();
        if (t.startsWith(r"||ad.2bulu.com^$important'")) {
          line = r'||ad.2bulu.com^$important';
        }
        if (t == r'@@||googleapis.com^$important' || t == r'@@||googleapis.com^') {
          if (!hasGoogleapisAllow) {
            hasGoogleapisAllow = true;
            cleaned.add(r'@@||googleapis.com^');
            seen.add(r'@@||googleapis.com^');
          }
          continue;
        }
        if (deprecatedFactoryRules.contains(t)) continue;
        cleaned.add(line);
        seen.add(line.trim());
      }
      for (final enh in _privacyEnhancementRules) {
        if (!seen.contains(enh.trim())) {
          cleaned.add(enh);
          seen.add(enh.trim());
        }
      }
      return cleaned;
    } catch (_) {
      return [];
    }
  }

  Future<List<String>> readAppAllowlist() async {
    if (!_isAndroid) return [];
    try {
      final result = await _runSu(
        '[ -f /data/adb/agh/app-allow.txt ] && cat /data/adb/agh/app-allow.txt || true',
      );
      if (result.exitCode != 0) return [];
      return result.stdout
          .toString()
          .split('\n')
          .map((e) => e.trim())
          .where((e) => e.isNotEmpty && !e.startsWith('#'))
          .toSet()
          .toList();
    } catch (_) {
      return [];
    }
  }

  Future<FirewallReloadResult> saveAppAllowlistDetailed(
    List<String> packages,
  ) async {
    if (!_isAndroid) {
      return const FirewallReloadResult(
        succeeded: false,
        branch: 'not_android',
        stage: 'not_android',
      );
    }
    try {
      final content = packages
          .map((e) => e.trim())
          .where((e) => e.isNotEmpty)
          .join('\n');
      final escaped = content.replaceAll("'", "'\\''");
      final cmd = '''
mkdir -p /data/adb/agh
printf '%s\\n' '$escaped' > /data/adb/agh/app-allow.txt
chmod 644 /data/adb/agh/app-allow.txt
/system/bin/sh /data/adb/agh/scripts/iptables.sh --apply-allowlist 2>&1
''';
      final result = await _runSu(cmd, timeout: const Duration(seconds: 20));
      _cachedDiag = null;
      _cachedDiagTime = null;
      final res = FirewallReloadResult.fromScriptOutput(
        exitCode: result.exitCode,
        stdoutText: result.stdout.toString(),
      );
      recordOperation(ModuleOperationRecord(
        timestamp: DateTime.now(),
        type: 'firewall_reload',
        opId: 'repair_${DateTime.now().millisecondsSinceEpoch}',
        target: res.branch,
        stage: res.stage,
        exitCode: result.exitCode,
        succeeded: res.succeeded,
      ));
      return res;
    } catch (_) {
      recordOperation(ModuleOperationRecord(
        timestamp: DateTime.now(),
        type: 'firewall_reload',
        opId: 'repair_${DateTime.now().millisecondsSinceEpoch}',
        target: 'exception',
        stage: 'exception',
        exitCode: -1,
        succeeded: false,
      ));
      return const FirewallReloadResult(
        succeeded: false,
        branch: 'exception',
        stage: 'exception',
      );
    }
  }

  Future<bool> saveAppAllowlist(List<String> packages) async {
    final res = await saveAppAllowlistDetailed(packages);
    return res.succeeded;
  }

  Future<List<Map<String, dynamic>>> getInstalledApps({
    bool includeSystem = false,
    bool forceRefresh = false,
  }) async {
    if (!_isAndroid) return [];
    if (!forceRefresh &&
        !includeSystem &&
        _cachedApps != null &&
        _cachedAppsTime != null &&
        DateTime.now().difference(_cachedAppsTime!) <
            const Duration(seconds: 60)) {
      return _cachedApps!
          .map((e) => Map<String, dynamic>.from(e))
          .toList();
    }
    try {
      final rawList = await _installedAppsChannel.invokeMethod<List<dynamic>>(
        'getInstalledApps',
        {
          'includeSystem': includeSystem,
          'forceRefresh': forceRefresh,
        },
      );
      if (rawList != null && rawList.isNotEmpty) {
        final List<Map<String, dynamic>> apps = [];
        for (final item in rawList) {
          if (item is Map) {
            final pkg = (item['package'] ?? '').toString().trim();
            if (pkg.isEmpty) continue;
            final rawName = (item['name'] ?? '').toString().trim();
            final name = (rawName.isNotEmpty && rawName != pkg)
                ? rawName
                : resolveKnownAppName(pkg);
            final icon = item['icon'] is Uint8List ? item['icon'] as Uint8List : null;
            final uid = item['uid'] is int ? item['uid'] as int : null;
            apps.add({
              'package': pkg,
              'name': name,
              'uid': uid,
              'icon': icon,
            });
          }
        }
        apps.sort((a, b) => (a['name'] as String).compareTo(b['name'] as String));
        if (!includeSystem) {
          _cachedApps = apps;
          _cachedAppsTime = DateTime.now();
        }
        return apps.map((e) => Map<String, dynamic>.from(e)).toList();
      }
    } catch (_) {
      // Fallback to root pm list packages below
    }

    try {
      final result = await _runSu(
        'pm list packages -3 2>/dev/null || pm list packages 2>/dev/null',
      );
      if (result.exitCode != 0) return [];
      final lines = result.stdout.toString().split('\n');
      final List<Map<String, dynamic>> apps = [];
      for (final raw in lines) {
        var pkg = raw.trim();
        if (pkg.startsWith('package:')) {
          pkg = pkg.substring('package:'.length).trim();
        }
        if (pkg.isNotEmpty) {
          apps.add({
            'package': pkg,
            'name': resolveKnownAppName(pkg),
            'uid': null,
            'icon': null,
          });
        }
      }
      apps.sort((a, b) => (a['name'] as String).compareTo(b['name'] as String));
      if (!includeSystem) {
        _cachedApps = apps;
        _cachedAppsTime = DateTime.now();
      }
      return apps.map((e) => Map<String, dynamic>.from(e)).toList();
    } catch (_) {
      return [];
    }
  }

  static String resolveKnownAppName(String pkg) {
    const known = {
      'com.tencent.mm': '微信',
      'com.eg.android.AlipayGphone': '支付宝',
      'com.taobao.taobao': '手机淘宝',
      'com.jingdong.app.mall': '京东',
      'tv.danmaku.bili': '哔哩哔哩',
      'com.autonavi.minimap': '高德地图',
      'com.baidu.BaiduMap': '百度地图',
      'com.sankuai.meituan': '美团',
      'com.zhihu.android': '知乎',
      'com.xingin.xhs': '小红书',
      'com.ss.android.ugc.aweme': '抖音',
      'com.kuaishou.nebula': '快手',
      'com.netease.cloudmusic': '网易云音乐',
      'com.tencent.qqmusic': 'QQ音乐',
      'com.tencent.mobileqq': 'QQ',
      'com.sina.weibo': '微博',
      'com.alibaba.android.rimet': '钉钉',
      'com.tencent.wework': '企业微信',
      'com.unionpay': '云闪付',
      'com.tmall.wireless': '手机天猫',
      'com.xunmeng.pinduoduo': '拼多多',
      'com.dragon.read': '番茄免费小说',
      'com.coolapk.market': '酷安',
      'com.android.vending': 'Google Play 商店',
      'com.google.android.gms': 'Google Play 服务',
      'com.chinamworld.main': '中国建设银行',
      'com.icbc': '中国工商银行',
      'com.bankofchina.mpassport': '中国银行',
      'com.android.bankabc': '中国农业银行',
      'cmb.pb': '招商银行',
      'com.traffic.alipay.wz': '交管12123',
    };
    return known[pkg] ?? pkg;
  }

  static String resolveFilterFileName(String pathOrFile) {
    final fileName = pathOrFile.split('/').last.trim();
    const map = {
      '1721861844.txt': 'AdGuard DNS 规则',
      '1721861846.txt': 'GOODBYEADS 规则',
      '1740000001.txt': 'AWAvenue 秋风规则',
      '1.txt': 'AdGuard DNS 规则',
      '1735560833.txt': 'URLHaus 恶意域名规则',
      '8.txt': 'NoCoin 防挖矿规则',
    };
    return map[fileName] ?? fileName;
  }

  /// 在本地规则库文件 (/data/adb/agh/bin/data/filters/*.txt) 中按关键词检索拦截规则
  Future<List<Map<String, String>>> searchFilterRules(String keyword) async {
    if (!_isAndroid) return [];
    final safeKey =
        keyword.trim().toLowerCase().replaceAll(RegExp(r'[^a-z0-9._-]'), '');
    if (safeKey.length < 2) return [];
    try {
      final cmd =
          'grep -i -H -m 25 "$safeKey" /data/adb/agh/bin/data/filters/*.txt 2>/dev/null | head -n 60 || true';
      final result = await _runSu(cmd);
      if (result.exitCode != 0) return [];
      final lines = result.stdout.toString().split('\n');
      final List<Map<String, String>> matches = [];
      final Set<String> seenDomains = {};

      for (final raw in lines) {
        final line = raw.trim();
        if (line.isEmpty) continue;
        final colonIdx = line.indexOf(':');
        if (colonIdx <= 0) continue;
        final filePath = line.substring(0, colonIdx);
        final ruleText = line.substring(colonIdx + 1).trim();
        if (ruleText.isEmpty ||
            ruleText.startsWith('!') ||
            ruleText.startsWith('#') ||
            ruleText.startsWith('@@')) {
          continue;
        }

        String? domain;
        if (ruleText.startsWith('||')) {
          var rest = ruleText.substring(2);
          final cutIdx = rest.indexOf(RegExp(r'[\^\$/]'));
          if (cutIdx > 0) rest = rest.substring(0, cutIdx);
          domain = rest.trim();
        } else if (ruleText.startsWith('0.0.0.0 ') ||
            ruleText.startsWith('127.0.0.1 ')) {
          final parts = ruleText.split(RegExp(r'\s+'));
          if (parts.length >= 2) {
            domain = parts[1].trim();
          }
        } else {
          final m = RegExp(r'^([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})')
              .firstMatch(ruleText);
          if (m != null) {
            domain = m.group(1);
          }
        }

        if (domain == null ||
            domain.isEmpty ||
            !domain.contains('.') ||
            domain.contains('*')) {
          continue;
        }
        domain = domain.toLowerCase();
        if (seenDomains.contains(domain)) continue;
        seenDomains.add(domain);

        matches.add({
          'domain': domain,
          'rule': ruleText,
          'filterName': resolveFilterFileName(filePath),
        });
        if (matches.length >= 25) break;
      }
      return matches;
    } catch (_) {
      return [];
    }
  }

  /// 抓取网页源码并提取该网页引用的所有主域名与第三方外链/静态资源域名
  Future<List<String>> extractWebpageDomains(String rawInput) async {
    var trimmed = rawInput.trim();
    if (trimmed.isEmpty) return [];

    final urlMatch = RegExp(r'https?://[^\s"<>]+').firstMatch(trimmed);
    if (urlMatch != null) {
      trimmed = urlMatch.group(0)!;
    } else if (!trimmed.startsWith('http://') &&
        !trimmed.startsWith('https://')) {
      final hostPart = trimmed.split('/').first.split(':').first.toLowerCase();
      final scheme = _isPrivateOrLoopbackHost(hostPart) ? 'http' : 'https';
      trimmed = '$scheme://$trimmed';
    }

    final uri = Uri.tryParse(trimmed);
    if (uri == null || uri.host.isEmpty) return [];

    final hostLower = uri.host.toLowerCase();
    final Set<String> domains = {};
    if (!_isIpLiteral(hostLower) && !_isPrivateOrLoopbackHost(hostLower)) {
      domains.add(hostLower);
    }

    Future<String> fetchHtml(String targetUrl) async {
      try {
        final client = HttpClient()
          ..connectionTimeout = const Duration(seconds: 6)
          ..badCertificateCallback = (_, __, ___) => true;
        final req = await client.getUrl(Uri.parse(targetUrl));
        req.headers.set(
          HttpHeaders.userAgentHeader,
          'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
        );
        final resp = await req.close().timeout(const Duration(seconds: 6));
        final bytes = await resp.fold<List<int>>(
          <int>[],
          (prev, elem) => prev.length < 262144 ? (prev..addAll(elem)) : prev,
        );
        client.close();
        return utf8.decode(bytes, allowMalformed: true);
      } catch (_) {
        if (!_isAndroid) return '';
        try {
          final safeUrl = targetUrl.replaceAll("'", '');
          final res = await _runSu(
            "/system/bin/curl -sS -L -k --max-time 6 -A 'Mozilla/5.0 (Linux; Android 14) Chrome/124.0.0.0 Mobile' '$safeUrl' 2>/dev/null | head -c 262144 || true",
          );
          return res.stdout.toString();
        } catch (_) {
          return '';
        }
      }
    }

    var mainHtml = await fetchHtml(uri.toString());
    if (mainHtml.isEmpty && uri.scheme == 'https') {
      final httpFallback = uri.replace(scheme: 'http').toString();
      mainHtml = await fetchHtml(httpFallback);
    }
    final StringBuffer allHtml = StringBuffer(mainHtml);

    if (mainHtml.isNotEmpty) {
      final iframeRegex =
          RegExp(r'<iframe[^>]+src=["\x27](/[^"\x27>]+)["\x27]', caseSensitive: false);
      int followed = 0;
      for (final m in iframeRegex.allMatches(mainHtml)) {
        final relPath = m.group(1);
        if (relPath != null && relPath.startsWith('/') && !relPath.startsWith('//')) {
          final subUrl = '${uri.scheme}://${uri.authority}$relPath';
          final subHtml = await fetchHtml(subUrl);
          if (subHtml.isNotEmpty) {
            allHtml.write('\n');
            allHtml.write(subHtml);
          }
          followed++;
          if (followed >= 2) break;
        }
      }
    }

    final htmlText = allHtml.toString();
    if (htmlText.isNotEmpty) {
      final hostRegex = RegExp(
        r'(?:https?:)?//([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})(?=[/:"\x27\s?>]|$)',
      );
      for (final m in hostRegex.allMatches(htmlText)) {
        final host = (m.group(1) ?? '').toLowerCase().trim();
        if (_isValidCandidateDomain(host)) {
          domains.add(host);
        }
      }
    }

    return domains.toList();
  }

  /// 扫描指定应用私有目录 (`/data/data/<pkg>`) 中缓存或配置保存的业务与接口域名
  Future<List<String>> scanAppLocalDomains(String packageName) async {
    if (!_isAndroid) return [];
    final safePkg =
        packageName.trim().replaceAll(RegExp(r'[^a-zA-Z0-9._]'), '');
    if (safePkg.isEmpty) return [];

    try {
      final cmd = '''
find /data/data/$safePkg/shared_prefs /data/data/$safePkg/files /data/data/$safePkg/databases /data/data/$safePkg/cache /data/data/$safePkg/app_webview -maxdepth 3 -type f -size -512k 2>/dev/null | head -n 60 | xargs grep -aEhro 'https?://[a-zA-Z0-9][-a-zA-Z0-9.]*\\.[a-zA-Z]{2,}' 2>/dev/null | sed -E 's#^https?://##; s#/.*##' | sort -u | head -n 80 || true
''';
      final result = await _runSu(cmd);
      if (result.exitCode != 0) return [];
      final lines = result.stdout.toString().split('\n');
      final Set<String> domains = {};
      for (final raw in lines) {
        final host = raw.trim().toLowerCase();
        if (_isValidCandidateDomain(host)) {
          domains.add(host);
        }
      }
      return domains.toList();
    } catch (_) {
      return [];
    }
  }

  /// 清理 DNS 缓存并冷启动目标应用，用于排错抓包复现
  Future<bool> launchAppForCapture(
    String packageName, {
    bool forceStop = true,
  }) async {
    if (!_isAndroid) return false;
    final safePkg =
        packageName.trim().replaceAll(RegExp(r'[^a-zA-Z0-9._]'), '');
    if (safePkg.isEmpty) return false;
    try {
      final stopCmd = forceStop ? 'am force-stop $safePkg >/dev/null 2>&1;' : '';
      final cmd = '''
$stopCmd
ndc resolver flushenv >/dev/null 2>&1 || true
ndc resolver flushdefaultif >/dev/null 2>&1 || true
cmd netd resolver flushdefaultif >/dev/null 2>&1 || true
monkey -p $safePkg -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
''';
      final result = await _runSu(cmd);
      return result.exitCode == 0;
    } catch (_) {
      return false;
    }
  }

  static bool _isIpLiteral(String host) {
    final clean = host.replaceAll('[', '').replaceAll(']', '');
    return InternetAddress.tryParse(clean) != null;
  }

  static bool _isPrivateOrLoopbackHost(String host) {
    final h = host.toLowerCase().replaceAll('[', '').replaceAll(']', '');
    if (h == 'localhost' ||
        h.endsWith('.local') ||
        h.endsWith('.lan') ||
        h.endsWith('.home.arpa') ||
        h.endsWith('.in-addr.arpa') ||
        h.endsWith('.ip6.arpa')) {
      return true;
    }
    final ip = InternetAddress.tryParse(h);
    if (ip == null) return false;
    if (ip.isLoopback || ip.isLinkLocal || ip.isMulticast) return true;
    final raw = ip.rawAddress;
    if (raw.length == 4) {
      final b0 = raw[0];
      final b1 = raw[1];
      if (b0 == 127 || b0 == 10) return true;
      if (b0 == 172 && b1 >= 16 && b1 <= 31) return true;
      if (b0 == 192 && b1 == 168) return true;
      if (b0 == 169 && b1 == 254) return true;
    } else if (raw.length == 16) {
      if ((raw[0] & 0xfe) == 0xfc || (raw[0] == 0xfe && (raw[1] & 0xc0) == 0x80)) {
        return true;
      }
    }
    return false;
  }

  static bool _isValidCandidateDomain(String host) {
    if (host.isEmpty || host.length > 120 || !host.contains('.')) return false;
    if (host.startsWith('.') || host.endsWith('.')) return false;
    if (_isIpLiteral(host) || _isPrivateOrLoopbackHost(host)) return false;
    const ignoredHosts = {
      'schemas.android.com',
      'www.w3.org',
      'ns.adobe.com',
      'xmlpull.org',
      'localhost',
      'example.com',
      'www.example.com',
    };
    if (ignoredHosts.contains(host)) return false;

    final tld = host.split('.').last;
    const invalidFileExts = {
      'js',
      'css',
      'png',
      'jpg',
      'jpeg',
      'gif',
      'webp',
      'svg',
      'ico',
      'woff',
      'woff2',
      'ttf',
      'eot',
      'mp3',
      'mp4',
      'json',
      'xml',
      'html',
      'htm',
      'apk',
      'dex',
      'so',
      'zip',
      'rar',
      '7z',
      'txt',
      'log',
      'db',
      'sqlite',
    };
    if (invalidFileExts.contains(tld)) return false;
    return RegExp(r'^[a-z0-9][-a-z0-9.]*\.[a-z]{2,}$').hasMatch(host);
  }
}
