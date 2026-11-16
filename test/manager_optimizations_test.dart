import 'dart:async';
import 'dart:io';

import 'package:adguard_home_manager/providers/status_provider.dart';
import 'package:adguard_home_manager/services/module_config_service.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('StatusProvider Countdown Tests (Section 五.A)', () {
    test('normal countdown ticks to zero, cancels timer, and refreshes once', () async {
      var fakeNow = DateTime(2026, 11, 15, 12, 0, 0);
      var refreshCount = 0;

      final provider = StatusProvider(
        nowProvider: () => fakeNow,
        onExpiredRefreshOverride: () async {
          refreshCount++;
          return true;
        },
      );

      final deadline = fakeNow.add(const Duration(seconds: 2));
      provider.startCountdown(deadline);

      expect(provider.hasActiveCountdown, isTrue);
      expect(provider.remainingTime, 2);
      expect(provider.remainingTimeNotifier.value, 2);

      fakeNow = fakeNow.add(const Duration(seconds: 1));
      await Future<void>.delayed(const Duration(milliseconds: 1100));
      expect(provider.hasActiveCountdown, isTrue);
      expect(provider.remainingTime, 1);

      fakeNow = fakeNow.add(const Duration(seconds: 1));
      await Future<void>.delayed(const Duration(milliseconds: 1100));
      expect(provider.hasActiveCountdown, isFalse);
      expect(provider.remainingTime, 0);
      expect(provider.currentDeadline, isNull);
      expect(refreshCount, 1);

      provider.dispose();
    });

    test('already expired deadline does not start repeating timer and refreshes once', () async {
      final fakeNow = DateTime(2026, 11, 15, 12, 0, 10);
      var refreshCount = 0;

      final provider = StatusProvider(
        nowProvider: () => fakeNow,
        onExpiredRefreshOverride: () async {
          refreshCount++;
          return true;
        },
      );

      final expiredDeadline = fakeNow.subtract(const Duration(seconds: 5));
      provider.startCountdown(expiredDeadline);

      expect(provider.hasActiveCountdown, isFalse);
      expect(provider.remainingTime, 0);
      expect(provider.currentDeadline, isNull);
      expect(refreshCount, 1);

      provider.dispose();
    });

    test('background pause / frame drop jumping past deadline stops immediately without negative loop', () async {
      var fakeNow = DateTime(2026, 11, 15, 12, 0, 0);
      var refreshCount = 0;

      final provider = StatusProvider(
        nowProvider: () => fakeNow,
        onExpiredRefreshOverride: () async {
          refreshCount++;
          return true;
        },
      );

      final deadline = fakeNow.add(const Duration(seconds: 3));
      provider.startCountdown(deadline);
      expect(provider.remainingTime, 3);
      expect(provider.hasActiveCountdown, isTrue);

      fakeNow = fakeNow.add(const Duration(seconds: 10));
      await Future<void>.delayed(const Duration(milliseconds: 1100));

      expect(provider.hasActiveCountdown, isFalse);
      expect(provider.remainingTime, 0);
      expect(provider.remainingTimeNotifier.value, 0);
      expect(refreshCount, 1);

      provider.dispose();
    });

    test('dispose cancels active countdown without firing refresh', () async {
      var fakeNow = DateTime(2026, 11, 15, 12, 0, 0);
      var refreshCount = 0;

      final provider = StatusProvider(
        nowProvider: () => fakeNow,
        onExpiredRefreshOverride: () async {
          refreshCount++;
          return true;
        },
      );

      provider.startCountdown(fakeNow.add(const Duration(seconds: 5)));
      expect(provider.hasActiveCountdown, isTrue);

      provider.dispose();
      expect(provider.hasActiveCountdown, isFalse);

      fakeNow = fakeNow.add(const Duration(seconds: 10));
      await Future<void>.delayed(const Duration(milliseconds: 1100));
      expect(refreshCount, 0);
    });
  });

  group('RuleSearchCoordinator Single-Flight & Generation Tests (Item 5)', () {
    test('coalesces burst searches to single-flight + latest pending and validates A -> B -> A by generation', () async {
      final executedKeywords = <String>[];
      final completers = <Completer<List<Map<String, String>>>>[];
      final delivered = <({int gen, String keyword, List<Map<String, String>> matches})>[];

      late final RuleSearchCoordinator coordinator;
      coordinator = RuleSearchCoordinator(
        executor: (keyword) {
          executedKeywords.add(keyword);
          final c = Completer<List<Map<String, String>>>();
          completers.add(c);
          return c.future;
        },
        onResult: (gen, keyword, matches, stillSearching) {
          delivered.add((gen: gen, keyword: keyword, matches: matches));
        },
      );

      // 1. Start search A (gen 1)
      final fA1 = coordinator.submitSearch('alpha');
      expect(coordinator.searchInFlight, isTrue);
      expect(executedKeywords, ['alpha']);
      expect(coordinator.requestGeneration, 1);

      // 2. While A (gen 1) is in flight, submit B (gen 2) then A again (gen 3: A -> B -> A)
      final fB = coordinator.submitSearch('beta');
      final fA2 = coordinator.submitSearch('alpha');
      await Future.wait([fB, fA2]);

      // B was overwritten by second A in latestPendingRequest; only 1 scan is currently running
      expect(executedKeywords, ['alpha']);
      expect(coordinator.latestPendingRequest?.keyword, 'alpha');
      expect(coordinator.latestPendingRequest?.generation, 3);

      // 3. Complete first A (gen 1) with stale data -> must NOT be delivered, and must immediately trigger gen 3
      completers[0].complete([
        {'domain': 'stale.alpha.com', 'rule': '||stale.alpha.com^', 'filterName': '1.txt'},
      ]);
      await Future<void>.delayed(const Duration(milliseconds: 20));

      expect(delivered, isEmpty);
      expect(executedKeywords, ['alpha', 'alpha']); // 'beta' was skipped!
      expect(coordinator.searchInFlight, isTrue);

      // 4. Complete second A (gen 3) -> delivered with fresh data
      completers[1].complete([
        {'domain': 'fresh.alpha.com', 'rule': '||fresh.alpha.com^', 'filterName': '1.txt'},
      ]);
      await fA1;

      expect(coordinator.searchInFlight, isFalse);
      expect(delivered.length, 1);
      expect(delivered.single.gen, 3);
      expect(delivered.single.keyword, 'alpha');
      expect(delivered.single.matches.single['domain'], 'fresh.alpha.com');
    });

    test('invalidatePending on clear/short input and dispose discard in-flight results', () async {
      final completer = Completer<List<Map<String, String>>>();
      final delivered = <int>[];

      final coordinator = RuleSearchCoordinator(
        executor: (_) => completer.future,
        onResult: (gen, _, __, ___) => delivered.add(gen),
      );

      final f = coordinator.submitSearch('tracker');
      expect(coordinator.searchInFlight, isTrue);

      // User clears input while scan is in flight
      coordinator.invalidatePending();
      expect(coordinator.latestPendingRequest, isNull);

      completer.complete([
        {'domain': 'tracker.com', 'rule': '||tracker.com^', 'filterName': '1.txt'},
      ]);
      await f;

      expect(delivered, isEmpty);
      coordinator.dispose();
      expect(coordinator.isDisposed, isTrue);
    });
  });

  group('ModuleConfigService Root Probe, Timeout & Capability Deduplication Tests (Items 4, 7, 8)', () {
    setUp(() {
      ModuleConfigService.resetTestState();
    });

    test('defaultSuProbeCandidate terminates and reaps hung child process on timeout without pipe deadlock', () async {
      final tmpDir = await Directory.current.createTemp('.agh_su_probe_test_');
      try {
        final fakeHungSu = File('${tmpDir.path}/fake_hung_su.sh');
        final pidRecord = File('${tmpDir.path}/hung.pid');
        await fakeHungSu.writeAsString(
          '#!/bin/sh\n'
          'echo \$\$ > "${pidRecord.path}"\n'
          'i=0\n'
          'while [ "\$i" -lt 200 ]; do\n'
          '  echo "flooding stdout line \$i"\n'
          '  echo "flooding stderr line \$i" >&2\n'
          '  i=\$((i + 1))\n'
          'done\n'
          'trap "exit 0" TERM INT\n'
          'while :; do sleep 1; done\n',
        );
        final chmodRes = await Process.run('/bin/chmod', ['755', fakeHungSu.path]);
        expect(chmodRes.exitCode, 0);

        final res = await ModuleConfigService.defaultSuProbeCandidate(
          fakeHungSu.path,
          const Duration(milliseconds: 1200),
        );
        expect(res, isNull);
        expect(await pidRecord.exists(), isTrue);

        final childPid = int.parse((await pidRecord.readAsString()).trim());
        // Verify the hung child process was terminated and reaped
        final checkProc = await Process.run('/bin/kill', ['-0', '$childPid']);
        expect(checkProc.exitCode, isNot(0));
      } finally {
        if (await tmpDir.exists()) {
          await tmpDir.delete(recursive: true);
        }
      }
    });

    test('concurrent su probes share single in-flight probe even when forceRefresh is triggered', () async {
      var probeCount = 0;
      final probeCompleter = Completer<ProcessResult?>();

      final s1 = ModuleConfigService(
        isAndroidOverride: true,
        probeCandidateRunner: (su, timeout) {
          probeCount++;
          return probeCompleter.future;
        },
        processRunner: (exe, args) async => ProcessResult(10, 0, 'cn\n', ''),
      );
      final s2 = ModuleConfigService(
        isAndroidOverride: true,
        probeCandidateRunner: (su, timeout) {
          probeCount++;
          return probeCompleter.future;
        },
        processRunner: (exe, args) async => ProcessResult(11, 0, 'cn\n', ''),
      );

      final f1 = s1.hasRoot();
      final f2 = s2.readRunMode();
      await Future<void>.delayed(const Duration(milliseconds: 30));
      expect(probeCount, 1);

      probeCompleter.complete(ProcessResult(1, 0, '0\n', ''));
      expect(await f1, isTrue);
      expect(await f2, 'cn');
      expect(probeCount, 1);
    });

    test('non-zero business command exit code is NOT retried across other su candidates', () async {
      final executedCommands = <String>[];

      final service = ModuleConfigService(
        isAndroidOverride: true,
        processRunner: (executable, arguments) async {
          final cmd = arguments.length >= 2 ? arguments[1] : '';
          executedCommands.add('$executable :: $cmd');
          if (cmd == 'id -u') {
            if (executable == 'su') {
              throw const ProcessException('su', ['-c', 'id -u'], 'not found');
            }
            if (executable == '/sbin/su') {
              return ProcessResult(100, 0, '0\n', '');
            }
          }
          return ProcessResult(101, 1, 'AGH_SWITCH_RESULT status=error stage=candidate_validation_failed mode=cn\n', 'business failure');
        },
      );

      final res = await service.switchRunModeDetailed('cn');
      expect(res.succeeded, isFalse);
      expect(res.stage, 'candidate_validation_failed');

      final businessRuns = executedCommands
          .where((e) => e.contains('switch_mode.sh'))
          .toList();
      expect(businessRuns.length, 1);
      expect(businessRuns.single, startsWith('/sbin/su :: '));
    });

    test('reloadFirewallRulesDetailed parses capability result and blocks duplicate mutation on timeout', () async {
      var repairInvocations = 0;
      final slowRepairCompleter = Completer<ProcessResult>();

      Future<ProcessResult> runner(String executable, List<String> arguments) {
        final cmd = arguments.length >= 2 ? arguments[1] : '';
        if (cmd == 'id -u') {
          return Future.value(ProcessResult(1, 0, '0\n', ''));
        }
        if (cmd.contains('service.sh --repair')) {
          repairInvocations++;
          return slowRepairCompleter.future;
        }
        return Future.value(ProcessResult(2, 0, '', ''));
      }

      final fastTimeoutService = ModuleConfigService(
        isAndroidOverride: true,
        mutationWaitTimeout: const Duration(milliseconds: 100),
        processRunner: runner,
      );

      // 1. First call times out waiting -> returns unconfirmed, while underlying process is still in flight
      final firstRes = await fastTimeoutService.reloadFirewallRulesDetailed();
      expect(firstRes.succeeded, isFalse);
      expect(firstRes.unconfirmed, isTrue);
      expect(firstRes.message, '执行结果未确认');
      expect(repairInvocations, 1);

      // 2. Second call while first is still running reuses the in-flight operation instead of spawning a second repair
      final normalWaitService = ModuleConfigService(
        isAndroidOverride: true,
        mutationWaitTimeout: const Duration(seconds: 2),
        processRunner: runner,
      );
      final secondFuture = normalWaitService.reloadFirewallRulesDetailed();
      await Future<void>.delayed(const Duration(milliseconds: 30));
      expect(repairInvocations, 1);

      // 3. Complete underlying repair with structured capability confirmation (dns_flushed=1)
      slowRepairCompleter.complete(
        ProcessResult(
          20,
          0,
          'AGH_REPAIR_RESULT status=ok stage=completed branch=service_repair dns_flushed=1\n',
          '',
        ),
      );
      final secondRes = await secondFuture;
      expect(secondRes.succeeded, isTrue);
      expect(secondRes.unconfirmed, isFalse);
      expect(secondRes.capabilityConfirmed, isTrue);
      expect(secondRes.systemDnsFlushed, isTrue);
      expect(secondRes.branch, 'service_repair');
      expect(repairInvocations, 1);
    });

    test('FirewallReloadResult distinguishes dns_flushed=1, dns_flushed=0, and legacy unconfirmed output', () {
      final confirmedFlushed = FirewallReloadResult.fromScriptOutput(
        exitCode: 0,
        stdoutText: 'AGH_REPAIR_RESULT status=ok stage=completed branch=service_repair dns_flushed=1\n',
      );
      expect(confirmedFlushed.succeeded, isTrue);
      expect(confirmedFlushed.capabilityConfirmed, isTrue);
      expect(confirmedFlushed.systemDnsFlushed, isTrue);

      final confirmedNotFlushed = FirewallReloadResult.fromScriptOutput(
        exitCode: 0,
        stdoutText: 'AGH_REPAIR_RESULT status=ok stage=completed branch=iptables_reload dns_flushed=0\n',
      );
      expect(confirmedNotFlushed.succeeded, isTrue);
      expect(confirmedNotFlushed.capabilityConfirmed, isTrue);
      expect(confirmedNotFlushed.systemDnsFlushed, isFalse);

      final legacyOutput = FirewallReloadResult.fromScriptOutput(
        exitCode: 0,
        stdoutText: '',
      );
      expect(legacyOutput.succeeded, isTrue);
      expect(legacyOutput.capabilityConfirmed, isFalse);
      expect(legacyOutput.systemDnsFlushed, isFalse);

      final failedOutput = FirewallReloadResult.fromScriptOutput(
        exitCode: 1,
        stdoutText: 'AGH_REPAIR_RESULT status=error stage=firewall_apply_failed branch=service_repair dns_flushed=0\n',
      );
      expect(failedOutput.succeeded, isFalse);
      expect(failedOutput.stage, 'firewall_apply_failed');
    });
  });

  group('ModeSwitch Target-Aware Coalescing & Serial Queue Tests (RC3 Item 1)', () {
    setUp(() {
      ModuleConfigService.resetTestState();
    });

    test('1. requesting cn while cn is already in flight executes only once and shares result', () async {
      final executedModes = <String>[];
      final cnCompleter = Completer<ProcessResult>();

      Future<ProcessResult> runner(String executable, List<String> arguments) {
        final cmd = arguments.length >= 2 ? arguments[1] : '';
        if (cmd == 'id -u') {
          return Future.value(ProcessResult(1, 0, '0\n', ''));
        }
        final match = RegExp(r'switch_mode\.sh\s+(cn|overseas)').firstMatch(cmd);
        if (match != null) {
          executedModes.add(match.group(1)!);
          return cnCompleter.future;
        }
        return Future.value(ProcessResult(2, 0, '', ''));
      }

      final service = ModuleConfigService(
        isAndroidOverride: true,
        processRunner: runner,
      );

      final f1 = service.switchRunModeDetailed('cn');
      final f2 = service.switchRunModeDetailed('CN');
      await Future<void>.delayed(const Duration(milliseconds: 30));

      expect(executedModes, ['cn']);

      cnCompleter.complete(
        ProcessResult(
          10,
          0,
          'AGH_SWITCH_RESULT status=ok stage=completed mode=cn\n',
          '',
        ),
      );

      final res1 = await f1;
      final res2 = await f2;
      expect(res1.succeeded, isTrue);
      expect(res1.targetMode, 'cn');
      expect(res1.mode, 'cn');
      expect(res2.succeeded, isTrue);
      expect(res2.targetMode, 'cn');
      expect(res2.mode, 'cn');
      expect(executedModes, ['cn']);
    });

    test('2. requesting overseas while cn is in flight queues and executes sequentially with final state overseas', () async {
      final executedModes = <String>[];
      final completers = <Completer<ProcessResult>>[];
      var activeCount = 0;
      var maxConcurrent = 0;
      var currentDeviceMode = 'overseas';

      Future<ProcessResult> runner(String executable, List<String> arguments) async {
        final cmd = arguments.length >= 2 ? arguments[1] : '';
        if (cmd == 'id -u') {
          return ProcessResult(1, 0, '0\n', '');
        }
        final match = RegExp(r'switch_mode\.sh\s+(cn|overseas)').firstMatch(cmd);
        if (match != null) {
          final mode = match.group(1)!;
          executedModes.add(mode);
          activeCount++;
          if (activeCount > maxConcurrent) {
            maxConcurrent = activeCount;
          }
          final c = Completer<ProcessResult>();
          completers.add(c);
          final res = await c.future;
          currentDeviceMode = mode;
          activeCount--;
          return res;
        }
        return ProcessResult(2, 0, '', '');
      }

      final service = ModuleConfigService(
        isAndroidOverride: true,
        processRunner: runner,
      );

      final fCn = service.switchRunModeDetailed('cn');
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(executedModes, ['cn']);
      expect(activeCount, 1);

      // Request overseas while cn is still running -> must NOT share cn's future and must NOT run concurrently
      final fOverseas = service.switchRunModeDetailed('overseas');
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(executedModes, ['cn']);
      expect(activeCount, 1);

      // Complete cn -> fCn finishes, overseas starts immediately
      completers[0].complete(
        ProcessResult(11, 0, 'AGH_SWITCH_RESULT status=ok stage=completed mode=cn\n', ''),
      );
      final resCn = await fCn;
      expect(resCn.succeeded, isTrue);
      expect(resCn.targetMode, 'cn');
      expect(resCn.mode, 'cn');

      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(executedModes, ['cn', 'overseas']);
      expect(activeCount, 1);

      // Complete overseas -> fOverseas finishes with overseas
      completers[1].complete(
        ProcessResult(12, 0, 'AGH_SWITCH_RESULT status=ok stage=completed mode=overseas\n', ''),
      );
      final resOverseas = await fOverseas;
      expect(resOverseas.succeeded, isTrue);
      expect(resOverseas.targetMode, 'overseas');
      expect(resOverseas.mode, 'overseas');
      expect(executedModes, ['cn', 'overseas']);
      expect(maxConcurrent, 1);
      expect(currentDeviceMode, 'overseas');
    });

    test('3. when first request wait times out while underlying switch is still running, second target does NOT execute concurrently', () async {
      final executedModes = <String>[];
      final completers = <Completer<ProcessResult>>[];
      var activeCount = 0;
      var maxConcurrent = 0;

      Future<ProcessResult> runner(String executable, List<String> arguments) async {
        final cmd = arguments.length >= 2 ? arguments[1] : '';
        if (cmd == 'id -u') {
          return ProcessResult(1, 0, '0\n', '');
        }
        final match = RegExp(r'switch_mode\.sh\s+(cn|overseas)').firstMatch(cmd);
        if (match != null) {
          final mode = match.group(1)!;
          executedModes.add(mode);
          activeCount++;
          if (activeCount > maxConcurrent) {
            maxConcurrent = activeCount;
          }
          final c = Completer<ProcessResult>();
          completers.add(c);
          try {
            return await c.future;
          } finally {
            activeCount--;
          }
        }
        return ProcessResult(2, 0, '', '');
      }

      final fastTimeoutService = ModuleConfigService(
        isAndroidOverride: true,
        mutationWaitTimeout: const Duration(milliseconds: 80),
        processRunner: runner,
      );
      final normalWaitService = ModuleConfigService(
        isAndroidOverride: true,
        mutationWaitTimeout: const Duration(seconds: 2),
        processRunner: runner,
      );

      // First request ('cn') times out waiting, while underlying 'cn' process continues running
      final firstRes = await fastTimeoutService.switchRunModeDetailed('cn');
      expect(firstRes.succeeded, isFalse);
      expect(firstRes.unconfirmed, isTrue);
      expect(firstRes.targetMode, 'cn');
      expect(firstRes.mode, 'cn');
      expect(executedModes, ['cn']);
      expect(activeCount, 1);

      // Second request ('overseas') submitted while 'cn' is still running in background -> must queue, NOT run concurrently
      final secondFuture = normalWaitService.switchRunModeDetailed('overseas');
      await Future<void>.delayed(const Duration(milliseconds: 40));
      expect(executedModes, ['cn']);
      expect(activeCount, 1);
      expect(maxConcurrent, 1);

      // Now finish underlying 'cn' -> 'overseas' starts
      completers[0].complete(
        ProcessResult(21, 0, 'AGH_SWITCH_RESULT status=ok stage=completed mode=cn\n', ''),
      );
      await Future<void>.delayed(const Duration(milliseconds: 30));
      expect(executedModes, ['cn', 'overseas']);
      expect(activeCount, 1);
      expect(maxConcurrent, 1);

      // Finish 'overseas'
      completers[1].complete(
        ProcessResult(22, 0, 'AGH_SWITCH_RESULT status=ok stage=completed mode=overseas\n', ''),
      );
      final secondRes = await secondFuture;
      expect(secondRes.succeeded, isTrue);
      expect(secondRes.unconfirmed, isFalse);
      expect(secondRes.targetMode, 'overseas');
      expect(secondRes.mode, 'overseas');
      expect(maxConcurrent, 1);
    });

    test('4. continuous A -> B -> A requests execute in exact order without collapsing second A into first A', () async {
      final executedModes = <String>[];
      final completers = <Completer<ProcessResult>>[];
      var finalMode = 'overseas';

      Future<ProcessResult> runner(String executable, List<String> arguments) async {
        final cmd = arguments.length >= 2 ? arguments[1] : '';
        if (cmd == 'id -u') {
          return ProcessResult(1, 0, '0\n', '');
        }
        final match = RegExp(r'switch_mode\.sh\s+(cn|overseas)').firstMatch(cmd);
        if (match != null) {
          final mode = match.group(1)!;
          executedModes.add(mode);
          final c = Completer<ProcessResult>();
          completers.add(c);
          final res = await c.future;
          finalMode = mode;
          return res;
        }
        return ProcessResult(2, 0, '', '');
      }

      final service = ModuleConfigService(
        isAndroidOverride: true,
        processRunner: runner,
      );

      final fA1 = service.switchRunModeDetailed('cn');
      await Future<void>.delayed(const Duration(milliseconds: 20));
      final fB = service.switchRunModeDetailed('overseas');
      final fA2 = service.switchRunModeDetailed('cn');
      await Future<void>.delayed(const Duration(milliseconds: 20));

      expect(executedModes, ['cn']);

      // Complete first A ('cn')
      completers[0].complete(
        ProcessResult(31, 0, 'AGH_SWITCH_RESULT status=ok stage=completed mode=cn\n', ''),
      );
      final rA1 = await fA1;
      expect(rA1.succeeded, isTrue);
      expect(rA1.targetMode, 'cn');

      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(executedModes, ['cn', 'overseas']);

      // Complete B ('overseas')
      completers[1].complete(
        ProcessResult(32, 0, 'AGH_SWITCH_RESULT status=ok stage=completed mode=overseas\n', ''),
      );
      final rB = await fB;
      expect(rB.succeeded, isTrue);
      expect(rB.targetMode, 'overseas');

      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(executedModes, ['cn', 'overseas', 'cn']);

      // Complete second A ('cn')
      completers[2].complete(
        ProcessResult(33, 0, 'AGH_SWITCH_RESULT status=ok stage=completed mode=cn\n', ''),
      );
      final rA2 = await fA2;
      expect(rA2.succeeded, isTrue);
      expect(rA2.targetMode, 'cn');
      expect(executedModes, ['cn', 'overseas', 'cn']);
      expect(finalMode, 'cn');
    });

    test('5. propagates op_id & queue wait duration and parses metadata fields from AGH_SWITCH_RESULT', () async {
      final capturedCmds = <String>[];
      final completers = <Completer<ProcessResult>>[];

      Future<ProcessResult> runner(String executable, List<String> arguments) async {
        final cmd = arguments.length >= 2 ? arguments[1] : '';
        if (cmd == 'id -u') {
          return ProcessResult(1, 0, '0\n', '');
        }
        if (cmd.contains('switch_mode.sh')) {
          capturedCmds.add(cmd);
          final c = Completer<ProcessResult>();
          completers.add(c);
          return c.future;
        }
        return ProcessResult(2, 0, '', '');
      }

      final service = ModuleConfigService(
        isAndroidOverride: true,
        processRunner: runner,
      );

      final fFirst = service.switchRunModeDetailed('cn');
      await Future<void>.delayed(const Duration(milliseconds: 35));
      final fSecond = service.switchRunModeDetailed('overseas');
      await Future<void>.delayed(const Duration(milliseconds: 60));

      expect(capturedCmds.length, 1);
      final firstOpMatch = RegExp(r'AGH_SWITCH_OP_ID=(mgr_[0-9]+)').firstMatch(capturedCmds[0]);
      final firstWaitMatch = RegExp(r'AGH_QUEUE_WAIT_MS=([0-9]+)').firstMatch(capturedCmds[0]);
      expect(firstOpMatch, isNotNull);
      expect(firstWaitMatch, isNotNull);

      completers[0].complete(
        ProcessResult(
          41,
          0,
          'AGH_SWITCH_RESULT status=ok stage=completed mode=cn op_id=${firstOpMatch!.group(1)} dns_port=55453 http_port=3000 total_ms=128\n',
          '',
        ),
      );
      final firstRes = await fFirst;
      expect(firstRes.succeeded, isTrue);
      expect(firstRes.opId, firstOpMatch.group(1));
      expect(firstRes.dnsPort, 55453);
      expect(firstRes.httpPort, 3000);
      expect(firstRes.totalMs, 128);
      expect(firstRes.scriptTotalMs, 128);
      expect(firstRes.managerQueueWaitMs, isNotNull);
      expect(firstRes.managerScriptWaitMs, greaterThanOrEqualTo(50));

      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(capturedCmds.length, 2);
      final secondWaitMatch = RegExp(r'AGH_QUEUE_WAIT_MS=([0-9]+)').firstMatch(capturedCmds[1]);
      expect(secondWaitMatch, isNotNull);
      expect(int.parse(secondWaitMatch!.group(1)!), greaterThanOrEqualTo(40));

      completers[1].complete(
        ProcessResult(
          42,
          0,
          'AGH_SWITCH_RESULT status=ok stage=completed mode=overseas op_id=custom_op dns_port=55453 http_port=3000 total_ms=unavailable\n',
          '',
        ),
      );
      final secondRes = await fSecond;
      expect(secondRes.succeeded, isTrue);
      expect(secondRes.opId, 'custom_op');
      expect(secondRes.httpPort, 3000);
      expect(secondRes.scriptTotalMs, isNull);
      expect(secondRes.managerQueueWaitMs, greaterThanOrEqualTo(40));
      expect(secondRes.managerScriptWaitMs, isNotNull);
    });
  });
}
