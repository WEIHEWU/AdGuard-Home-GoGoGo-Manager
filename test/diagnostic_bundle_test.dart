import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:adguard_home_manager/providers/app_config_provider.dart';
import 'package:adguard_home_manager/services/diagnostic_bundle_service.dart';
import 'package:adguard_home_manager/services/diagnostic_redactor.dart';
import 'package:adguard_home_manager/services/module_config_service.dart';
import 'package:adguard_home_manager/widgets/module_diagnostics_sheet.dart';

/// 简易 ZIP 解析校验器，直接解压每个条目做秘密字符串扫描
Map<String, String> _decodeZipEntries(List<int> zipBytes) {
  final result = <String, String>{};
  var offset = 0;
  while (offset + 30 <= zipBytes.length) {
    final sig = zipBytes[offset] |
        (zipBytes[offset + 1] << 8) |
        (zipBytes[offset + 2] << 16) |
        (zipBytes[offset + 3] << 24);
    if (sig != 0x04034B50) break;
    final method = zipBytes[offset + 8] | (zipBytes[offset + 9] << 8);
    final compSize = zipBytes[offset + 18] |
        (zipBytes[offset + 19] << 8) |
        (zipBytes[offset + 20] << 16) |
        (zipBytes[offset + 21] << 24);
    final nameLen = zipBytes[offset + 26] | (zipBytes[offset + 27] << 8);
    final extraLen = zipBytes[offset + 28] | (zipBytes[offset + 29] << 8);
    final nameStart = offset + 30;
    final dataStart = nameStart + nameLen + extraLen;
    final name = utf8.decode(zipBytes.sublist(nameStart, nameStart + nameLen));
    final compData = zipBytes.sublist(dataStart, dataStart + compSize);
    final raw = method == 8
        ? ZLibCodec(raw: true).decode(compData)
        : compData;
    result[name] = utf8.decode(raw);
    offset = dataStart + compSize;
  }
  return result;
}

void main() {
  setUp(() {
    ModuleConfigService.resetTestState();
    DiagnosticBundleService.resetTestState();
  });

  group('DiagnosticRedactor Tests (Requirement #9)', () {
    test('redacts malicious URLs, passwords, tokens, folded headers, IPs, MACs, IDs, packages while keeping whitelist', () {
      const sample = '''
2026-11-16 15:00:00 [INFO] Testing PROXY_URL="https://alice:SECRET_PASS_8899@sub.secretproxy.example:8443/api/v1/sub?token=MY_SECRET_TOKEN#frag"
2026-11-16 15:00:01 [INFO] JSON {"password": "JSON_PASSWORD_42", "api_key": "API_KEY_999"}
2026-11-16 15:00:02 [INFO] Authorization: Bearer SUPER_SECRET_BEARER_ABC
Cookie: session=COOKIE_VAL_42; csrf=CSRF_42
  folded_secret=FOLDED_VAL_42
2026-11-16 15:00:03 [INFO] hash=\$2a\$10\$abcdef1234567890SECRETTOKEN jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.SIG_PART_999
2026-11-16 15:00:04 [INFO] upstream=https://dns.google:443/custom-secret?k=1 and http://127.0.0.1:3000/control/login?pw=123
2026-11-16 15:00:05 [INFO] sdns://AgEAAAAAAAAABzguOC44Ljg vless://uuid@host.example:443?type=ws#node
2026-11-16 15:00:06 [INFO] client=192.168.50.88 wan=203.0.113.77 again=192.168.50.88 v6=2001:db8:85a3::8a2e:370:7334 mac=AA:BB:CC:DD:EE:FF
2026-11-16 15:00:07 [INFO] whitelist 127.0.0.1 198.18.0.0/15 8.8.8.8 ::1/128 fc00::/7
2026-11-16 15:00:08 [INFO] SSID="MyHomeWiFi_Secret" imei=359999000012345 android_id=a1b2c3d4e5f67890
2026-11-16 15:00:09 [INFO] path=/sdcard/Download/user_secret.txt data=/data/user/0/com.secret.bankapp/files/db app=com.thirdparty.vpn self=com.wu.adgogogo file=service.sh
''';
      final ctx = RedactionContext();
      final redacted = DiagnosticRedactor.redact(sample, context: ctx);

      // Zero raw secrets allowed
      for (final secret in const <String>[
        'SECRET_PASS_8899',
        'MY_SECRET_TOKEN',
        'sub.secretproxy.example',
        'JSON_PASSWORD_42',
        'API_KEY_999',
        'SUPER_SECRET_BEARER_ABC',
        'COOKIE_VAL_42',
        'FOLDED_VAL_42',
        'abcdef1234567890SECRETTOKEN',
        'SIG_PART_999',
        '/custom-secret',
        'AgEAAAAAAAAABzguOC44Ljg',
        '192.168.50.88',
        '203.0.113.77',
        '2001:db8:85a3::8a2e:370:7334',
        'AA:BB:CC:DD:EE:FF',
        'MyHomeWiFi_Secret',
        '359999000012345',
        'a1b2c3d4e5f67890',
        'user_secret.txt',
        'com.secret.bankapp',
        'com.thirdparty.vpn',
      ]) {
        expect(redacted, isNot(contains(secret)), reason: 'Leaked $secret');
      }

      // Consistent IP placeholders within same bundle + whitelists kept
      expect(redacted, contains('PROXY_URL=<REDACTED_PROXY_URL>'));
      expect(redacted, contains('https://dns.google:443/<REDACTED_PATH>'));
      expect(redacted, contains('http://127.0.0.1:3000/<REDACTED_PATH>'));
      expect(redacted, contains('127.0.0.1'));
      expect(redacted, contains('198.18.0.0/15'));
      expect(redacted, contains('8.8.8.8'));
      expect(redacted, contains('com.wu.adgogogo'));
      expect(redacted, contains('service.sh'));
      // Repeated IPv4 on same/later lines gets the exact same placeholder
      expect('<IP_2>'.allMatches(redacted).length, 2);
      expect(redacted, contains('<IP_1>'));
      expect(redacted, contains('<IP_3>'));
      expect(redacted, contains('<MAC_1>'));
    });

    test('redacts log-prefixed opaque Cookie/Authorization/X-API-Key headers, colon/equals & folded lines without Bearer/JWT', () {
      const prefixed = '''
2026-11-16 20:00:00 [ERROR] Cookie: opaque-cookie-value
[DEBUG] Authorization: opaque-auth-value
request failed: X-API-Key: opaque-key
  opaque-folded-cookie-continuation
2026-11-16 20:00:01 [WARN] auth_header X-Auth-Token=opaque-eq-token
''';
      final redacted = DiagnosticRedactor.redact(prefixed);
      for (final secret in const <String>[
        'opaque-cookie-value',
        'opaque-auth-value',
        'opaque-key',
        'opaque-folded-cookie-continuation',
        'opaque-eq-token',
      ]) {
        expect(redacted, isNot(contains(secret)), reason: 'Leaked $secret');
      }
      expect(redacted, contains('2026-11-16 20:00:00 [ERROR] Cookie: <REDACTED_SECRET>'));
      expect(redacted, contains('[DEBUG] Authorization: <REDACTED_SECRET>'));
      expect(redacted, contains('request failed: X-API-Key: <REDACTED_SECRET>'));
      expect(redacted, contains('<REDACTED_HEADER_CONTINUATION>'));
      expect(redacted, contains('<REDACTED_SECRET>'));
    });
  });

  group('DebugLogConfig Switch Tests (Requirements #1, #2, #3)', () {
    test('defaults to OFF, toggles without restarting core/iptables, enforces auto-expiry & strict parse', () async {
      final executedCmds = <String>[];
      var confOnDisk = '';

      Future<ProcessResult> runner(String exe, List<String> args) async {
        final cmd = args.length >= 2 ? args[1] : '';
        if (cmd == 'id -u') return ProcessResult(1, 0, '0\n', '');
        executedCmds.add(cmd);
        if (cmd.contains('cat /data/adb/agh/diag.conf')) {
          return ProcessResult(
            2,
            0,
            confOnDisk.isEmpty ? '__MISSING__\n' : confOnDisk,
            '',
          );
        }
        if (cmd.contains('agh_diag_write_conf')) {
          final m = RegExp(r'agh_diag_write_conf\s+([01])\s+([0-9]+)')
              .firstMatch(cmd);
          if (m != null) {
            confOnDisk =
                'debug_enabled=${m.group(1)}\ndebug_expire_epoch=${m.group(2)}\n';
          }
          return ProcessResult(3, 0, '', '');
        }
        return ProcessResult(4, 0, '', '');
      }

      final service = ModuleConfigService(
        isAndroidOverride: true,
        processRunner: runner,
      );

      // Missing -> OFF
      final initial = await service.readDebugLogConfig();
      expect(initial.enabled, isFalse);
      expect(initial.isActive, isFalse);

      // Turn ON with default 30m -> active & no core restart / firewall command executed
      final enabledCfg = await service.setDebugLogConfig(enabled: true);
      expect(enabledCfg, isNotNull);
      expect(enabledCfg!.enabled, isTrue);
      expect(enabledCfg.isActive, isTrue);
      expect(enabledCfg.remainingMinutesAt(DateTime.now()), inInclusiveRange(29, 31));
      for (final c in executedCmds) {
        expect(c, isNot(contains('service.sh')));
        expect(c, isNot(contains('iptables.sh')));
        expect(c, isNot(contains('switch_mode.sh')));
      }

      // Expired config fails closed
      confOnDisk = 'debug_enabled=1\ndebug_expire_epoch=100\n';
      final expiredCfg = await service.readDebugLogConfig();
      expect(expiredCfg.enabled, isFalse);
      expect(expiredCfg.isActive, isFalse);

      // Malformed config fails closed
      confOnDisk = 'debug_enabled=yes\nmalicious=\$(rm -rf /)\n';
      final badCfg = await service.readDebugLogConfig();
      expect(badCfg.enabled, isFalse);
      expect(badCfg.isActive, isFalse);
    });
  });

  group('DiagnosticBundleService Export, Lock-Timeout, Redaction & Cache Tests (Requirements #4-#11)', () {
    test('exports redacted zip during lock_timeout without acquiring/modifying locks or calling mutators, coalesces concurrent clicks, and prunes cache safely', () async {
      final tmpDir = await Directory.systemTemp.createTemp('agh_diag_test_');
      addTearDown(() async {
        if (await tmpDir.exists()) await tmpDir.delete(recursive: true);
      });

      final suCmds = <String>[];
      var lockDiagCalls = 0;

      Future<ProcessResult> runner(String exe, List<String> args) async {
        final cmd = args.length >= 2 ? args[1] : '';
        if (cmd == 'id -u') return ProcessResult(1, 0, '0\n', '');
        suCmds.add(cmd);

        if (cmd.contains('/data/adb/agh/agh.log')) {
          return ProcessResult(
            2,
            0,
            '''
=== /data/adb/agh/agh.log ===
2026-11-16 11:25:12 [WARN] switch_mode.sh: timed out waiting for operation lock
2026-11-16 11:25:13 [ERROR] password=FIXED_TEST_SECRET_PASS token=FIXED_TEST_TOKEN_XYZ url=https://bob:FIXED_URL_PASS@proxy.evil.example/sub?k=FIXED_QUERY
2026-11-16 11:25:14 [INFO] peer=192.168.123.45 mac=11:22:33:44:55:66
''',
            '',
          );
        }
        if (cmd.contains('core_crash.log')) {
          // Simulate hung command timeout on crash log!
          return ProcessResult(3, 124, '', 'command_timeout');
        }
        if (cmd.contains('filters_total_count')) {
          return ProcessResult(
            4,
            0,
            '''
=== module.prop ===
id=AdGuardHome
version=20261116.1
=== config.prop (allowed summary keys only) ===
RUN_MODE=overseas
redir_port=55453
ENABLE_SNI=1
VPN_DNS_TAKEOVER=auto
yaml_present=1 bytes=70430 sha256=deadbeef1234
filter file=1.txt bytes=1024 sha256=cafe0001
filters_total_count=1
''',
            '',
          );
        }
        if (cmd.contains('agh_op.pid')) {
          lockDiagCalls++;
          await Future<void>.delayed(const Duration(milliseconds: 25));
          return ProcessResult(
            5,
            0,
            '''
diag_pid_disclaimer=诊断PID仅作为排查线索，不能单独证明当前内核锁的真实持有者
state_file=/dev/shm/agh_op.pid value=9876
--- pid=9876 comm=switch_mode.sh ---
Name:	switch_mode.sh
State:	S (sleeping)
Pid:	9876
Gid:	0	0	0	0
  fd=9 -> /dev/shm/agh_op.flock
''',
            '',
          );
        }
        if (cmd.contains('--diag-flock')) {
          return ProcessResult(
            50,
            0,
            'AGH_FLOCK_DIAG script=service.sh status=PASS impl=toybox bin=/system/bin/toybox\n',
            '',
          );
        }
        if (cmd.contains('nat OUTPUT jumps')) {
          return ProcessResult(
            6,
            0,
            '''
ipv6_dns_mode=none
sni_fw_mode=connbytes
-A OUTPUT -j ADGUARD
-A ADGUARD -p udp -m udp --dport 53 -j REDIRECT --to-ports 55453
''',
            '',
          );
        }
        if (cmd.contains('/proc/meminfo')) {
          return ProcessResult(
            7,
            0,
            '''
uptime=1234.56 5000.00
MemTotal:        8000000 kB
MemAvailable:    4000000 kB
''',
            '',
          );
        }
        return ProcessResult(8, 0, '', '');
      }

      // Seed 3 pre-existing cached zip files + 1 expired file to verify retention limit <= 3 after export
      final oldExpired = File('${tmpDir.path}/agh_diag_20200101_000000_0001.zip');
      await oldExpired.writeAsBytes(const <int>[1, 2, 3]);
      await oldExpired.setLastModified(DateTime.now().subtract(const Duration(hours: 30)));
      for (var i = 1; i <= 3; i++) {
        final f = File('${tmpDir.path}/agh_diag_20261116_00000${i}_000$i.zip');
        await f.writeAsBytes(const <int>[1, 2, 3]);
        await f.setLastModified(DateTime.now().subtract(Duration(minutes: 10 - i)));
      }

      ModuleConfigService.recordOperation(ModuleOperationRecord(
        timestamp: DateTime.now(),
        type: 'mode_switch',
        opId: 'mgr_test_op',
        target: 'cn',
        stage: 'lock_timeout',
        exitCode: 1,
        succeeded: false,
      ));

      final modService = ModuleConfigService(
        isAndroidOverride: true,
        processRunner: runner,
      );
      var shareCount = 0;
      String? sharedPath;
      final bundleService = DiagnosticBundleService(
        moduleService: modService,
        cacheDirProvider: () async => tmpDir.path,
        shareInvoker: (filePath, title) async {
          shareCount++;
          sharedPath = filePath;
          return false; // simulate user cancelling share sheet
        },
      );

      // Simultaneous double-tap -> single-flight coalesced to 1 export!
      final f1 = bundleService.exportBundle();
      final f2 = bundleService.exportBundle();
      final results = await Future.wait([f1, f2]);
      expect(identical(results[0], results[1]), isTrue);
      expect(lockDiagCalls, 1);

      final res = results[0];
      final sampleOut = Platform.environment['AGH_SAMPLE_ZIP_OUT'];
      if (sampleOut != null && sampleOut.isNotEmpty) {
        await File(res.zipPath).copy(sampleOut);
      }
      expect(res.succeeded, isTrue);
      expect(res.partialSuccess, isTrue); // crash log timed out -> partial bundle still generated
      expect(res.zipBytes, lessThanOrEqualTo(DiagnosticBundleService.maxZipBytes));
      expect(File(res.zipPath).existsSync(), isTrue);

      // Verify zero lock-acquiring/mutating commands were issued during export
      for (final c in suCmds) {
        expect(c, isNot(contains('exec 9')));
        expect(c, isNot(contains('rm -')));
        expect(c, isNot(contains('flock -')));
        expect(c, isNot(contains('--repair')));
        expect(c, isNot(contains('--stop')));
        expect(c, isNot(contains('switch_mode.sh')));
        expect(c, isNot(contains('iptables.sh')));
        expect(c, isNot(contains('/environ')));
        expect(c, isNot(contains('querylog.json')));
      }

      // Unzip and verify NO secret leaked anywhere on disk / zip
      final zipBytes = await File(res.zipPath).readAsBytes();
      final decoded = _decodeZipEntries(zipBytes);
      expect(decoded.keys, containsAll(<String>[
        '00_README_AND_MANIFEST.txt',
        'manifest.json',
        '01_module_logs.txt',
        '02_core_crash_log.txt',
        '03_module_state_and_rules_digest.txt',
        '04_lock_diagnostics.txt',
        '04b_lock_flock_selfcheck.txt',
        '05_firewall_summary.txt',
        '06_resource_snapshot.txt',
        '07_manager_operations.txt',
      ]));

      final allContent = decoded.values.join('\n');
      for (final secret in const <String>[
        'FIXED_TEST_SECRET_PASS',
        'FIXED_TEST_TOKEN_XYZ',
        'FIXED_URL_PASS',
        'proxy.evil.example',
        'FIXED_QUERY',
        '192.168.123.45',
        '11:22:33:44:55:66',
      ]) {
        expect(allContent, isNot(contains(secret)));
      }
      expect(decoded['00_README_AND_MANIFEST.txt'],
          contains('已按默认规则脱敏，但仍请检查内容后再分享。'));
      expect(decoded['04_lock_diagnostics.txt'],
          contains('诊断PID仅作为排查线索'));
      expect(decoded['07_manager_operations.txt'], contains('lock_timeout'));

      // Cache retention kept <= 3 bundles and pruned expired
      expect(await oldExpired.exists(), isFalse);
      final cachedZips = tmpDir
          .listSync()
          .whereType<File>()
          .where((e) => e.path.endsWith('.zip'))
          .toList();
      expect(cachedZips.length, lessThanOrEqualTo(3));

      // Cancelling share must NOT delete ZIP file and must return cleanly
      final shared = await bundleService.shareBundle(res.zipPath);
      expect(shared, isFalse);
      expect(shareCount, 1);
      expect(sharedPath, res.zipPath);
      expect(await File(res.zipPath).exists(), isTrue);
    });

    test('handles missing logs, offline core, no root, and cancellation gracefully', () async {
      final tmpDir = await Directory.systemTemp.createTemp('agh_diag_noroot_');
      addTearDown(() async {
        if (await tmpDir.exists()) await tmpDir.delete(recursive: true);
      });

      Future<ProcessResult> noRootRunner(String exe, List<String> args) async {
        return ProcessResult(0, 1, '', 'su denied');
      }

      final modService = ModuleConfigService(
        isAndroidOverride: true,
        processRunner: noRootRunner,
      );
      final bundleService = DiagnosticBundleService(
        moduleService: modService,
        cacheDirProvider: () async => tmpDir.path,
      );

      final res = await bundleService.exportBundle();
      expect(res.succeeded, isTrue);
      expect(res.partialSuccess, isTrue);
      final decoded = _decodeZipEntries(await File(res.zipPath).readAsBytes());
      expect(decoded['01_module_logs.txt'], contains('无 Root 权限'));
      expect(decoded['manifest.json'], contains('"partial_success": true'));

      // Pre-cancelled token exits cleanly without writing bundle
      final cancelToken = DiagnosticCancelToken()..cancel();
      final cancelledRes =
          await bundleService.exportBundle(cancelToken: cancelToken);
      expect(cancelledRes.cancelled, isTrue);
      expect(cancelledRes.succeeded, isFalse);
    });

    test('preserves redacted partial stdout on timeout, isolates slow --diag-flock from fast lock snapshot, and scans all ZIP entries for fixed secrets', () async {
      final tmpDir = await Directory.systemTemp.createTemp('agh_diag_partial_');
      addTearDown(() async {
        if (await tmpDir.exists()) await tmpDir.delete(recursive: true);
      });

      Future<ProcessResult> runner(String exe, List<String> args) async {
        final cmd = args.length >= 2 ? args[1] : '';
        if (cmd == 'id -u') return ProcessResult(1, 0, '0\n', '');
        if (cmd.contains('/data/adb/agh/agh.log')) {
          return ProcessResult(
            2,
            0,
            '''
2026-11-16 20:00:00 [ERROR] Cookie: opaque-cookie-value
[DEBUG] Authorization: opaque-auth-value
request failed: X-API-Key: opaque-key
  opaque-continuation-val
''',
            '',
          );
        }
        if (cmd.contains('core_crash.log')) {
          // Simulates collector writing partial redacted-needed output before timing out
          return ProcessResult(
            3,
            124,
            'crash_line_before_hang=1\nrequest failed: X-API-Key: opaque-crash-key\n',
            'command_timeout',
          );
        }
        if (cmd.contains('agh_op.pid')) {
          return ProcessResult(
            4,
            0,
            'state_file=/dev/shm/agh_op.pid value=4321\n  fd=9 -> /dev/shm/agh_op.flock\n',
            '',
          );
        }
        if (cmd.contains('--diag-flock')) {
          // Simulates slow --diag-flock timing out after printing partial line
          return ProcessResult(
            5,
            124,
            'diag_step=starting_probe\n[DEBUG] Authorization: opaque-hang-auth\n',
            'command_timeout',
          );
        }
        if (cmd.contains('filters_total_count')) {
          throw StateError('thrown with Cookie: opaque-exception-cookie');
        }
        return ProcessResult(6, 0, 'ok\n', '');
      }

      final modService = ModuleConfigService(
        isAndroidOverride: true,
        processRunner: runner,
      );
      final bundleService = DiagnosticBundleService(
        moduleService: modService,
        cacheDirProvider: () async => tmpDir.path,
      );

      final res = await bundleService.exportBundle();
      expect(res.succeeded, isTrue);
      expect(res.partialSuccess, isTrue);

      final decoded = _decodeZipEntries(await File(res.zipPath).readAsBytes());
      // Fast lock snapshot succeeded with PID/FD while --diag-flock timed out cleanly
      expect(decoded['04_lock_diagnostics.txt'], contains('value=4321'));
      expect(decoded['04_lock_diagnostics.txt'], contains('fd=9 -> /dev/shm/agh_op.flock'));
      expect(decoded['04b_lock_flock_selfcheck.txt'], contains('采集超时，以下为部分输出'));
      expect(decoded['04b_lock_flock_selfcheck.txt'], contains('diag_step=starting_probe'));
      expect(decoded['02_core_crash_log.txt'], contains('采集超时，以下为部分输出'));
      expect(decoded['02_core_crash_log.txt'], contains('crash_line_before_hang=1'));

      final manifest = jsonDecode(decoded['manifest.json']!) as Map<String, dynamic>;
      expect(manifest['partial_success'], isTrue);
      final items = (manifest['items'] as List).cast<Map<String, dynamic>>();
      final fastLock = items.firstWhere((e) => e['key'] == 'lock_diagnostics');
      final slowFlock = items.firstWhere((e) => e['key'] == 'lock_flock_selfcheck');
      final crashItem = items.firstWhere((e) => e['key'] == 'core_crash_log');
      expect(fastLock['status'], 'ok');
      expect(slowFlock['status'], 'timeout');
      expect(crashItem['status'], 'timeout');

      final combinedText = '${decoded.values.join('\n')}\n${res.previewText}\n${res.summaryText}';
      for (final secret in const <String>[
        'opaque-cookie-value',
        'opaque-auth-value',
        'opaque-key',
        'opaque-continuation-val',
        'opaque-crash-key',
        'opaque-hang-auth',
        'opaque-exception-cookie',
      ]) {
        expect(combinedText, isNot(contains(secret)), reason: 'Secret leaked: $secret');
      }
    });

    test('real OS subprocess timeout captures pre-hang stdout, kills & reaps child cleanly, cancels streams, and enforces monotonic total budget across hasRoot', () async {
      final modService = ModuleConfigService(
        isAndroidOverride: true,
        probeCandidateRunner: (_, __) async => ProcessResult(0, 0, '0\n', ''),
        processStarter: (_, args) => Process.start('/bin/sh', args),
      );

      final sw = Stopwatch()..start();
      // Print partial line, ignore TERM briefly or sleep 5s -> real OS timeout must kill child & cancel streams
      final procRes = await modService.runSuTimed(
        'echo REAL_CHILD_PARTIAL_OUT; exec sleep 5',
        timeout: const Duration(milliseconds: 250),
      );
      sw.stop();

      expect(procRes.exitCode, 124);
      expect(procRes.stdout.toString(), contains('REAL_CHILD_PARTIAL_OUT'));
      expect(procRes.stderr.toString(), 'command_timeout');
      expect(sw.elapsedMilliseconds, lessThan(2000));

      // Verify monotonic total budget spans hasRoot() + steps
      final tmpDir = await Directory.systemTemp.createTemp('agh_diag_budget_');
      addTearDown(() async {
        if (await tmpDir.exists()) await tmpDir.delete(recursive: true);
      });
      ModuleConfigService.resetTestState();
      final slowRootService = ModuleConfigService(
        isAndroidOverride: true,
        probeCandidateRunner: (_, __) async {
          await Future<void>.delayed(const Duration(milliseconds: 600));
          return ProcessResult(0, 0, '0\n', '');
        },
        processStarter: (_, args) => Process.start('/bin/sh', args),
      );
      final budgetBundleService = DiagnosticBundleService(
        moduleService: slowRootService,
        cacheDirProvider: () async => tmpDir.path,
        totalBudget: const Duration(milliseconds: 500),
        itemTimeout: const Duration(milliseconds: 200),
      );
      final budgetRes = await budgetBundleService.exportBundle();
      expect(budgetRes.succeeded, isTrue);
      expect(budgetRes.partialSuccess, isTrue);
      final decoded = _decodeZipEntries(await File(budgetRes.zipPath).readAsBytes());
      expect(decoded['01_module_logs.txt'], contains('已超过总采集预算'));
      expect(decoded['manifest.json'], contains('超出总时间预算'));
    });

    testWidgets('UI export dialog disables button while generating, handles cancel/dispose safely, and previews & shares', (WidgetTester tester) async {
      final tmpDir = Directory.systemTemp.createTempSync('agh_diag_ui_');
      addTearDown(() {
        if (tmpDir.existsSync()) tmpDir.deleteSync(recursive: true);
      });

      late _StubUiDiagService stubService;
      stubService = _StubUiDiagService(
        zipPath: '${tmpDir.path}/agh_diag_ui.zip',
      );

      SharedPreferences.setMockInitialValues(<String, Object>{});
      final prefs = await SharedPreferences.getInstance();

      await tester.pumpWidget(
        ChangeNotifierProvider<AppConfigProvider>(
          create: (_) => AppConfigProvider(sharedPreferencesInstance: prefs),
          child: MaterialApp(
            home: Builder(
              builder: (ctx) => Scaffold(
                body: Center(
                  child: ElevatedButton(
                    onPressed: () => showDiagnosticExportFlow(
                      ctx,
                      isZhOverride: true,
                      bundleService: stubService,
                    ),
                    child: const Text('Open'),
                  ),
                ),
              ),
            ),
          ),
        ),
      );

      // 1) Normal generate -> disabled state while pending -> preview -> share -> close
      await tester.tap(find.text('Open'));
      await tester.pumpAndSettle();
      expect(find.text('导出诊断包'), findsOneWidget);
      expect(find.text('生成诊断包'), findsOneWidget);

      await tester.tap(find.text('生成诊断包'));
      await tester.pump();
      expect(find.text('生成中…'), findsOneWidget);

      stubService.completeCurrent(DiagnosticBundleResult(
        succeeded: true,
        zipPath: stubService.zipPath,
        fileName: 'agh_diag_ui.zip',
        zipBytes: 2048,
        bundleId: 'diag_ui_1',
        generatedAtUtc: DateTime.now().toUtc(),
        previewText: 'preview ok',
        summaryText: 'summary ok',
      ));
      await tester.pumpAndSettle();
      expect(find.text('已按默认规则脱敏，但仍请检查内容后再分享。'), findsOneWidget);
      expect(find.text('分享'), findsOneWidget);

      await tester.tap(find.text('分享'));
      await tester.pumpAndSettle();
      expect(stubService.shareCalls, 1);

      await tester.tap(find.text('关闭'));
      await tester.pumpAndSettle();

      // 2) Cancel mid-export does not throw or update disposed state
      await tester.tap(find.text('Open'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('生成诊断包'));
      await tester.pump();
      await tester.tap(find.text('取消'));
      await tester.pumpAndSettle();
      expect(stubService.lastToken?.isCancelled, isTrue);
      stubService.completeCurrent(DiagnosticBundleResult(
        succeeded: false,
        cancelled: true,
        generatedAtUtc: DateTime.now().toUtc(),
      ));
      await tester.pumpAndSettle();
    });
  });
}

class _StubUiDiagService extends DiagnosticBundleService {
  final String zipPath;
  int shareCalls = 0;
  DiagnosticCancelToken? lastToken;
  Completer<DiagnosticBundleResult>? _pending;

  _StubUiDiagService({required this.zipPath});

  @override
  Future<DiagnosticBundleResult> exportBundle({
    DiagnosticCancelToken? cancelToken,
    String appVersion = '2.24.20',
  }) {
    lastToken = cancelToken;
    _pending = Completer<DiagnosticBundleResult>();
    return _pending!.future;
  }

  void completeCurrent(DiagnosticBundleResult res) {
    final c = _pending;
    if (c != null && !c.isCompleted) {
      c.complete(res);
    }
  }

  @override
  Future<bool> shareBundle(
    String zipPath, {
    String title = '分享 AdGuard Home GoGoGo 诊断包',
  }) async {
    shareCalls++;
    return false;
  }
}
