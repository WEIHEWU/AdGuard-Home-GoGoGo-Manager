import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:adguard_home_manager/constants/enums.dart';
import 'package:adguard_home_manager/l10n/app_localizations.dart';
import 'package:adguard_home_manager/models/dns_statistics.dart';
import 'package:adguard_home_manager/models/filtering_status.dart' as fs;
import 'package:adguard_home_manager/models/logs.dart';
import 'package:adguard_home_manager/models/server.dart';
import 'package:adguard_home_manager/models/server_status.dart';
import 'package:adguard_home_manager/providers/app_config_provider.dart';
import 'package:adguard_home_manager/providers/filtering_provider.dart';
import 'package:adguard_home_manager/providers/servers_provider.dart';
import 'package:adguard_home_manager/providers/status_provider.dart';
import 'package:adguard_home_manager/screens/filters/custom_rules_list.dart';
import 'package:adguard_home_manager/screens/filters/my_manual_rules_screen.dart';
import 'package:adguard_home_manager/screens/logs/log_tile.dart';
import 'package:adguard_home_manager/services/api_client.dart';
import 'package:adguard_home_manager/services/diagnostic_bundle_service.dart';
import 'package:adguard_home_manager/services/domain_input_parser.dart';
import 'package:adguard_home_manager/services/host_rule_diagnostics.dart';
import 'package:adguard_home_manager/services/manual_rule_provenance_service.dart';
import 'package:adguard_home_manager/services/module_config_service.dart';
import 'package:adguard_home_manager/widgets/troubleshooter_rule_panel.dart';

class _PassthroughHttpOverrides extends HttpOverrides {}

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
    final raw = method == 8 ? ZLibCodec(raw: true).decode(compData) : compData;
    result[name] = utf8.decode(raw);
    offset = dataStart + compSize;
  }
  return result;
}

class _MockCoreEnv {
  final List<String> rules;
  String coreInstance = 'inst1';
  int epoch = 1;
  bool failNextSetRules = false;
  bool forceConflictNextSetRules = false;
  bool failNextReadbackAfterSet = false;
  bool omitRevision = false;
  void Function()? onAfterSetRulesBeforeReadback;
  bool _failNextGetStatusArmed = false;
  int setRulesPostCount = 0;
  int getStatusCount = 0;
  Map<String, dynamic> Function(String host, String qtype)? checkHostHandler;

  late final HttpServer _server;
  late final Server serverModel;
  late final ApiClientV2 apiClient;

  _MockCoreEnv._(this.rules);

  String currentRev() => 'v2:$coreInstance:$epoch';

  static Future<_MockCoreEnv> start({
    List<String> initialRules = const [],
    String serverId = 'srv-test',
  }) async {
    final env = _MockCoreEnv._(List<String>.from(initialRules));
    env._server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    env.serverModel = Server(
      id: serverId,
      name: 'MockCore',
      connectionMethod: 'http',
      domain: '127.0.0.1',
      port: env._server.port,
      user: 'admin',
      password: 'SECRET_PASSWORD_DO_NOT_LEAK',
      authToken: 'SECRET_AUTH_TOKEN_DO_NOT_LEAK',
      defaultServer: true,
      runningOnHa: false,
    );
    env.apiClient = ApiClientV2(server: env.serverModel);

    env._server.listen((req) async {
      final path = req.uri.path;
      if (path == '/control/filtering/status') {
        env.getStatusCount++;
        if (env._failNextGetStatusArmed) {
          env._failNextGetStatusArmed = false;
          req.response
            ..statusCode = 500
            ..write('readback error');
        } else {
          req.response
            ..statusCode = 200
            ..headers.contentType = ContentType.json
            ..write(jsonEncode({
              'filters': [
                {
                  'id': 1,
                  'name': 'Anti-AD',
                  'url': 'https://anti-ad.net/adguard.txt',
                  'rules_count': 1000,
                  'enabled': true,
                },
              ],
              'whitelist_filters': [
                {
                  'id': 2,
                  'name': 'Module-Allowlist',
                  'url': 'https://example.invalid/allow.txt',
                  'rules_count': 50,
                  'enabled': true,
                },
              ],
              'user_rules': env.rules,
              if (!env.omitRevision) 'user_rules_revision': env.currentRev(),
              'interval': 24,
              'enabled': true,
            }));
        }
      } else if (path == '/control/filtering/set_rules') {
        env.setRulesPostCount++;
        if (env.failNextSetRules) {
          env.failNextSetRules = false;
          req.response
            ..statusCode = 500
            ..write('set_rules failed');
        } else {
          final raw = await utf8.decoder.bind(req).join();
          final body = jsonDecode(raw) as Map<String, dynamic>;
          final exp = body['expected_revision']?.toString();
          if (env.forceConflictNextSetRules ||
              (exp != null && exp.isNotEmpty && exp != env.currentRev())) {
            env.forceConflictNextSetRules = false;
            req.response
              ..statusCode = 409
              ..write('conflict');
          } else {
            env.rules
              ..clear()
              ..addAll((body['rules'] as List).map((e) => e.toString()));
            env.epoch++;
            final committedRev = env.currentRev();
            if (env.onAfterSetRulesBeforeReadback != null) {
              final cb = env.onAfterSetRulesBeforeReadback!;
              env.onAfterSetRulesBeforeReadback = null;
              cb();
            }
            if (env.failNextReadbackAfterSet) {
              env.failNextReadbackAfterSet = false;
              env._failNextGetStatusArmed = true;
            }
            req.response.statusCode = 200;
            if (!env.omitRevision) {
              req.response.headers.set('X-User-Rules-Revision', committedRev);
            }
          }
        }
      } else if (path == '/control/filtering/check_host') {
        final host = req.uri.queryParameters['name'] ?? '';
        final qtype = req.uri.queryParameters['qtype'] ?? 'A';
        final resp = env.checkHostHandler != null
            ? env.checkHostHandler!(host, qtype)
            : <String, dynamic>{
                'reason': 'NotFilteredWhiteList',
                'rules': <dynamic>[],
              };
        req.response
          ..statusCode = 200
          ..headers.contentType = ContentType.json
          ..write(jsonEncode(resp));
      } else if (path == '/control/cache_clear') {
        req.response.statusCode = 200;
      } else {
        req.response.statusCode = 404;
      }
      await req.response.close();
    });
    return env;
  }

  Future<void> close() => _server.close(force: true);
}

ServerStatus _makeDummyServerStatus(List<String> rules) {
  return ServerStatus(
    stats: DnsStatistics(
      timeUnits: 'hours',
      topQueriedDomains: const [],
      topBlockedDomains: const [],
      topUpstreamResponses: null,
      topUpstreamsAvgTime: null,
      dnsQueries: const [],
      blockedFiltering: const [],
      numDnsQueries: 0,
      numBlockedFiltering: 0,
      avgProcessingTime: 0,
    ),
    filteringStatus: fs.FilteringStatus(
      enabled: true,
      interval: 24,
      filters: const [],
      whitelistFilters: const [],
      userRules: rules,
    ),
    timeGeneralDisabled: 0,
    generalEnabled: true,
    filteringEnabled: true,
    safeBrowsingEnabled: false,
    parentalControlEnabled: false,
    serverVersion: '0.107.0',
    dhcpAvailable: false,
  );
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    ServerRuleWriteQueue.resetForTest();
    ModuleConfigService.resetTestState();
    DiagnosticBundleService.resetTestState();
    ManualRuleProvenanceService.resetInstanceForTest();
  });

  group('Manual Rule Provenance Service & Entrypoints', () {
    test('1 & 2. Records manual rules across all 4 entrypoints only after Core readback confirm; skips on Core fail / readback fail / 409 / pre-existing', () async {
      await HttpOverrides.runWithHttpOverrides(() async {
        final env = await _MockCoreEnv.start(
          initialRules: ['@@||preexisting.example.org^'],
        );
        addTearDown(env.close);

        final backend = InMemoryManualRuleProvenanceStoreBackend();
        final prov = ManualRuleProvenanceService(
          backend: backend,
          nowProvider: () => DateTime.utc(2026, 11, 17, 9, 0, 0),
        );
        ManualRuleProvenanceService.setInstanceForTest(prov);

        final serversProvider = ServersProvider()
          ..setSelectedServer(env.serverModel)
          ..setApiClient2(env.apiClient);
        final filteringProvider = FilteringProvider(provenanceService: prov)
          ..update(serversProvider, null);
        final statusProvider = StatusProvider(provenanceService: prov)
          ..update(serversProvider)
          ..setServerStatusData(data: _makeDummyServerStatus(env.rules));

        final srvKey = ServerRuleWriteQueue.serverKeyFor(env.serverModel);

        // A) Pre-existing rule in Core MUST NOT get recorded or undo token
        final coord = ExceptionRuleCoordinator();
        final preOutcome = await coord.applyExceptionAndVerify(
          apiClient: env.apiClient,
          verifyHost: 'preexisting.example.org',
          exceptionRule: '@@||preexisting.example.org^',
          provenanceService: prov,
        );
        expect(preOutcome.writeSucceeded, isTrue);
        expect(preOutcome.undoToken, isNull);
        expect(prov.findRecordsForRule(srvKey, '@@||preexisting.example.org^'), isEmpty);

        // B) Core commit fails -> zero provenance record
        env.failNextSetRules = true;
        final failRes = await filteringProvider.addCustomRuleDetailed(
          '||blocked.fail.example^',
        );
        expect(failRes.ok, isFalse);
        expect(prov.findRecordsForRule(srvKey, '||blocked.fail.example^'), isEmpty);

        // C) Core commit succeeds, readback fails -> NO confirmed provenance record written
        env.failNextReadbackAfterSet = true;
        final rbFailRes = await filteringProvider.addCustomRuleDetailed(
          '||readback.fail.example^',
        );
        expect(rbFailRes.ok, isTrue);
        expect(rbFailRes.readbackFailed, isTrue);
        expect(prov.findRecordsForRule(srvKey, '||readback.fail.example^'), isEmpty);

        // D) 409 conflict -> NO provenance record written
        env.forceConflictNextSetRules = true;
        final conflictRes = await filteringProvider.addCustomRuleDetailed(
          '||conflict.example^',
        );
        expect(conflictRes.ok, isFalse);
        expect(conflictRes.conflictDetected, isTrue);
        expect(prov.findRecordsForRule(srvKey, '||conflict.example^'), isEmpty);

        // E) Succeed via all 4 entrypoints for generic non-SendGrid domains & rules
        final tpOutcome = await coord.applyExceptionAndVerify(
          apiClient: env.apiClient,
          verifyHost: 'api.github.com',
          exceptionRule: '@@||api.github.com^',
          entryPoint: '误杀排错',
          provenanceService: prov,
        );
        expect(tpOutcome.writeSucceeded, isTrue);
        expect(tpOutcome.undoToken, isNotNull);

        final addRes = await filteringProvider.addCustomRuleDetailed(
          '||ads.example.net^\$important',
          entryPoint: '自定义规则-单条添加',
        );
        expect(addRes.ok, isTrue);

        // Bulk edit: add a complex rule and remove nothing -> unchanged pre-existing stays unrecorded!
        final bulkRes = await filteringProvider.setCustomRulesDetailed(
          [
            ...env.rules,
            '@@||custom.example.org^\$dnsrewrite=1.2.3.4',
            '! user note comment',
          ],
          entryPoint: '自定义规则-批量编辑',
        );
        expect(bulkRes.ok, isTrue);

        final logRes = await statusProvider.blockUnblockDomainDetailed(
          domain: 'tracker.example.net',
          newStatus: 'block',
          entryPoint: '日志详情',
        );
        expect(logRes.ok, isTrue);

        // Pre-existing rule MUST STILL be unrecorded
        expect(prov.findRecordsForRule(srvKey, '@@||preexisting.example.org^'), isEmpty);

        // Verify all 4 newly added entries recorded accurately with entry points & action
        final r1 = prov.findRecordsForRule(srvKey, '@@||api.github.com^').single;
        expect(r1.action, ManualRuleAction.allow);
        expect(r1.entryPoint, '误杀排错');
        expect(r1.primaryLabel, '手动放行');

        final r2 = prov.findRecordsForRule(srvKey, '||ads.example.net^\$important').single;
        expect(r2.action, ManualRuleAction.block);
        expect(r2.entryPoint, '自定义规则-单条添加');
        expect(r2.primaryLabel, '手动拦截');

        final r3 = prov
            .findRecordsForRule(srvKey, '@@||custom.example.org^\$dnsrewrite=1.2.3.4')
            .single;
        expect(r3.action, ManualRuleAction.other);
        expect(r3.entryPoint, '自定义规则-批量编辑');
        expect(r3.primaryLabel, '手动规则');

        final r4 = prov.findRecordsForRule(srvKey, '||tracker.example.net^\$important').single;
        expect(r4.action, ManualRuleAction.block);
        expect(r4.entryPoint, '日志详情');
        expect(r4.primaryLabel, '手动拦截');
      }, _PassthroughHttpOverrides());
    });

    test('3, 4, 5, 6. Classification, subscription vs custom vs unrecorded separation, exact rule identity, and coexistence hint', () async {
      final prov = ManualRuleProvenanceService(
        backend: InMemoryManualRuleProvenanceStoreBackend(),
      );

      // All rule kinds classified safely
      final cAllow = RuleClassification.classify('@@||sub.example.com^');
      expect(cAllow.action, ManualRuleAction.allow);
      expect(cAllow.extractableHost, 'sub.example.com');
      expect(cAllow.isCheckHostTestable, isTrue);

      final cAllowImp = RuleClassification.classify('@@||sub.example.com^\$important');
      expect(cAllowImp.action, ManualRuleAction.allow);
      expect(cAllowImp.isImportant, isTrue);

      final cBlock = RuleClassification.classify('||ads.example.org^');
      expect(cBlock.action, ManualRuleAction.block);
      expect(cBlock.extractableHost, 'ads.example.org');

      for (final complex in [
        '@@||example.org^\$dnsrewrite=NOERROR',
        '*example.org*\$script',
        '/^ad[0-9]+\\.example\\.net\$/',
        '0.0.0.0 bad.example',
        '! comment rule',
      ]) {
        final cls = RuleClassification.classify(complex);
        expect(cls.action, ManualRuleAction.other, reason: complex);
        expect(cls.isCheckHostTestable, isFalse, reason: complex);
      }

      // Subscription whitelist rule (`filter_list_id == 2`) NEVER gets mislabeled manual, even with @@
      final subOnlyDisp = prov.resolveMatchedRuleDisplay(
        serverKey: 'srvA',
        ruleText: '@@||partner.example.com^',
        filterListId: 2,
        subscriptionDisplayName: 'Module-Allowlist',
      );
      expect(subOnlyDisp.label, 'Module-Allowlist');
      expect(subOnlyDisp.isSubscriptionOrigin, isTrue);
      expect(subOnlyDisp.isManualOrigin, isFalse);
      expect(subOnlyDisp.secondaryHint, isNull);

      // Custom unrecorded rule (e.g. module preset or web-console rule) stays "来源未记录", NEVER guessed by @@ prefix
      final unrecordedCustom = prov.resolveCustomListRowDisplay(
        serverKey: 'srvA',
        rawRule: '@@||preset.example.com^',
      );
      expect(unrecordedCustom.label, '来源未记录');
      expect(unrecordedCustom.isUnrecordedCustom, isTrue);
      expect(unrecordedCustom.isManualOrigin, isFalse);

      await prov.recordManualAdditions(
        serverKey: 'srvA',
        addedRules: ['@@||shared.example.com^'],
        entryPoint: '误杀排错',
      );

      final exactMatch = prov.resolveCustomListRowDisplay(
        serverKey: 'srvA',
        rawRule: '@@||shared.example.com^',
      );
      expect(exactMatch.label, '手动放行');

      // Adding $important variant does NOT match plain rule provenance
      final impVariant = prov.resolveCustomListRowDisplay(
        serverKey: 'srvA',
        rawRule: '@@||shared.example.com^\$important',
      );
      expect(impVariant.label, '来源未记录');

      // Same rule text matched from subscription list + also present in manual store -> secondary hint!
      final coexistDisp = prov.resolveMatchedRuleDisplay(
        serverKey: 'srvA',
        ruleText: '@@||shared.example.com^',
        filterListId: 2,
        subscriptionDisplayName: 'Module-Allowlist',
      );
      expect(coexistDisp.label, 'Module-Allowlist');
      expect(coexistDisp.secondaryHint, '同时存在相同手动规则');
    });

    test('7 & 8. Restart persistence, server isolation, backup export/import (no credentials), write failure tolerance & corrupt JSON graceful degradation', () async {
      final tmpDir = await Directory.systemTemp.createTemp('agh_prov_test_');
      addTearDown(() async {
        if (await tmpDir.exists()) {
          await tmpDir.delete(recursive: true);
        }
      });

      final fileBackend = FileManualRuleProvenanceStoreBackend(
        directoryResolver: () async => tmpDir,
      );
      final srvA = Server(
        id: 'srvA',
        name: 'A',
        connectionMethod: 'http',
        domain: '127.0.0.1',
        port: 3001,
        user: 'admin',
        password: 'TOP_SECRET_PASSWORD_A',
        authToken: 'TOP_SECRET_TOKEN_A',
        defaultServer: true,
        runningOnHa: false,
      );
      final srvB = Server(
        id: 'srvB',
        name: 'B',
        connectionMethod: 'http',
        domain: '127.0.0.1',
        port: 3002,
        user: 'admin',
        password: 'TOP_SECRET_PASSWORD_B',
        defaultServer: false,
        runningOnHa: false,
      );
      final keyA = ServerRuleWriteQueue.serverKeyFor(srvA);
      final keyB = ServerRuleWriteQueue.serverKeyFor(srvB);

      final prov1 = ManualRuleProvenanceService(backend: fileBackend);
      await prov1.recordManualAdditions(
        serverKey: keyA,
        addedRules: ['@@||alpha.example^'],
        entryPoint: '误杀排错',
        note: 'Mail tracking fix',
      );
      await prov1.recordManualAdditions(
        serverKey: keyB,
        addedRules: ['||beta.example^'],
        entryPoint: '日志详情',
      );

      // Fresh service reading from disk after restart
      final provRestarted = ManualRuleProvenanceService(
        backend: FileManualRuleProvenanceStoreBackend(
          directoryResolver: () async => tmpDir,
        ),
      );
      await provRestarted.ensureLoaded();
      expect(provRestarted.recordsForServer(keyA).single.ruleText, '@@||alpha.example^');
      expect(provRestarted.recordsForServer(keyA).single.note, 'Mail tracking fix');
      expect(provRestarted.recordsForServer(keyB).single.ruleText, '||beta.example^');

      // Export backup JSON contains NO passwords/tokens
      final backupJson = await provRestarted.exportBackupJson();
      expect(backupJson, isNot(contains('TOP_SECRET_PASSWORD_A')));
      expect(backupJson, isNot(contains('TOP_SECRET_TOKEN_A')));
      expect(backupJson, isNot(contains('TOP_SECRET_PASSWORD_B')));

      // Corrupt disk file -> degrades cleanly to 来源未确认, never throws or alters Core rules
      final storeFile = File('${tmpDir.path}/${FileManualRuleProvenanceStoreBackend.defaultFileName}');
      await storeFile.writeAsString('{corrupted json!!!');

      final provCorrupted = ManualRuleProvenanceService(
        backend: FileManualRuleProvenanceStoreBackend(
          directoryResolver: () async => tmpDir,
        ),
      );
      await provCorrupted.ensureLoaded();
      expect(provCorrupted.hasStorageError, isTrue);
      final degradedDisp = provCorrupted.resolveCustomListRowDisplay(
        serverKey: keyA,
        rawRule: '@@||alpha.example^',
      );
      expect(degradedDisp.label, '来源未确认');

      // Valid backup import recovers without touching Core! Invalid schema throws FormatException safely.
      expect(
        () => provCorrupted.importBackupJson(
          '{"schema_version": 999}',
          overwriteStorageIfCorrupted: true,
        ),
        throwsFormatException,
      );
      final impRes = await provCorrupted.importBackupJson(
        backupJson,
        overwriteStorageIfCorrupted: true,
      );
      expect(impRes.importedCount, 2);
      expect(provCorrupted.hasStorageError, isFalse);
      final importedAlphaDisp = provCorrupted.resolveCustomListRowDisplay(
        serverKey: keyA,
        rawRule: '@@||alpha.example^',
      );
      // 导入备份默认降为“来源待确认”（不直接恢复成“已确认”），同时保留历史来源、时间与备注
      expect(importedAlphaDisp.label, '来源待确认');
      expect(importedAlphaDisp.record!.historicalActionLabel, '手动放行');
      expect(importedAlphaDisp.record!.note, 'Mail tracking fix');

      // Write failure on provenance store does NOT roll back Core rule!
      await HttpOverrides.runWithHttpOverrides(() async {
        final env = await _MockCoreEnv.start();
        addTearDown(env.close);
        final memFail = InMemoryManualRuleProvenanceStoreBackend()..failNextWrite = true;
        final provWriteFail = ManualRuleProvenanceService(backend: memFail);
        final coord = ExceptionRuleCoordinator();

        final out = await coord.applyExceptionAndVerify(
          apiClient: env.apiClient,
          verifyHost: 'writefail.example.org',
          exceptionRule: '@@||writefail.example.org^',
          provenanceService: provWriteFail,
        );
        expect(out.writeSucceeded, isTrue);
        expect(out.provenanceSaveFailed, isTrue);
        expect(out.message, contains('规则已添加，但来源记录保存失败。'));
        expect(env.rules, contains('@@||writefail.example.org^'));
      }, _PassthroughHttpOverrides());
    });

    test('9. External delete -> missing -> external re-add -> unconfirmed; explicit claim sets claimedAt & null createdAt', () async {
      final prov = ManualRuleProvenanceService(
        backend: InMemoryManualRuleProvenanceStoreBackend(),
        nowProvider: () => DateTime.utc(2026, 11, 17, 10, 0, 0),
      );
      await prov.recordManualAdditions(
        serverKey: 'srv1',
        addedRules: ['@@||ext.example.com^'],
        entryPoint: '误杀排错',
      );

      // External delete
      await prov.syncWithCoreRules(serverKey: 'srv1', coreRules: []);
      expect(
        prov.findRecordsForRule('srv1', '@@||ext.example.com^').single.syncStatus,
        ManualRuleSyncStatus.missing,
      );

      // Re-appears externally -> MUST become unconfirmed ("来源待确认")
      await prov.syncWithCoreRules(
        serverKey: 'srv1',
        coreRules: ['@@||ext.example.com^'],
        currentRevision: 'v2:inst1:2',
      );
      final recAfterReadd = prov.findRecordsForRule('srv1', '@@||ext.example.com^').single;
      expect(recAfterReadd.syncStatus, ManualRuleSyncStatus.unconfirmed);
      expect(recAfterReadd.primaryLabel, '来源待确认');
      expect(recAfterReadd.historicalOriginLabel, '手动新增');
      expect(recAfterReadd.associationStatusLabel, '待确认');

      // Existing legacy/external unrecorded rule claimed explicitly by user
      final claimedOk = await prov.claimExistingRule(
        serverKey: 'srv1',
        ruleText: '||legacy.example.com^',
        latestCoreRules: ['@@||ext.example.com^', '||legacy.example.com^'],
        confirmedRevision: 'v2:inst1:2',
        note: 'Legacy rule claimed by me',
      );
      expect(claimedOk, isTrue);
      final claimedRec = prov.findRecordsForRule('srv1', '||legacy.example.com^').single;
      expect(claimedRec.source, ManualRuleSource.claimed);
      expect(claimedRec.createdAt, isNull);
      expect(claimedRec.claimedAt, isNotNull);
      expect(claimedRec.primaryLabel, '用户认领');
      expect(claimedRec.syncStatus, ManualRuleSyncStatus.present);
    });

    test('11, 12, 13. Remove metadata only preserves Core; remove rule checks duplicates & expected_revision; ExceptionUndoToken remains strict', () async {
      await HttpOverrides.runWithHttpOverrides(() async {
        final env = await _MockCoreEnv.start(
          initialRules: ['||dup.example^', '||dup.example^', '||single.example^'],
        );
        addTearDown(env.close);

        final prov = ManualRuleProvenanceService(
          backend: InMemoryManualRuleProvenanceStoreBackend(),
        );
        final srvProvider = ServersProvider()
          ..setSelectedServer(env.serverModel)
          ..setApiClient2(env.apiClient);
        final fp = FilteringProvider(provenanceService: prov)
          ..update(srvProvider, null);
        await fp.fetchFilters();
        final srvKey = ServerRuleWriteQueue.serverKeyFor(env.serverModel);

        await fp.claimExistingCustomRule('||single.example^');
        await fp.claimExistingCustomRule('||dup.example^');
        expect(
          prov.resolveCustomListRowDisplay(
            serverKey: srvKey,
            rawRule: '||dup.example^',
            duplicateCountInCore: 2,
          ).label,
          '归属未确认',
        );

        // Removing metadata only makes zero Core requests & keeps ||single.example^ in Core
        final singleRec = prov.findRecordsForRule(srvKey, '||single.example^').single;
        final postsBeforeMetaRemove = env.setRulesPostCount;
        await prov.removeProvenanceRecordOnly(
          serverKey: srvKey,
          recordId: singleRec.recordId,
        );
        expect(env.setRulesPostCount, postsBeforeMetaRemove);
        expect(env.rules, contains('||single.example^'));
        expect(prov.findRecordsForRule(srvKey, '||single.example^'), isEmpty);

        // Removing duplicate line MUST refuse guesswork without posting!
        final dupRemove = await fp.removeCustomRuleDetailed('||dup.example^');
        expect(dupRemove.ok, isFalse);
        expect(dupRemove.duplicateAmbiguous, isTrue);
        expect(env.setRulesPostCount, postsBeforeMetaRemove);
        expect(env.rules.where((r) => r == '||dup.example^').length, 2);

        // Removing single line with expected_revision succeeds & updates provenance
        await fp.claimExistingCustomRule('||single.example^');
        final okRemove = await fp.removeCustomRuleDetailed('||single.example^');
        expect(okRemove.ok, isTrue);
        expect(env.rules, isNot(contains('||single.example^')));
        expect(
          prov.findRecordsForRule(srvKey, '||single.example^').single.syncStatus,
          ManualRuleSyncStatus.missing,
        );

        // Strict undo token unchanged across Core restart
        final coord = ExceptionRuleCoordinator();
        final addOut = await coord.applyExceptionAndVerify(
          apiClient: env.apiClient,
          verifyHost: 'undo.strict.example',
          exceptionRule: '@@||undo.strict.example^',
          provenanceService: prov,
        );
        expect(addOut.undoToken, isNotNull);
        env.coreInstance = 'inst_restarted';
        final undoAfterRestart = await coord.undoAddedException(
          apiClient: env.apiClient,
          addedRule: '@@||undo.strict.example^',
          undoToken: addOut.undoToken,
          provenanceService: prov,
        );
        expect(undoAfterRestart.ok, isFalse);
        expect(env.rules, contains('@@||undo.strict.example^'));
      }, _PassthroughHttpOverrides());
    });

    test('14. DiagnosticBundleService NEVER leaks manual rule notes, provenance records, or manual rule texts', () async {
      SharedPreferences.setMockInitialValues({});
      final provDir = await Directory.systemTemp.createTemp('agh_prov_diag_');
      final cacheDiagDir = await Directory.systemTemp.createTemp('agh_cache_diag_');
      addTearDown(() async {
        if (await provDir.exists()) await provDir.delete(recursive: true);
        if (await cacheDiagDir.exists()) await cacheDiagDir.delete(recursive: true);
      });

      final prov = ManualRuleProvenanceService(
        backend: FileManualRuleProvenanceStoreBackend(
          directoryResolver: () async => provDir,
        ),
      );
      await prov.recordManualAdditions(
        serverKey: 'srv|http|127.0.0.1|3000',
        addedRules: ['@@||private.secret-manual-domain.example^'],
        entryPoint: '误杀排错',
        note: 'PRIVATE_USER_NOTE_SHOULD_NEVER_BE_EXPORTED_IN_DIAG_ZIP',
      );

      final modService = ModuleConfigService(
        isAndroidOverride: true,
        processRunner: (exe, args) async => ProcessResult(1, 0, 'status: ok\n', ''),
      );
      final bundleService = DiagnosticBundleService(
        moduleService: modService,
        cacheDirProvider: () async => cacheDiagDir.path,
        shareInvoker: (_, __) async => true,
      );

      final result = await bundleService.exportBundle();
      expect(result.succeeded, isTrue);
      expect(result.zipPath.isNotEmpty, isTrue);

      final entries = _decodeZipEntries(await File(result.zipPath).readAsBytes());
      for (final entry in entries.entries) {
        expect(entry.value, isNot(contains('PRIVATE_USER_NOTE_SHOULD_NEVER_BE_EXPORTED_IN_DIAG_ZIP')));
        expect(entry.value, isNot(contains('private.secret-manual-domain.example')));
        expect(entry.value, isNot(contains('manual_rule_provenance')));
      }
    });
  });

  group('10 & UI. Widget Verification for MyManualRulesScreen, CustomRulesList, Troubleshooter & LogTile', () {
    testWidgets('MyManualRulesScreen separates provenance from check_host live status (\$important block vs other rule vs complex vs missing) and saves notes locally without Core writes', (tester) async {
      SharedPreferences.setMockInitialValues({});
      final prefs = await SharedPreferences.getInstance();

      await tester.runAsync(() async {
        await HttpOverrides.runWithHttpOverrides(() async {
          final env = await _MockCoreEnv.start(
            initialRules: [
              '@@||blocked-by-imp.example.org^',
              '@@||not-hit-other.example.org^',
              '@@||complex.example.org^\$dnsrewrite=1.2.3.4',
            ],
          );
          addTearDown(env.close);

          env.checkHostHandler = (host, qtype) {
            if (host == 'blocked-by-imp.example.org') {
              return <String, dynamic>{
                'reason': 'FilteredBlackList',
                'rules': <Map<String, dynamic>>[
                  <String, dynamic>{
                    'text': '||blocked-by-imp.example.org^\$important',
                    'filter_list_id': 1,
                  },
                ],
              };
            }
            if (host == 'not-hit-other.example.org') {
              return <String, dynamic>{
                'reason': 'NotFilteredWhiteList',
                'rules': <Map<String, dynamic>>[
                  <String, dynamic>{
                    'text': '@@||example.org^',
                    'filter_list_id': 2,
                  },
                ],
              };
            }
            return <String, dynamic>{
              'reason': 'NotFilteredNotFound',
              'rules': <dynamic>[],
            };
          };

          final prov = ManualRuleProvenanceService(
            backend: InMemoryManualRuleProvenanceStoreBackend(),
            nowProvider: () => DateTime.utc(2026, 11, 17, 11, 0, 0),
          );
          await prov.recordManualAdditions(
            serverKey: ServerRuleWriteQueue.serverKeyFor(env.serverModel),
            addedRules: [
              '@@||blocked-by-imp.example.org^',
              '@@||not-hit-other.example.org^',
              '@@||complex.example.org^\$dnsrewrite=1.2.3.4',
              '@@||gone.example.org^',
            ],
            entryPoint: '误杀排错',
            confirmedRevision: env.currentRev(),
          );
          await prov.syncWithCoreRules(
            serverKey: ServerRuleWriteQueue.serverKeyFor(env.serverModel),
            coreRules: env.rules,
            currentRevision: env.currentRev(),
          );

          final srvProvider = ServersProvider()
            ..setSelectedServer(env.serverModel)
            ..setApiClient2(env.apiClient);
          final fp = FilteringProvider(provenanceService: prov)
            ..update(srvProvider, null);
          final appCfg = AppConfigProvider(sharedPreferencesInstance: prefs);

          await tester.pumpWidget(
            MultiProvider(
              providers: [
                ChangeNotifierProvider.value(value: srvProvider),
                ChangeNotifierProvider.value(value: fp),
                ChangeNotifierProvider.value(value: appCfg),
              ],
              child: MaterialApp(
                localizationsDelegates: AppLocalizations.localizationsDelegates,
                supportedLocales: AppLocalizations.supportedLocales,
                home: ScaffoldMessenger(
                  child: MyManualRulesScreen(provenanceService: prov),
                ),
              ),
            ),
          );
          await Future<void>.delayed(const Duration(milliseconds: 50));
          await tester.pump();
          await tester.pumpAndSettle();

          expect(find.text('我的手动规则'), findsOneWidget);
          expect(find.text('@@||blocked-by-imp.example.org^'), findsOneWidget);

          Future<void> tapCheckOnCard(String ruleText) async {
            final ruleFinder = find.text(ruleText);
            await tester.scrollUntilVisible(
              ruleFinder,
              200,
              scrollable: find.byType(Scrollable).last,
            );
            await tester.pumpAndSettle();
            final card = find.ancestor(of: ruleFinder, matching: find.byType(Card));
            final btn = find.descendant(of: card, matching: find.text('检查是否生效'));
            await tester.ensureVisible(btn);
            await tester.pumpAndSettle();
            await tester.tap(btn);
            await Future<void>.delayed(const Duration(milliseconds: 80));
            await tester.pumpAndSettle();
          }

          await tapCheckOnCard('@@||blocked-by-imp.example.org^');
          expect(find.textContaining('仍被更高优先级'), findsOneWidget);

          await tapCheckOnCard('@@||not-hit-other.example.org^');
          expect(find.textContaining('当前未被本条规则显式命中'), findsOneWidget);

          await tapCheckOnCard('@@||complex.example.org^\$dnsrewrite=1.2.3.4');
          expect(find.textContaining('复杂规则暂不支持单域名探活'), findsOneWidget);

          await tapCheckOnCard('@@||gone.example.org^');
          expect(find.textContaining('已不在 Core 自定义规则中'), findsOneWidget);

          // Edit note on top rule -> saves locally with ZERO Core /filtering/set_rules calls!
          final setCountBeforeNote = env.setRulesPostCount;
          final noteBtn = find.text('编辑备注').first;
          await tester.ensureVisible(noteBtn);
          await tester.pumpAndSettle();
          await tester.tap(noteBtn);
          await tester.pumpAndSettle();
          await tester.enterText(find.byType(TextField).last, 'local management note');
          await tester.tap(find.text('保存备注'));
          await Future<void>.delayed(const Duration(milliseconds: 50));
          await tester.pumpAndSettle();
          expect(env.setRulesPostCount, setCountBeforeNote);
          expect(find.textContaining('local management note'), findsOneWidget);

          // 15. Clean dispose without pending periodic timers
          await tester.pumpWidget(const SizedBox.shrink());
        }, _PassthroughHttpOverrides());
      });
    });

    testWidgets('CustomRulesList, Troubleshooter LiveRuleDiagnosticCard and LogTile render accurate provenance badges without false-attribution', (tester) async {
      SharedPreferences.setMockInitialValues({});
      final prefs = await SharedPreferences.getInstance();

      final srv = Server(
        id: 'ui-srv',
        name: 'UISrv',
        connectionMethod: 'http',
        domain: '127.0.0.1',
        port: 3000,
        defaultServer: true,
        runningOnHa: false,
      );
      final srvKey = ServerRuleWriteQueue.serverKeyFor(srv);
      final prov = ManualRuleProvenanceService(
        backend: InMemoryManualRuleProvenanceStoreBackend(),
      );
      await prov.recordManualAdditions(
        serverKey: srvKey,
        addedRules: ['@@||manual.example.com^'],
        entryPoint: '误杀排错',
      );
      ManualRuleProvenanceService.setInstanceForTest(prov);

      final srvProvider = ServersProvider()..setSelectedServer(srv);
      final fp = FilteringProvider(provenanceService: prov)
        ..update(srvProvider, null);
      final sp = StatusProvider(provenanceService: prov)..update(srvProvider);
      final cfg = AppConfigProvider(sharedPreferencesInstance: prefs);

      // 1) CustomRulesList shows "手动放行" for manual.example.com and "来源未记录" for preset @@ rule
      await tester.pumpWidget(
        MultiProvider(
          providers: [
            ChangeNotifierProvider.value(value: srvProvider),
            ChangeNotifierProvider.value(value: fp),
            ChangeNotifierProvider.value(value: cfg),
          ],
          child: MaterialApp(
            localizationsDelegates: AppLocalizations.localizationsDelegates,
            supportedLocales: AppLocalizations.supportedLocales,
            home: Scaffold(
              body: CustomRulesList(
                loadStatus: LoadStatus.loaded,
                data: const ['@@||manual.example.com^', '@@||preset-only.example.com^'],
                onRemoveCustomRule: (_) {},
              ),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.text('手动放行'), findsOneWidget);
      expect(find.text('来源未记录'), findsOneWidget);

      // 2) LiveRuleDiagnosticCard shows subscription badge + coexistence hint when subscription matches manual rule text
      final report = HostFamilyCheckReport(
        parsedInput: DomainParseResult.success(normalizedHost: 'manual.example.com'),
        originalA: const HostCheckResult(
          host: 'manual.example.com',
          isOriginal: true,
          status: RuleCheckStatus.whitelisted,
          rawReason: 'FilteredWhiteList',
          qtype: 'A',
          rules: [
            MatchedRuleInfo(
              text: '@@||manual.example.com^',
              filterListId: 2,
              sourceName: 'Module-Allowlist',
              isCustomRule: false,
              isImportant: false,
            ),
          ],
        ),
        parentResults: const [],
      );
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SingleChildScrollView(
              child: LiveRuleDiagnosticCard(
                rawQuery: 'manual.example.com',
                checking: false,
                report: report,
                outcomesByRule: const {},
                writeBusy: false,
                serverKey: srvKey,
                provenanceService: prov,
                onApplyException: (_, {required confirmBroad}) async {},
                onUndoException: (_) async {},
              ),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.text('Module-Allowlist'), findsOneWidget);
      expect(find.text('同时存在相同手动规则'), findsOneWidget);

      // 3) LogTile dialog shows matched rule provenance badge for custom manual rule
      final log = Log(
        time: DateTime.utc(2026, 11, 17, 12, 0),
        reason: 'FilteredBlackList',
        client: '127.0.0.1',
        question: Question(type: 'A', name: 'manual.example.com', questionClass: 'IN'),
        answer: const [],
        rules: [Rule(text: '@@||manual.example.com^', filterListId: 0)],
        elapsedMs: '2',
        clientProto: '',
        cached: false,
        upstream: '',
        answerDnssec: false,
      );
      await tester.pumpWidget(
        MultiProvider(
          providers: [
            ChangeNotifierProvider.value(value: srvProvider),
            ChangeNotifierProvider.value(value: sp),
            ChangeNotifierProvider.value(value: cfg),
          ],
          child: MaterialApp(
            localizationsDelegates: AppLocalizations.localizationsDelegates,
            supportedLocales: AppLocalizations.supportedLocales,
            home: Scaffold(body: LogTile(log: log)),
          ),
        ),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('manual.example.com'));
      await tester.pumpAndSettle();
      expect(find.text('手动放行'), findsOneWidget);
    });
  });

  group('RC4 Patch: Commit-Bound Provenance, Unobserved Drift, Restart & Import Security', () {
    test('S1. Concurrent external add between POST and readback never gets misattributed; interrupts provenance without rolling back Core; legacy Core lowers strength', () async {
      await HttpOverrides.runWithHttpOverrides(() async {
        final env = await _MockCoreEnv.start(
          initialRules: ['||base.example.org^'],
        );
        addTearDown(env.close);

        final prov = ManualRuleProvenanceService(
          backend: InMemoryManualRuleProvenanceStoreBackend(),
          nowProvider: () => DateTime.utc(2026, 11, 17, 13, 0, 0),
        );
        final srvKey = ServerRuleWriteQueue.serverKeyFor(env.serverModel);
        final srvProvider = ServersProvider()
          ..setSelectedServer(env.serverModel)
          ..setApiClient2(env.apiClient);
        final fp = FilteringProvider(provenanceService: prov)
          ..update(srvProvider, null);
        final sp = StatusProvider(provenanceService: prov)
          ..update(srvProvider)
          ..setServerStatusData(data: _makeDummyServerStatus(env.rules));

        // 1A) FilteringProvider: concurrent client injects '||evil-external.example^' after POST, before readback
        env.onAfterSetRulesBeforeReadback = () {
          env.rules.add('||evil-external.example^');
          env.epoch++;
        };
        final addInt = await fp.addCustomRuleDetailed('@@||mine-interrupted.example^');
        expect(addInt.ok, isTrue);
        expect(addInt.provenanceInterrupted, isTrue);
        expect(addInt.message, contains('规则操作已提交，但来源确认被其他更新打断'));
        // UI reflects actual Core state, does NOT roll back external rule, and NEVER attributes external rule to user!
        expect(fp.filtering!.userRules, contains('||evil-external.example^'));
        expect(fp.filtering!.userRules, contains('@@||mine-interrupted.example^'));
        expect(prov.findRecordsForRule(srvKey, '||evil-external.example^'), isEmpty);
        expect(prov.findRecordsForRule(srvKey, '@@||mine-interrupted.example^'), isEmpty);

        // 1B) StatusProvider: concurrent external injection between POST and readback
        env.onAfterSetRulesBeforeReadback = () {
          env.rules.add('||evil-status-ext.example^');
          env.epoch++;
        };
        final logInt = await sp.blockUnblockDomainDetailed(
          domain: 'mine-log.example',
          newStatus: 'block',
        );
        expect(logInt.ok, isTrue);
        expect(logInt.provenanceInterrupted, isTrue);
        expect(logInt.message, contains('规则操作已提交，但来源确认被其他更新打断'));
        expect(prov.findRecordsForRule(srvKey, '||evil-status-ext.example^'), isEmpty);
        expect(prov.findRecordsForRule(srvKey, '||mine-log.example^\$important'), isEmpty);

        // 1C) ExceptionRuleCoordinator: concurrent external injection between POST and readback
        final coord = ExceptionRuleCoordinator();
        env.onAfterSetRulesBeforeReadback = () {
          env.rules.add('||evil-tp-ext.example^');
          env.epoch++;
        };
        final tpInt = await coord.applyExceptionAndVerify(
          apiClient: env.apiClient,
          verifyHost: 'tp-interrupted.example',
          exceptionRule: '@@||tp-interrupted.example^',
          provenanceService: prov,
        );
        expect(tpInt.writeSucceeded, isTrue);
        expect(tpInt.provenanceInterrupted, isTrue);
        expect(tpInt.undoToken, isNull);
        expect(tpInt.message, contains('规则操作已提交，但来源确认被其他更新打断'));
        expect(prov.findRecordsForRule(srvKey, '||evil-tp-ext.example^'), isEmpty);
        expect(prov.findRecordsForRule(srvKey, '@@||tp-interrupted.example^'), isEmpty);

        // 1D) Legacy Core without revision headers -> lowers strength to unconfirmed ("待确认"), never confirmed present!
        env.omitRevision = true;
        final legacyRes = await fp.addCustomRuleDetailed('@@||legacy-core.example^');
        expect(legacyRes.ok, isTrue);
        expect(legacyRes.provenanceLegacyUnconfirmed, isTrue);
        final legacyRec = prov.findRecordsForRule(srvKey, '@@||legacy-core.example^').single;
        expect(legacyRec.syncStatus, ManualRuleSyncStatus.unconfirmed);
        expect(legacyRec.confirmedRevision, isNull);
      }, _PassthroughHttpOverrides());
    });

    test('S2. Separates historical source from current association across unobserved delete+readd, external add, own add, Core restart, and duplicate appear/disappear', () async {
      await HttpOverrides.runWithHttpOverrides(() async {
        final env = await _MockCoreEnv.start(initialRules: []);
        addTearDown(env.close);

        final prov = ManualRuleProvenanceService(
          backend: InMemoryManualRuleProvenanceStoreBackend(),
          nowProvider: () => DateTime.utc(2026, 11, 17, 14, 0, 0),
        );
        final srvKey = ServerRuleWriteQueue.serverKeyFor(env.serverModel);
        final srvProvider = ServersProvider()
          ..setSelectedServer(env.serverModel)
          ..setApiClient2(env.apiClient);
        final fp = FilteringProvider(provenanceService: prov)
          ..update(srvProvider, null);

        // Client cleanly adds rule A -> confirmed ("手动放行" + "已确认")
        expect((await fp.addCustomRuleDetailed('@@||rule-a.example^')).ok, isTrue);
        final recA1 = prov.findRecordsForRule(srvKey, '@@||rule-a.example^').single;
        expect(recA1.source, ManualRuleSource.manual);
        expect(recA1.syncStatus, ManualRuleSyncStatus.present);
        expect(recA1.confirmedRevision, env.currentRev());

        // Case 2a: This client normally adds another rule B on unbroken revision chain -> BOTH A and B remain "已确认"!
        expect((await fp.addCustomRuleDetailed('@@||rule-b.example^')).ok, isTrue);
        expect(prov.findRecordsForRule(srvKey, '@@||rule-a.example^').single.syncStatus, ManualRuleSyncStatus.present);
        expect(prov.findRecordsForRule(srvKey, '@@||rule-b.example^').single.syncStatus, ManualRuleSyncStatus.present);

        // Case 2b: External client adds X (unobserved version jump) -> A & B keep historical "手动新增", association drops to "待确认"!
        env.rules.add('||external-x.example^');
        env.epoch++;
        await fp.fetchFilters();
        final recA2 = prov.findRecordsForRule(srvKey, '@@||rule-a.example^').single;
        expect(recA2.historicalOriginLabel, '手动新增');
        expect(recA2.associationStatusLabel, '待确认');
        expect(recA2.createdAt, isNotNull);
        expect(prov.findRecordsForRule(srvKey, '||external-x.example^'), isEmpty);

        // Case 2c: Re-establishing a new rule C by this client MUST NOT accidentally confirm already-unconfirmed A!
        expect((await fp.addCustomRuleDetailed('@@||rule-c.example^')).ok, isTrue);
        expect(prov.findRecordsForRule(srvKey, '@@||rule-c.example^').single.syncStatus, ManualRuleSyncStatus.present);
        expect(prov.findRecordsForRule(srvKey, '@@||rule-a.example^').single.syncStatus, ManualRuleSyncStatus.unconfirmed);

        // Case 2d: External deletes C and re-adds exact same C WITHOUT Manager seeing the missing state -> C drops to "待确认"!
        env.rules.remove('@@||rule-c.example^');
        env.epoch++;
        env.rules.add('@@||rule-c.example^');
        env.epoch++;
        await fp.fetchFilters();
        final recCAfterUnobserved = prov.findRecordsForRule(srvKey, '@@||rule-c.example^').single;
        expect(recCAfterUnobserved.historicalOriginLabel, '手动新增');
        expect(recCAfterUnobserved.syncStatus, ManualRuleSyncStatus.unconfirmed);
        expect(prov.resolveCustomListRowDisplay(serverKey: srvKey, rawRule: '@@||rule-c.example^').label, '来源待确认');

        // User explicitly claims C at current revision -> establishes fresh "用户认领" + "已确认"
        expect(await fp.claimExistingCustomRule('@@||rule-c.example^', note: 'Re-claimed C'), isTrue);
        final recCClaimed = prov.findRecordsForRule(srvKey, '@@||rule-c.example^').single;
        expect(recCClaimed.source, ManualRuleSource.claimed);
        expect(recCClaimed.syncStatus, ManualRuleSyncStatus.present);
        expect(recCClaimed.createdAt, isNull);
        expect(recCClaimed.claimedAt, isNotNull);

        // Case 2e: Core restarts with identical rules AND identical epoch counter, only instance ID changes -> C drops to "待确认"!
        final sameEpoch = env.epoch;
        env.coreInstance = 'inst2_restarted';
        env.epoch = sameEpoch;
        await fp.fetchFilters();
        final recCAfterRestart = prov.findRecordsForRule(srvKey, '@@||rule-c.example^').single;
        expect(recCAfterRestart.historicalOriginLabel, '用户认领');
        expect(recCAfterRestart.syncStatus, ManualRuleSyncStatus.unconfirmed);
        expect(recCAfterRestart.note, 'Re-claimed C');

        // Case 2f: Duplicate identical rules appear -> duplicateAmbiguous -> then 1 copy removed externally -> transitions to unconfirmed ("待确认"), NEVER present!
        expect((await fp.addCustomRuleDetailed('@@||dup-drift.example^')).ok, isTrue);
        expect(prov.findRecordsForRule(srvKey, '@@||dup-drift.example^').single.syncStatus, ManualRuleSyncStatus.present);
        env.rules.add('@@||dup-drift.example^');
        env.epoch++;
        await fp.fetchFilters();
        expect(prov.findRecordsForRule(srvKey, '@@||dup-drift.example^').single.syncStatus, ManualRuleSyncStatus.duplicateAmbiguous);

        env.rules.removeLast();
        env.epoch++;
        await fp.fetchFilters();
        expect(prov.findRecordsForRule(srvKey, '@@||dup-drift.example^').single.syncStatus, ManualRuleSyncStatus.unconfirmed);
      }, _PassthroughHttpOverrides());
    });

    test('S3. Import provenance backup never self-certifies as present, preserves notes/history, validates enums strictly, protects local trusted records, and never writes Core', () async {
      final prov = ManualRuleProvenanceService(
        backend: InMemoryManualRuleProvenanceStoreBackend(),
        nowProvider: () => DateTime.utc(2026, 11, 17, 15, 0, 0),
      );
      const localSrv = 'srv_new|http|127.0.0.1|3000';

      // Seed one existing trusted "present" manual rule locally
      await prov.recordManualAdditions(
        serverKey: localSrv,
        addedRules: ['@@||trusted-local.example^'],
        entryPoint: '误杀排错',
        confirmedRevision: 'v2:inst1:10',
        note: 'Keep my trusted note',
      );

      // Build malicious/over-claiming backup JSON from old server claiming sync_status="present" + old revision
      final oldBackup = jsonEncode({
        'schema_version': 1,
        'records_by_server': {
          'srv_old|http|127.0.0.1|3000': [
            {
              'record_id': 'old_1',
              'server_key': 'srv_old|http|127.0.0.1|3000',
              'rule_text': '@@||same-text-imported.example^',
              'action': 'allow',
              'source': 'manual',
              'entry_point': '误杀排错',
              'created_at': '2026-11-10T08:00:00Z',
              'updated_at': '2026-11-10T08:00:00Z',
              'note': 'Historical note preserved',
              'confirmed_revision': 'v2:old_inst:99',
              'sync_status': 'present',
            },
            {
              'record_id': 'old_2',
              'server_key': 'srv_old|http|127.0.0.1|3000',
              'rule_text': '||deleted-never-create.example^',
              'action': 'block',
              'source': 'claimed',
              'entry_point': '自定义规则-主动认领',
              'claimed_at': '2026-11-11T08:00:00Z',
              'updated_at': '2026-11-11T08:00:00Z',
              'sync_status': 'present',
            },
            {
              'record_id': 'old_3',
              'server_key': 'srv_old|http|127.0.0.1|3000',
              'rule_text': '@@||trusted-local.example^',
              'action': 'allow',
              'source': 'claimed',
              'entry_point': '旧导入冲突',
              'claimed_at': '2026-11-12T08:00:00Z',
              'updated_at': '2099-01-01T00:00:00Z',
              'note': 'Attempted overwrite note',
              'sync_status': 'unconfirmed',
            },
          ],
        },
      });

      final currentCoreRules = <String>[
        '@@||trusted-local.example^',
        '@@||same-text-imported.example^',
      ];
      final res = await prov.importBackupJson(
        oldBackup,
        importIntoServerKey: localSrv,
        currentCoreRulesForTargetServer: currentCoreRules,
      );
      expect(res.importedCount, 2);
      expect(res.skippedCount, 1);

      // 1) Imported rule present in Core CANNOT become present ("已确认") — must stay "待确认", keeping history & note!
      final importedSameText = prov.findRecordsForRule(localSrv, '@@||same-text-imported.example^').single;
      expect(importedSameText.syncStatus, ManualRuleSyncStatus.unconfirmed);
      expect(importedSameText.confirmedRevision, isNull);
      expect(importedSameText.source, ManualRuleSource.manual);
      expect(importedSameText.note, 'Historical note preserved');
      expect(importedSameText.createdAt, DateTime.utc(2026, 11, 10, 8, 0, 0));

      // 2) Imported rule NOT in Core -> marked missing ("已不存在"), never creates Core rules!
      final importedMissing = prov.findRecordsForRule(localSrv, '||deleted-never-create.example^').single;
      expect(importedMissing.syncStatus, ManualRuleSyncStatus.missing);
      expect(importedMissing.source, ManualRuleSource.claimed);
      expect(currentCoreRules, isNot(contains('||deleted-never-create.example^')));

      // 3) Existing local trusted "present" rule was NOT overwritten or downgraded by unconfirmed conflicting import!
      final trustedLocal = prov.findRecordsForRule(localSrv, '@@||trusted-local.example^').single;
      expect(trustedLocal.syncStatus, ManualRuleSyncStatus.present);
      expect(trustedLocal.source, ManualRuleSource.manual);
      expect(trustedLocal.confirmedRevision, 'v2:inst1:10');
      expect(trustedLocal.note, 'Keep my trusted note');

      // 4) Strict enum validation rejects unknown source / action / sync_status without defaulting to manual/present
      for (final badField in [
        {'source': 'auto_preset'},
        {'action': 'redirect_magic'},
        {'sync_status': 'verified_forever'},
      ]) {
        final badJson = jsonEncode({
          'schema_version': 1,
          'records_by_server': {
            localSrv: [
              {
                'record_id': 'bad_1',
                'server_key': localSrv,
                'rule_text': '@@||bad-enum.example^',
                'action': badField['action'] ?? 'allow',
                'source': badField['source'] ?? 'manual',
                'entry_point': 'test',
                'created_at': '2026-11-10T08:00:00Z',
                'updated_at': '2026-11-10T08:00:00Z',
                'sync_status': badField['sync_status'] ?? 'unconfirmed',
              },
            ],
          },
        });
        await expectLater(
          prov.importBackupJson(badJson),
          throwsFormatException,
        );
      }

      // 5) Explicit user claim on imported unconfirmed record establishes new managed "用户认领" + "已确认" association
      await prov.claimExistingRule(
        serverKey: localSrv,
        ruleText: '@@||same-text-imported.example^',
        latestCoreRules: currentCoreRules,
        confirmedRevision: 'v2:inst1:11',
      );
      final reclaimed = prov.findRecordsForRule(localSrv, '@@||same-text-imported.example^').single;
      expect(reclaimed.source, ManualRuleSource.claimed);
      expect(reclaimed.syncStatus, ManualRuleSyncStatus.present);
      expect(reclaimed.confirmedRevision, 'v2:inst1:11');
      expect(reclaimed.note, 'Historical note preserved');
    });
  });
}
