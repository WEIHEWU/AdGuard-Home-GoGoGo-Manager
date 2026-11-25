import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:adguard_home_manager/l10n/app_localizations.dart';
import 'package:adguard_home_manager/models/dns_statistics.dart';
import 'package:adguard_home_manager/models/filtering.dart';
import 'package:adguard_home_manager/models/filtering_status.dart' as fs;
import 'package:adguard_home_manager/models/logs.dart';
import 'package:adguard_home_manager/models/server.dart';
import 'package:adguard_home_manager/models/server_status.dart';
import 'package:adguard_home_manager/providers/app_config_provider.dart';
import 'package:adguard_home_manager/providers/filtering_provider.dart';
import 'package:adguard_home_manager/providers/logs_provider.dart';
import 'package:adguard_home_manager/providers/servers_provider.dart';
import 'package:adguard_home_manager/providers/status_provider.dart';
import 'package:adguard_home_manager/screens/logs/logs.dart';
import 'package:adguard_home_manager/services/api_client.dart';
import 'package:adguard_home_manager/services/diagnostic_bundle_service.dart';
import 'package:adguard_home_manager/services/manual_rule_provenance_service.dart';
import 'package:adguard_home_manager/services/module_config_service.dart';
import 'package:adguard_home_manager/widgets/module_diagnostics_sheet.dart';

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

class _HungMockProcess implements Process {
  final StreamController<List<int>> _out = StreamController<List<int>>();
  final StreamController<List<int>> _err = StreamController<List<int>>();
  final Completer<int> _exitCompleter = Completer<int>();
  bool killed = false;

  @override
  int get pid => 42424;

  @override
  Stream<List<int>> get stdout => _out.stream;

  @override
  Stream<List<int>> get stderr => _err.stream;

  @override
  IOSink get stdin => throw UnimplementedError();

  @override
  Future<int> get exitCode => _exitCompleter.future;

  @override
  bool kill([ProcessSignal signal = ProcessSignal.sigterm]) {
    killed = true;
    if (!_out.isClosed) _out.close();
    if (!_err.isClosed) _err.close();
    if (!_exitCompleter.isCompleted) {
      _exitCompleter.complete(-15);
    }
    return true;
  }
}

class _FakeFilteringAndLogsApiClient extends ApiClientV2 {
  int getFilteringCalls = 0;
  int setCustomRulesCalls = 0;
  final LogsData? logsToReturn;
  final Filtering? filteringToReturn;

  _FakeFilteringAndLogsApiClient({
    this.logsToReturn,
    this.filteringToReturn,
  }) : super(
          server: Server(
            id: 'test-srv',
            name: 'local',
            connectionMethod: 'http',
            domain: '127.0.0.1',
            path: null,
            port: 55786,
            user: 'root',
            password: 'root',
            defaultServer: true,
            authToken: 'cm9vdDpyb290',
            runningOnHa: false,
          ),
        );

  @override
  Future<ApiResponse> getFiltering() async {
    getFilteringCalls++;
    if (filteringToReturn != null) {
      return ApiResponse(successful: true, content: filteringToReturn);
    }
    return const ApiResponse(successful: false, statusCode: 503);
  }

  @override
  Future<ApiResponse> setCustomRules({
    required List<String> rules,
    String? expectedRevision,
  }) async {
    setCustomRulesCalls++;
    return const ApiResponse(successful: true);
  }

  @override
  Future<ApiResponse> getLogs({
    int? count,
    int? offset,
    DateTime? olderThan,
    String? responseStatus,
    String? search,
  }) async {
    if (logsToReturn == null) {
      return const ApiResponse(successful: false);
    }
    return ApiResponse(successful: true, content: logsToReturn);
  }
}

class _PolishStubUiDiagService extends DiagnosticBundleService {
  int shareCalls = 0;
  Completer<DiagnosticBundleResult>? _pending;

  @override
  Future<DiagnosticBundleResult> exportBundle({
    DiagnosticCancelToken? cancelToken,
    String appVersion = AppConfigProvider.appVersion,
  }) {
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
    return true;
  }
}

void main() {
  setUp(() {
    ModuleConfigService.resetTestState();
  });

  test('P0-Manager-1: hung su process is killed on timeout and queue recovers',
      () async {
    final hungProc = _HungMockProcess();
    var launchCount = 0;
    final service = ModuleConfigService(
      isAndroidOverride: true,
      mutationWaitTimeout: const Duration(milliseconds: 120),
      mutationSuTimeout: const Duration(milliseconds: 220),
      probeCandidateRunner: (su, _) async {
        if (su == 'su') return ProcessResult(1, 0, '0\n', '');
        return null;
      },
      processStarter: (exe, args) async {
        launchCount++;
        if (launchCount == 1) {
          return hungProc;
        }
        return await Process.start('/bin/sh', [
          '-c',
          'echo "AGH_SWITCH_RESULT status=ok mode=cn http_port=3000 op_id=ok2"',
        ]);
      },
    );

    final first = await service.switchRunModeDetailed('cn');
    expect(first.succeeded, isFalse);
    expect(first.unconfirmed, isTrue);
    expect(first.stage, 'timeout_unconfirmed');

    // Wait past _mutationSuTimeout so _runSu automatically kills hungProc & drains queue.
    await Future<void>.delayed(const Duration(milliseconds: 350));
    expect(hungProc.killed, isTrue);

    final second = await service.switchRunModeDetailed('cn');
    expect(second.succeeded, isTrue);
    expect(second.httpPort, 3000);
  });

  test(
      'P0-Manager-2: restoreFactoryUserRules aborts with 0 writes when getFiltering fails',
      () async {
    final api = _FakeFilteringAndLogsApiClient();
    final serversProvider = ServersProvider();
    serversProvider.setSelectedServer(api.server);
    serversProvider.setApiClient2(api);

    final statusProvider = StatusProvider();
    statusProvider.update(serversProvider);

    final filteringProvider = FilteringProvider();
    filteringProvider.update(serversProvider, statusProvider);

    final res = await filteringProvider.restoreFactoryUserRules(
      factoryRules: const ['||ads.example.com^\$important'],
      mergeExisting: true,
      deprecatedFactoryRules: const {},
    );

    expect(res.ok, isFalse);
    expect(api.getFilteringCalls, 1);
    expect(api.setCustomRulesCalls, 0);
  });

  test(
      'P1-CrossRepo-1: DiagnosticBundleService defaults to AppConfigProvider.appVersion',
      () async {
    final tmpDir = await Directory.systemTemp.createTemp('agh_diag_ver_test');
    addTearDown(() async {
      if (await tmpDir.exists()) {
        await tmpDir.delete(recursive: true);
      }
    });

    final localTime = DateTime(2026, 11, 25, 8, 5, 9, 123);
    String? savedSrcPath;
    String? savedFileName;
    final service = DiagnosticBundleService(
      moduleService: ModuleConfigService(isAndroidOverride: false),
      cacheDirProvider: () async => tmpDir.path,
      nowProvider: () => localTime,
      downloadsSaver: (filePath, fileName) async {
        savedSrcPath = filePath;
        savedFileName = fileName;
        return (
          saved: true,
          displayPath: 'Download/$fileName',
          isPublicDownload: true,
        );
      },
      shareInvoker: (_, __) async => true,
    );

    final result = await service.exportBundle();
    expect(result.succeeded, isTrue);
    expect(result.fileName, startsWith('agh_diag_20261125_080509_'));
    expect(result.bundleId, startsWith('diag_20261125_080509_'));
    expect(savedSrcPath, result.zipPath);
    expect(savedFileName, result.fileName);
    expect(result.savedDisplayPath, 'Download/${result.fileName}');
    expect(result.savedToPublicDownloads, isTrue);
    expect(File(result.zipPath).existsSync(), isTrue);

    final entries = _decodeZipEntries(await File(result.zipPath).readAsBytes());
    final allContent = entries.values.join('\n');
    expect(allContent, contains('管理器版本: ${AppConfigProvider.appVersion}'));
    expect(allContent, contains('"manager_version": "${AppConfigProvider.appVersion}"'));

    final manifest =
        jsonDecode(entries['manifest.json']!) as Map<String, dynamic>;
    expect(manifest['generated_at_utc'], localTime.toUtc().toIso8601String());
    expect(
      manifest['generated_at_local'] as String,
      matches(RegExp(r'^2026-11-25T08:05:09\.123([+-]\d{2}:\d{2}|Z)$')),
    );
    expect(
      entries['00_README_AND_MANIFEST.txt'],
      contains('生成时间 (本地): ${manifest['generated_at_local']}'),
    );
    expect(
      entries['00_README_AND_MANIFEST.txt'],
      contains('生成时间 (UTC): ${manifest['generated_at_utc']}'),
    );
  });

  testWidgets(
      'Polish-DiagSheet: displays Download saved path while preserving Share button',
      (tester) async {
    SharedPreferences.setMockInitialValues({});
    final prefs = await SharedPreferences.getInstance();
    final appConfigProvider =
        AppConfigProvider(sharedPreferencesInstance: prefs);

    final stub = _PolishStubUiDiagService();

    await tester.pumpWidget(
      ChangeNotifierProvider<AppConfigProvider>.value(
        value: appConfigProvider,
        child: MaterialApp(
          locale: const Locale('zh'),
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: Builder(
            builder: (ctx) => Scaffold(
              body: Center(
                child: ElevatedButton(
                  onPressed: () => showDiagnosticExportFlow(
                    ctx,
                    isZhOverride: true,
                    bundleService: stub,
                  ),
                  child: const Text('Open'),
                ),
              ),
            ),
          ),
        ),
      ),
    );

    await tester.tap(find.text('Open'));
    await tester.pumpAndSettle();

    await tester.tap(find.text('生成诊断包'));
    await tester.pump();

    stub.completeCurrent(DiagnosticBundleResult(
      succeeded: true,
      zipPath: '/tmp/agh_diag_20261125_091011_abcd.zip',
      savedDisplayPath: 'Download/agh_diag_20261125_091011_abcd.zip',
      savedToPublicDownloads: true,
      fileName: 'agh_diag_20261125_091011_abcd.zip',
      zipBytes: 2048,
      bundleId: 'diag_20261125_091011_abcd',
      generatedAtUtc: DateTime.utc(2026, 11, 24, 22, 10, 11),
      generatedAtLocal: DateTime(2026, 11, 25, 9, 10, 11),
      previewText: 'preview ok',
      summaryText: 'summary ok',
    ));
    await tester.pumpAndSettle();

    expect(
      find.textContaining('已保存至 Download/agh_diag_20261125_091011_abcd.zip'),
      findsWidgets,
    );
    expect(find.text('分享'), findsOneWidget);

    await tester.tap(find.text('分享'));
    await tester.pumpAndSettle();
    expect(stub.shareCalls, 1);

    await tester.tap(find.text('关闭'));
    await tester.pumpAndSettle();
  });

  testWidgets(
      'P1-Manager-3: aggregated log tile keeps compact row & opens detail dialog with Block/Unblock',
      (tester) async {
    SharedPreferences.setMockInitialValues({});
    final prefs = await SharedPreferences.getInstance();

    await tester.runAsync(() async {
      await ManualRuleProvenanceService.instance.ensureLoaded();

      final now = DateTime.utc(2026, 11, 25, 1, 2, 3);
      final logsData = LogsData(
        oldest: now,
        data: [
          Log(
            answerDnssec: false,
            cached: false,
            client: '127.0.0.1',
            clientProto: '',
            elapsedMs: '0.2',
            upstream: '',
            answer: const [],
            question: Question(
              questionClass: 'IN',
              name: 'ads.example.com',
              type: 'HTTPS',
            ),
            reason: 'FilteredBlackList',
            rules: [
              Rule(filterListId: 0, text: '||ads.example.com^\$important'),
            ],
            status: 'NOERROR',
            time: now.add(const Duration(milliseconds: 200)),
          ),
          Log(
            answerDnssec: false,
            cached: false,
            client: '127.0.0.1',
            clientProto: '',
            elapsedMs: '0.2',
            upstream: '',
            answer: const [],
            question: Question(
              questionClass: 'IN',
              name: 'ads.example.com',
              type: 'HTTPS',
            ),
            reason: 'FilteredBlackList',
            rules: [
              Rule(filterListId: 0, text: '||ads.example.com^\$important'),
            ],
            status: 'NOERROR',
            time: now,
          ),
        ],
      );

      final appConfigProvider =
          AppConfigProvider(sharedPreferencesInstance: prefs);
      final api = _FakeFilteringAndLogsApiClient(
        logsToReturn: logsData,
        filteringToReturn: Filtering(
          enabled: true,
          interval: 0,
          filters: const [],
          whitelistFilters: const [],
          userRules: const [],
          blockedServices: const [],
        ),
      );
      final serversProvider = ServersProvider();
      serversProvider.setSelectedServer(api.server);
      serversProvider.setApiClient2(api);

      final statusProvider = StatusProvider()..update(serversProvider);
      statusProvider.setServerStatusData(
        data: ServerStatus(
          stats: DnsStatistics(
            timeUnits: 'hours',
            topQueriedDomains: const [],
            topBlockedDomains: const [],
            topUpstreamResponses: const [],
            topUpstreamsAvgTime: const [],
            dnsQueries: const [],
            blockedFiltering: const [],
            numDnsQueries: 0,
            numBlockedFiltering: 0,
            avgProcessingTime: 0,
          ),
          filteringStatus: fs.FilteringStatus(
            filters: const [],
            whitelistFilters: const [],
            userRules: const [],
            interval: 0,
            enabled: true,
          ),
          timeGeneralDisabled: 0,
          generalEnabled: true,
          filteringEnabled: true,
          safeBrowsingEnabled: false,
          parentalControlEnabled: false,
          serverVersion: 'v2026-11-25-rc.1',
          dhcpAvailable: false,
        ),
      );
      final filteringProvider = FilteringProvider()
        ..update(serversProvider, statusProvider);
      final logsProvider = LogsProvider()..update(serversProvider);

      await tester.pumpWidget(
        MultiProvider(
          providers: [
            ChangeNotifierProvider<AppConfigProvider>.value(
                value: appConfigProvider),
            ChangeNotifierProvider<ServersProvider>.value(value: serversProvider),
            ChangeNotifierProvider<StatusProvider>.value(value: statusProvider),
            ChangeNotifierProvider<FilteringProvider>.value(
                value: filteringProvider),
            ChangeNotifierProvider<LogsProvider>.value(value: logsProvider),
          ],
          child: const MaterialApp(
            locale: Locale('zh'),
            localizationsDelegates: AppLocalizations.localizationsDelegates,
            supportedLocales: AppLocalizations.supportedLocales,
            home: Logs(),
          ),
        ),
      );
      await Future<void>.delayed(const Duration(milliseconds: 50));
      await tester.pumpAndSettle();

      // Row must NOT have extra trailing IconButtons.
      final listTileRow = find.byWidgetPredicate(
        (w) => w is ListView && w.scrollDirection == Axis.vertical,
      );
      expect(listTileRow, findsOneWidget);
      expect(
        find.descendant(
          of: listTileRow,
          matching: find.byType(IconButton),
        ),
        findsNothing,
      );

      // Tapping the aggregated item opens detail dialog with Unblock button.
      await tester.tap(find.text('ads.example.com'));
      await tester.pumpAndSettle();

      expect(find.byType(AlertDialog), findsOneWidget);
      expect(
        find.descendant(
          of: find.byType(AlertDialog),
          matching: find.byIcon(Icons.check_rounded),
        ),
        findsOneWidget,
      );
    });
  });
}
