import 'dart:convert';
import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:adguard_home_manager/l10n/app_localizations.dart';
import 'package:adguard_home_manager/models/server.dart';
import 'package:adguard_home_manager/providers/app_config_provider.dart';
import 'package:adguard_home_manager/providers/filtering_provider.dart';
import 'package:adguard_home_manager/providers/logs_provider.dart';
import 'package:adguard_home_manager/providers/servers_provider.dart';
import 'package:adguard_home_manager/providers/status_provider.dart';
import 'package:adguard_home_manager/screens/logs/logs.dart';
import 'package:adguard_home_manager/services/api_client.dart';
import 'package:adguard_home_manager/widgets/log_status_indicator.dart';

class _PassthroughHttpOverrides extends HttpOverrides {}

class _ThemeColorAppConfigProvider extends AppConfigProvider {
  _ThemeColorAppConfigProvider({required super.sharedPreferencesInstance});

  @override
  bool get useThemeColorForStatus => true;
}

Map<String, dynamic> _logJson({
  required String domain,
  required String reason,
  required String timeIso,
  String qtype = 'A',
  String clientProto = '',
  List<Map<String, dynamic>> rules = const [],
}) {
  return <String, dynamic>{
    'time': timeIso,
    'reason': reason,
    'client': '127.0.0.1',
    'client_proto': clientProto,
    'elapsedMs': '1.2',
    'cached': false,
    'upstream': '',
    'question': <String, dynamic>{
      'type': qtype,
      'name': domain,
      'class': 'IN',
    },
    'rules': rules,
    'answer': <dynamic>[],
  };
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('Aggregated Logs Status Indicator & UI Tests', () {
    testWidgets('1-4. Logs page shows status + expand arrow in aggregated mode for all reasons, preserves predictedBlocked, toggles cleanly, and opens detail dialog', (tester) async {
      SharedPreferences.setMockInitialValues({});
      final prefs = await SharedPreferences.getInstance();

      await tester.runAsync(() async {
        await HttpOverrides.runWithHttpOverrides(() async {
          const ts = '2026-11-17T01:02:03.000Z';
          final queryLogs = <Map<String, dynamic>>[
            // Duplicate pair 1: FilteredBlackList
            _logJson(
              domain: 'ads.example.com',
              reason: 'FilteredBlackList',
              timeIso: ts,
              rules: [{'text': '||ads.example.com^', 'filter_list_id': 1}],
            ),
            _logJson(
              domain: 'ads.example.com',
              reason: 'FilteredBlackList',
              timeIso: ts,
              rules: [{'text': '||ads.example.com^', 'filter_list_id': 1}],
            ),
            // Duplicate pair 2: FilteredSNI
            _logJson(
              domain: 'sni-blocked.example.com',
              reason: 'FilteredSNI',
              qtype: 'SNI',
              clientProto: 'sni',
              timeIso: ts,
              rules: [{'text': '||sni-blocked.example.com^', 'filter_list_id': 1}],
            ),
            _logJson(
              domain: 'sni-blocked.example.com',
              reason: 'FilteredSNI',
              qtype: 'SNI',
              clientProto: 'sni',
              timeIso: ts,
              rules: [{'text': '||sni-blocked.example.com^', 'filter_list_id': 1}],
            ),
            // Duplicate pair 3: NotFilteredNotFound
            _logJson(
              domain: 'ok.example.org',
              reason: 'NotFilteredNotFound',
              timeIso: ts,
            ),
            _logJson(
              domain: 'ok.example.org',
              reason: 'NotFilteredNotFound',
              timeIso: ts,
            ),
            // Duplicate pair 4: NotFilteredSNI
            _logJson(
              domain: 'sni-ok.example.org',
              reason: 'NotFilteredSNI',
              qtype: 'SNI',
              clientProto: 'sni',
              timeIso: ts,
            ),
            _logJson(
              domain: 'sni-ok.example.org',
              reason: 'NotFilteredSNI',
              qtype: 'SNI',
              clientProto: 'sni',
              timeIso: ts,
            ),
            // Duplicate pair 5: NotFilteredWhiteList
            _logJson(
              domain: 'wl.example.org',
              reason: 'NotFilteredWhiteList',
              timeIso: ts,
              rules: [{'text': '@@||wl.example.org^', 'filter_list_id': 0}],
            ),
            _logJson(
              domain: 'wl.example.org',
              reason: 'NotFilteredWhiteList',
              timeIso: ts,
              rules: [{'text': '@@||wl.example.org^', 'filter_list_id': 0}],
            ),
            // Duplicate pair 6: Rewrite*
            _logJson(
              domain: 'rw.example.org',
              reason: 'RewriteCustom',
              timeIso: ts,
            ),
            _logJson(
              domain: 'rw.example.org',
              reason: 'RewriteCustom',
              timeIso: ts,
            ),
            // Duplicate pair 7: Unknown reason
            _logJson(
              domain: 'unk.example.org',
              reason: 'SomeFutureReason',
              timeIso: ts,
            ),
            _logJson(
              domain: 'unk.example.org',
              reason: 'SomeFutureReason',
              timeIso: ts,
            ),
          ];

          final httpSrv = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
          addTearDown(() => httpSrv.close(force: true));
          httpSrv.listen((req) async {
            final p = req.uri.path;
            if (p == '/control/querylog') {
              req.response
                ..statusCode = 200
                ..headers.contentType = ContentType.json
                ..write(jsonEncode({'data': queryLogs, 'oldest': ts}));
            } else if (p == '/control/filtering/status') {
              req.response
                ..statusCode = 200
                ..headers.contentType = ContentType.json
                ..write(jsonEncode({
                  'filters': [
                    {'id': 1, 'name': 'Anti-AD', 'url': 'https://a.invalid/1.txt', 'rules_count': 10, 'enabled': true},
                  ],
                  'whitelist_filters': <dynamic>[],
                  'user_rules': <dynamic>[],
                  'interval': 24,
                  'enabled': true,
                }));
            } else {
              req.response.statusCode = 404;
            }
            await req.response.close();
          });

          final srv = Server(
            id: 'logs-srv',
            name: 'LogsMock',
            connectionMethod: 'http',
            domain: '127.0.0.1',
            port: httpSrv.port,
            defaultServer: true,
            runningOnHa: false,
          );
          final api = ApiClientV2(server: srv);
          final sp = ServersProvider()
            ..setSelectedServer(srv)
            ..setApiClient2(api);
          final fp = FilteringProvider()..update(sp, null);
          final lp = LogsProvider()..update(sp);
          final statusP = StatusProvider()..update(sp);
          final cfg = AppConfigProvider(sharedPreferencesInstance: prefs);

          await tester.pumpWidget(
            MultiProvider(
              providers: [
                ChangeNotifierProvider.value(value: sp),
                ChangeNotifierProvider.value(value: fp),
                ChangeNotifierProvider.value(value: lp),
                ChangeNotifierProvider.value(value: statusP),
                ChangeNotifierProvider.value(value: cfg),
              ],
              child: const MaterialApp(
                locale: Locale('zh'),
                localizationsDelegates: AppLocalizations.localizationsDelegates,
                supportedLocales: AppLocalizations.supportedLocales,
                home: Logs(),
              ),
            ),
          );
          await Future<void>.delayed(const Duration(milliseconds: 100));
          await tester.pumpAndSettle();

          // Aggregated mode is active by default
          expect(find.text('聚合重复'), findsOneWidget);
          expect(find.text('ads.example.com'), findsOneWidget);

          // Check all aggregated entries show BOTH status icon+text AND expand arrow (using secondary color)
          Future<void> scrollToAndVerify({
            required String domain,
            required String expectedLabel,
            required IconData expectedIcon,
            required Color expectedColor,
          }) async {
            final dFinder = find.text(domain);
            await tester.scrollUntilVisible(
              dFinder,
              150,
              scrollable: find.byType(Scrollable).last,
            );
            await tester.pumpAndSettle();
            expect(dFinder, findsOneWidget);

            final tileRow = find.ancestor(of: dFinder, matching: find.byType(InkWell));
            final indFinder = find.descendant(
              of: tileRow,
              matching: find.byType(LogStatusIndicator),
            );
            expect(indFinder, findsOneWidget);
            expect(
              find.descendant(of: indFinder, matching: find.text(expectedLabel)),
              findsOneWidget,
            );
            final statusIcon = tester.widget<Icon>(
              find.descendant(of: indFinder, matching: find.byIcon(expectedIcon)),
            );
            expect(statusIcon.color, expectedColor);

            final arrowFinder = find.descendant(
              of: indFinder,
              matching: find.byIcon(Icons.expand_more_rounded),
            );
            expect(arrowFinder, findsOneWidget);
            final arrowIcon = tester.widget<Icon>(arrowFinder);
            expect(arrowIcon.color, isNot(Colors.red));
            expect(arrowIcon.color, isNot(Colors.green));
          }

          await scrollToAndVerify(
            domain: 'ads.example.com',
            expectedLabel: '已拦截\n黑名单',
            expectedIcon: Icons.gpp_bad_rounded,
            expectedColor: Colors.red,
          );
          await scrollToAndVerify(
            domain: 'sni-blocked.example.com',
            expectedLabel: '已拦截\nSNI',
            expectedIcon: Icons.gpp_bad_rounded,
            expectedColor: Colors.red,
          );
          await scrollToAndVerify(
            domain: 'ok.example.org',
            expectedLabel: '已处理\n无拦截',
            expectedIcon: Icons.verified_user_rounded,
            expectedColor: Colors.green,
          );
          await scrollToAndVerify(
            domain: 'sni-ok.example.org',
            expectedLabel: '已处理\nSNI',
            expectedIcon: Icons.verified_user_rounded,
            expectedColor: Colors.green,
          );
          await scrollToAndVerify(
            domain: 'wl.example.org',
            expectedLabel: '已处理\n白名单',
            expectedIcon: Icons.verified_user_rounded,
            expectedColor: Colors.green,
          );
          await scrollToAndVerify(
            domain: 'rw.example.org',
            expectedLabel: '重写',
            expectedIcon: Icons.shield_rounded,
            expectedColor: Colors.blue,
          );
          await scrollToAndVerify(
            domain: 'unk.example.org',
            expectedLabel: 'Unknown',
            expectedIcon: Icons.help_outline_rounded,
            expectedColor: Colors.grey,
          );

          // Tapping aggregated item still opens detail dialog with raw events
          await tester.tap(find.text('unk.example.org'));
          await tester.pumpAndSettle();
          expect(find.text('原始事件详情:'), findsOneWidget);
          await tester.tap(find.text('关闭'));
          await tester.pumpAndSettle();

          // Toggle "聚合重复" -> "原始逐条" and verify same status appears on LogTile!
          await tester.tap(find.text('聚合重复'));
          await tester.pumpAndSettle();
          expect(find.text('原始逐条'), findsOneWidget);

          await tester.scrollUntilVisible(
            find.text('ads.example.com').first,
            -250,
            scrollable: find.byType(Scrollable).last,
          );
          await tester.pumpAndSettle();
          expect(find.text('已拦截\n黑名单'), findsWidgets);
          expect(find.byIcon(Icons.expand_more_rounded), findsNothing);
        }, _PassthroughHttpOverrides());
      });
    });

    testWidgets('3b, 5, 6. predictedBlocked stays processed, narrow screen + huge textScaler + long domain has zero overflow, dark mode & useThemeColorForStatus preserved', (tester) async {
      SharedPreferences.setMockInitialValues({});
      final prefs = await SharedPreferences.getInstance();

      await tester.runAsync(() async {
        await HttpOverrides.runWithHttpOverrides(() async {
          const ts = '2026-11-17T01:05:00.000Z';
          // Emulate AdGuard paused protection event: reason=NotFilteredNotFound, but rule was blocking!
          final pausedEvent = <String, dynamic>{
            'time': ts,
            'reason': 'NotFilteredNotFound',
            'client': '127.0.0.1',
            'elapsedMs': '1.0',
            'cached': false,
            'upstream': '',
            'predicted_blocked': true,
            'question': {
              'type': 'A',
              'name': 'very-very-long-subdomain-that-should-ellipsize-cleanly.example.co.uk',
              'class': 'IN',
            },
            'rules': [{'text': '||very-very-long-subdomain-that-should-ellipsize-cleanly.example.co.uk^', 'filter_list_id': 1}],
            'answer': <dynamic>[],
          };

          final httpSrv = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
          addTearDown(() => httpSrv.close(force: true));
          httpSrv.listen((req) async {
            if (req.uri.path == '/control/querylog') {
              req.response
                ..statusCode = 200
                ..headers.contentType = ContentType.json
                ..write(jsonEncode({'data': [pausedEvent, pausedEvent], 'oldest': ts}));
            } else if (req.uri.path == '/control/filtering/status') {
              req.response
                ..statusCode = 200
                ..headers.contentType = ContentType.json
                ..write(jsonEncode({
                  'filters': <dynamic>[],
                  'whitelist_filters': <dynamic>[],
                  'user_rules': <dynamic>[],
                  'interval': 24,
                  'enabled': true,
                }));
            } else {
              req.response.statusCode = 404;
            }
            await req.response.close();
          });

          final srv = Server(
            id: 'narrow-srv',
            name: 'Narrow',
            connectionMethod: 'http',
            domain: '127.0.0.1',
            port: httpSrv.port,
            defaultServer: true,
            runningOnHa: false,
          );
          final sp = ServersProvider()
            ..setSelectedServer(srv)
            ..setApiClient2(ApiClientV2(server: srv));
          final fp = FilteringProvider()..update(sp, null);
          final lp = LogsProvider()..update(sp);
          final statusP = StatusProvider()..update(sp);
          final themeColorCfg =
              _ThemeColorAppConfigProvider(sharedPreferencesInstance: prefs);

          // Narrow 300px viewport + dark theme + 1.8x accessibility text scale + useThemeColorForStatus=true
          tester.view.physicalSize = const Size(300, 700);
          tester.view.devicePixelRatio = 1.0;
          addTearDown(tester.view.resetPhysicalSize);
          addTearDown(tester.view.resetDevicePixelRatio);

          await tester.pumpWidget(
            MultiProvider(
              providers: [
                ChangeNotifierProvider.value(value: sp),
                ChangeNotifierProvider.value(value: fp),
                ChangeNotifierProvider.value(value: lp),
                ChangeNotifierProvider.value(value: statusP),
                ChangeNotifierProvider<AppConfigProvider>.value(
                  value: themeColorCfg,
                ),
              ],
              child: MaterialApp(
                locale: const Locale('zh'),
                theme: ThemeData.dark(),
                localizationsDelegates: AppLocalizations.localizationsDelegates,
                supportedLocales: AppLocalizations.supportedLocales,
                home: const MediaQuery(
                  data: MediaQueryData(textScaler: TextScaler.linear(1.8)),
                  child: Logs(),
                ),
              ),
            ),
          );
          await Future<void>.delayed(const Duration(milliseconds: 100));
          await tester.pumpAndSettle();

          // Paused protection MUST render processed (using theme primary color, NEVER red "已拦截")
          final indFinder = find.byType(LogStatusIndicator);
          expect(indFinder, findsOneWidget);
          expect(find.descendant(of: indFinder, matching: find.text('已处理\n无拦截')), findsOneWidget);
          expect(find.descendant(of: indFinder, matching: find.textContaining('已拦截')), findsNothing);
          final processedIcon = tester.widget<Icon>(
            find.descendant(of: indFinder, matching: find.byIcon(Icons.verified_user_rounded)),
          );
          expect(processedIcon.color, isNot(Colors.red));
          expect(find.descendant(of: indFinder, matching: find.byIcon(Icons.expand_more_rounded)), findsOneWidget);
          expect(tester.takeException(), isNull);

          // Tap aggregated row to verify predictedBlocked detail note is preserved
          await tester.tap(find.text('very-very-long-subdomain-that-should-ellipsize-cleanly.example.co.uk'));
          await tester.pumpAndSettle();
          expect(find.textContaining('因保护暂停实际已放行'), findsOneWidget);
          await tester.tap(find.text('关闭'));
          await tester.pumpAndSettle();

          // Test LogStatusIndicator dark + useThemeColorForStatus=true for FilteredBlackList -> Colors.grey
          await tester.pumpWidget(
            ChangeNotifierProvider<AppConfigProvider>.value(
              value: themeColorCfg,
              child: MaterialApp(
                locale: const Locale('zh'),
                theme: ThemeData.dark(),
                localizationsDelegates: AppLocalizations.localizationsDelegates,
                supportedLocales: AppLocalizations.supportedLocales,
                home: const Scaffold(
                  body: LogStatusIndicator(
                    reason: 'FilteredBlackList',
                    showExpandArrow: true,
                  ),
                ),
              ),
            ),
          );
          await tester.pumpAndSettle();
          final blkIcon = tester.widget<Icon>(find.byIcon(Icons.gpp_bad_rounded));
          expect(blkIcon.color, Colors.grey);
          expect(find.text('已拦截\n黑名单'), findsOneWidget);
          expect(find.byIcon(Icons.expand_more_rounded), findsOneWidget);
        }, _PassthroughHttpOverrides());
      });
    });
  });

  group('Mixed Normal & Aggregated Column Alignment Tests', () {
    Future<void> loadPreviewFontsIfNeeded() async {
      final iconFile = File(
        '/opt/homebrew/share/flutter/bin/cache/artifacts/material_fonts/MaterialIcons-Regular.otf',
      );
      if (iconFile.existsSync()) {
        final loader = FontLoader('MaterialIcons')
          ..addFont(Future.value(ByteData.sublistView(iconFile.readAsBytesSync())));
        await loader.load();
      }
      final cjkFile = File('/System/Library/Fonts/Hiragino Sans GB.ttc');
      if (cjkFile.existsSync()) {
        final bytes = ByteData.sublistView(cjkFile.readAsBytesSync());
        for (final family in const ['Roboto', '.AppleSystemUIFont']) {
          final loader = FontLoader(family)..addFont(Future.value(bytes));
          await loader.load();
        }
      }
    }

    Future<void> runMixedAlignmentCase(
      WidgetTester tester, {
      required Locale locale,
      required Size viewportSize,
      required double textScale,
      required String captureTag,
      bool capturePreview = false,
    }) async {
      SharedPreferences.setMockInitialValues({});
      final prefs = await SharedPreferences.getInstance();
      final cfg = AppConfigProvider(sharedPreferencesInstance: prefs);
      const ts = '2026-11-17T01:10:00.000Z';

      // Alternate single rows (rendered by LogTile) and repeated duplicate pairs
      // (rendered by _AggregatedLogsPageTile) in the same ListView.
      final queryLogs = <Map<String, dynamic>>[
        // Row 1 (single): FilteredBlackList
        _logJson(
          domain: 'single-blk-verylong-domain-name-example.doubleclick.net',
          reason: 'FilteredBlackList',
          timeIso: ts,
          rules: [
            {'text': '||doubleclick.net^', 'filter_list_id': 1},
          ],
        ),
        // Row 2 (aggregated x2): FilteredBlackList
        _logJson(
          domain: 'dup-blk.tracker.example.com',
          reason: 'FilteredBlackList',
          timeIso: ts,
          rules: [
            {'text': '||dup-blk.tracker.example.com^', 'filter_list_id': 1},
          ],
        ),
        _logJson(
          domain: 'dup-blk.tracker.example.com',
          reason: 'FilteredBlackList',
          timeIso: ts,
          rules: [
            {'text': '||dup-blk.tracker.example.com^', 'filter_list_id': 1},
          ],
        ),
        // Row 3 (single): NotFilteredNotFound
        _logJson(
          domain: 'single-ok.cdn.example.org',
          reason: 'NotFilteredNotFound',
          timeIso: ts,
        ),
        // Row 4 (aggregated x2): NotFilteredNotFound
        _logJson(
          domain: 'dup-ok.api.example.org',
          reason: 'NotFilteredNotFound',
          timeIso: ts,
        ),
        _logJson(
          domain: 'dup-ok.api.example.org',
          reason: 'NotFilteredNotFound',
          timeIso: ts,
        ),
        // Row 5 (single): FilteredSNI
        _logJson(
          domain: 'single-sni-blk.example.net',
          reason: 'FilteredSNI',
          qtype: 'SNI',
          clientProto: 'sni',
          timeIso: ts,
          rules: [
            {'text': '||single-sni-blk.example.net^', 'filter_list_id': 1},
          ],
        ),
        // Row 6 (aggregated x2): FilteredSNI
        _logJson(
          domain: 'dup-sni-blk.example.net',
          reason: 'FilteredSNI',
          qtype: 'SNI',
          clientProto: 'sni',
          timeIso: ts,
          rules: [
            {'text': '||dup-sni-blk.example.net^', 'filter_list_id': 1},
          ],
        ),
        _logJson(
          domain: 'dup-sni-blk.example.net',
          reason: 'FilteredSNI',
          qtype: 'SNI',
          clientProto: 'sni',
          timeIso: ts,
          rules: [
            {'text': '||dup-sni-blk.example.net^', 'filter_list_id': 1},
          ],
        ),
        // Row 7 (single): NotFilteredSNI
        _logJson(
          domain: 'single-sni-ok.example.net',
          reason: 'NotFilteredSNI',
          qtype: 'SNI',
          clientProto: 'sni',
          timeIso: ts,
        ),
        // Row 8 (aggregated x2): NotFilteredSNI
        _logJson(
          domain: 'dup-sni-ok.example.net',
          reason: 'NotFilteredSNI',
          qtype: 'SNI',
          clientProto: 'sni',
          timeIso: ts,
        ),
        _logJson(
          domain: 'dup-sni-ok.example.net',
          reason: 'NotFilteredSNI',
          qtype: 'SNI',
          clientProto: 'sni',
          timeIso: ts,
        ),
      ];

      final httpSrv = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() => httpSrv.close(force: true));
      httpSrv.listen((req) async {
        if (req.uri.path == '/control/querylog') {
          req.response
            ..statusCode = 200
            ..headers.contentType = ContentType.json
            ..write(jsonEncode({'data': queryLogs, 'oldest': ts}));
        } else if (req.uri.path == '/control/filtering/status') {
          req.response
            ..statusCode = 200
            ..headers.contentType = ContentType.json
            ..write(jsonEncode({
              'filters': [
                {'id': 1, 'name': 'AdRules', 'enabled': true, 'url': ''},
              ],
              'whitelist_filters': <dynamic>[],
              'user_rules': <dynamic>[],
              'interval': 24,
              'enabled': true,
            }));
        } else {
          req.response.statusCode = 404;
        }
        await req.response.close();
      });

      final srv = Server(
        id: 'align-srv-$captureTag',
        name: 'AlignServer',
        connectionMethod: 'http',
        domain: '127.0.0.1',
        port: httpSrv.port,
        defaultServer: true,
        runningOnHa: false,
      );
      final sp = ServersProvider()
        ..setSelectedServer(srv)
        ..setApiClient2(ApiClientV2(server: srv));
      final fp = FilteringProvider()..update(sp, null);
      final lp = LogsProvider()..update(sp);
      final statusP = StatusProvider()..update(sp);

      tester.view.physicalSize = viewportSize;
      tester.view.devicePixelRatio = capturePreview ? 2.0 : 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      if (capturePreview) {
        await loadPreviewFontsIfNeeded();
      }

      final repaintKey = GlobalKey();
      await tester.pumpWidget(
        RepaintBoundary(
          key: repaintKey,
          child: MultiProvider(
            providers: [
              ChangeNotifierProvider.value(value: sp),
              ChangeNotifierProvider.value(value: fp),
              ChangeNotifierProvider.value(value: lp),
              ChangeNotifierProvider.value(value: statusP),
              ChangeNotifierProvider<AppConfigProvider>.value(value: cfg),
            ],
            child: MaterialApp(
              debugShowCheckedModeBanner: false,
              locale: locale,
              theme: ThemeData(
                colorSchemeSeed: Colors.blue,
                useMaterial3: true,
                fontFamily: capturePreview ? 'Roboto' : null,
              ),
              localizationsDelegates: AppLocalizations.localizationsDelegates,
              supportedLocales: AppLocalizations.supportedLocales,
              home: Builder(
                builder: (ctx) => MediaQuery(
                  data: MediaQuery.of(ctx).copyWith(
                    textScaler: TextScaler.linear(textScale),
                  ),
                  child: const Logs(),
                ),
              ),
            ),
          ),
        ),
      );
      await Future<void>.delayed(const Duration(milliseconds: 120));
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);

      final verticalScrollable = find.byWidgetPredicate(
        (w) => w is Scrollable && w.axisDirection == AxisDirection.down,
      );

      final expectedRows = <({String domain, bool aggregated})>[
        (domain: 'dup-sni-blk.example.net', aggregated: true),
        (domain: 'dup-sni-ok.example.net', aggregated: true),
        (domain: 'single-sni-blk.example.net', aggregated: false),
        (domain: 'single-sni-ok.example.net', aggregated: false),
        (domain: 'dup-blk.tracker.example.com', aggregated: true),
        (domain: 'dup-ok.api.example.org', aggregated: true),
        (domain: 'single-blk-verylong-domain-name-example.doubleclick.net', aggregated: false),
        (domain: 'single-ok.cdn.example.org', aggregated: false),
      ];

      final measuredCenters = <double>[];
      final measuredArrowCenters = <double>[];

      for (final row in expectedRows) {
        final dFinder = find.text(row.domain);
        await tester.scrollUntilVisible(
          dFinder,
          120,
          scrollable: verticalScrollable,
        );
        await tester.pumpAndSettle();
        expect(dFinder, findsOneWidget);

        final tileInkWell = find.ancestor(of: dFinder, matching: find.byType(InkWell));
        final indicator = find.descendant(
          of: tileInkWell,
          matching: find.byType(LogStatusIndicator),
        );
        final statusArea = find.descendant(
          of: indicator,
          matching: find.byKey(LogStatusIndicator.statusAreaKey),
        );
        final arrowSlot = find.descendant(
          of: indicator,
          matching: find.byKey(LogStatusIndicator.arrowSlotKey),
        );
        expect(statusArea, findsOneWidget);
        expect(arrowSlot, findsOneWidget);

        final statusRect = tester.getRect(statusArea);
        final arrowRect = tester.getRect(arrowSlot);
        final statusIconFinder = find.descendant(of: statusArea, matching: find.byType(Icon));
        final statusTextFinder = find.descendant(of: statusArea, matching: find.byType(Text));
        final statusIconWidget = tester.widget<Icon>(statusIconFinder);
        final statusTextWidget = tester.widget<Text>(statusTextFinder);
        expect((statusTextWidget.data ?? '').trim(), isNotEmpty);

        // Icon and Text must both be centered horizontally within statusArea
        expect(
          (tester.getCenter(statusIconFinder).dx - statusRect.center.dx).abs(),
          lessThanOrEqualTo(0.01),
        );
        expect(
          (tester.getCenter(statusTextFinder).dx - statusRect.center.dx).abs(),
          lessThanOrEqualTo(0.01),
        );
        expect(statusIconWidget.size, 14);
        expect(arrowRect.width, closeTo(LogStatusIndicator.arrowSlotWidth, 0.01));

        // Arrow present ONLY on aggregated rows, empty same-width slot on normal rows
        final arrowIcon = find.descendant(
          of: arrowSlot,
          matching: find.byIcon(Icons.expand_more_rounded),
        );
        expect(arrowIcon, row.aggregated ? findsOneWidget : findsNothing);

        measuredCenters.add(statusRect.center.dx);
        measuredArrowCenters.add(arrowRect.center.dx);
        debugPrint(
          '[$captureTag] aggregated=${row.aggregated} domain=${row.domain} '
          'statusRect=${statusRect.left.toStringAsFixed(1)}..${statusRect.right.toStringAsFixed(1)} '
          'centerX=${statusRect.center.dx.toStringAsFixed(2)} '
          'arrowX=${arrowRect.center.dx.toStringAsFixed(2)} '
          'label=${(statusTextWidget.data ?? '').replaceAll('\n', '/')}',
        );
      }

      // Every normal & aggregated row shares the exact same statusArea center X and arrowSlot center X
      final baseCenter = measuredCenters.first;
      final baseArrowCenter = measuredArrowCenters.first;
      for (final x in measuredCenters) {
        expect((x - baseCenter).abs(), lessThanOrEqualTo(0.01));
      }
      for (final ax in measuredArrowCenters) {
        expect((ax - baseArrowCenter).abs(), lessThanOrEqualTo(0.01));
      }

      // Capture screenshot from top of list (showing SNI & DNS normal+aggregated mix)
      await tester.scrollUntilVisible(
        find.text('dup-sni-blk.example.net'),
        -200,
        scrollable: verticalScrollable,
      );
      await tester.pumpAndSettle();

      if (capturePreview) {
        final previewPath = Platform.environment['AGH_CAPTURE_PREVIEW_PATH'];
        if (previewPath != null && previewPath.isNotEmpty) {
          final boundary = repaintKey.currentContext!.findRenderObject()!
              as RenderRepaintBoundary;
          final image = await boundary.toImage(pixelRatio: 2.0);
          final byteData = await image.toByteData(format: ui.ImageByteFormat.png);
          if (byteData != null) {
            final outFile = File(previewPath);
            outFile.parent.createSync(recursive: true);
            outFile.writeAsBytesSync(byteData.buffer.asUint8List());
          }
        }
      }

      // Tap aggregated row -> opens detail dialog with raw events
      await tester.scrollUntilVisible(
        find.text('dup-blk.tracker.example.com'),
        150,
        scrollable: verticalScrollable,
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('dup-blk.tracker.example.com'));
      await tester.pumpAndSettle();
      expect(find.text('原始事件详情:'), findsOneWidget);
      await tester.tap(find.text('关闭'));
      await tester.pumpAndSettle();

      // Tap normal row -> opens standard log detail dialog
      await tester.scrollUntilVisible(
        find.text('single-ok.cdn.example.org'),
        150,
        scrollable: verticalScrollable,
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('single-ok.cdn.example.org'));
      await tester.pumpAndSettle();
      expect(find.byType(AlertDialog), findsOneWidget);
      Navigator.of(tester.element(find.byType(AlertDialog))).pop();
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
    }

    testWidgets('Normal and aggregated rows align across zh/en viewports and narrow 300px + 1.8x scale', (tester) async {
      await tester.runAsync(() async {
        await HttpOverrides.runWithHttpOverrides(() async {
          await runMixedAlignmentCase(
            tester,
            locale: const Locale('zh'),
            viewportSize: const Size(820, 1520), // 410x760 @ dpr 2.0 when capturePreview=true
            textScale: 1.0,
            captureTag: 'zh-410',
            capturePreview: true,
          );
          await runMixedAlignmentCase(
            tester,
            locale: const Locale('en'),
            viewportSize: const Size(410, 760),
            textScale: 1.0,
            captureTag: 'en-410',
          );
          await runMixedAlignmentCase(
            tester,
            locale: const Locale('zh'),
            viewportSize: const Size(300, 760),
            textScale: 1.8,
            captureTag: 'zh-300-1.8x',
          );
          await runMixedAlignmentCase(
            tester,
            locale: const Locale('en'),
            viewportSize: const Size(300, 760),
            textScale: 1.8,
            captureTag: 'en-300-1.8x',
          );
        }, _PassthroughHttpOverrides());
      });
    });

    testWidgets('Toggling showExpandArrow preserves exact statusArea coordinates', (tester) async {
      SharedPreferences.setMockInitialValues({});
      final prefs = await SharedPreferences.getInstance();
      final cfg = AppConfigProvider(sharedPreferencesInstance: prefs);

      Widget buildIndicatorRow({required bool showArrow}) {
        return ChangeNotifierProvider<AppConfigProvider>.value(
          value: cfg,
          child: MaterialApp(
            locale: const Locale('zh'),
            localizationsDelegates: AppLocalizations.localizationsDelegates,
            supportedLocales: AppLocalizations.supportedLocales,
            home: Scaffold(
              body: SizedBox(
                width: 380,
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      const Expanded(child: Text('example.com')),
                      const SizedBox(width: 10),
                      LogStatusIndicator(
                        reason: 'FilteredSNI',
                        showExpandArrow: showArrow,
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        );
      }

      await tester.pumpWidget(buildIndicatorRow(showArrow: false));
      await tester.pumpAndSettle();
      final beforeRect = tester.getRect(find.byKey(LogStatusIndicator.statusAreaKey));
      expect(find.byIcon(Icons.expand_more_rounded), findsNothing);

      await tester.pumpWidget(buildIndicatorRow(showArrow: true));
      await tester.pumpAndSettle();
      final afterRect = tester.getRect(find.byKey(LogStatusIndicator.statusAreaKey));
      expect(find.byIcon(Icons.expand_more_rounded), findsOneWidget);

      expect(afterRect.left, closeTo(beforeRect.left, 0.01));
      expect(afterRect.right, closeTo(beforeRect.right, 0.01));
      expect(afterRect.width, closeTo(beforeRect.width, 0.01));
      expect(afterRect.center.dx, closeTo(beforeRect.center.dx, 0.01));
    });
  });
}
