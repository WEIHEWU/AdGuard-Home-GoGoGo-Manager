import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:adguard_home_manager/models/logs.dart';
import 'package:adguard_home_manager/models/server.dart';
import 'package:adguard_home_manager/services/api_client.dart';
import 'package:adguard_home_manager/services/diagnostic_redactor.dart';
import 'package:adguard_home_manager/services/domain_input_parser.dart';
import 'package:adguard_home_manager/services/host_rule_diagnostics.dart';
import 'package:adguard_home_manager/widgets/troubleshooter_rule_panel.dart';

void main() {
  group('1-2. DomainInputParser & Bounded Parent Chain', () {
    test('extracts SendGrid host safely without accessing URL or mutating tokens, handles IDN, port, trailing dot and rejects ambiguous/multi links', () {
      final sg = DomainInputParser.parseSingleInput(
        '  "<https://U56112681.CT.SendGrid.NET.:443/ls/click?upn=SECRET_TOKEN_XYZ#frag>"  ',
      );
      expect(sg.ok, isTrue);
      expect(sg.normalizedHost, 'u56112681.ct.sendgrid.net');
      expect(sg.isIpAddress, isFalse);

      final bare = DomainInputParser.parseSingleInput('u56112681.ct.sendgrid.net.');
      expect(bare.ok, isTrue);
      expect(bare.normalizedHost, 'u56112681.ct.sendgrid.net');

      final idn = DomainInputParser.parseSingleInput('https://例子.测试/path');
      expect(idn.ok, isTrue);
      expect(idn.normalizedHost, 'xn--fsqu00a.xn--0zwm56d');
      expect(idn.unicodeHost, '例子.测试');

      final ipv6 = DomainInputParser.parseSingleInput('https://[2001:db8::1]:8443/x');
      expect(ipv6.ok, isTrue);
      expect(ipv6.isIpAddress, isTrue);
      expect(ipv6.normalizedHost, '2001:db8::1');

      // Ambiguous whitespace in authority or multiple URLs MUST fail instead of silent merge
      for (final bad in const <String>[
        '',
        'a.com b.com',
        'u56112681. ct.sendgrid.net',
        'https://a.com https://b.com',
        'javascript:alert(1)',
        'example.com:99999',
        'singlelabel',
      ]) {
        final r = DomainInputParser.parseSingleInput(bad);
        expect(r.ok, isFalse, reason: 'Expected rejection for: $bad');
      }
    });

    test('builds bounded parent domain list stopping at registrable domain (SendGrid, co.uk, com.au, IP)', () {
      expect(
        DomainInputParser.buildParentDomains('u56112681.ct.sendgrid.net'),
        <String>[
          'u56112681.ct.sendgrid.net',
          'ct.sendgrid.net',
          'sendgrid.net',
        ],
      );
      expect(
        DomainInputParser.buildParentDomains('a.b.example.co.uk'),
        <String>[
          'a.b.example.co.uk',
          'b.example.co.uk',
          'example.co.uk',
        ],
      );
      expect(
        DomainInputParser.buildParentDomains('track.shop.com.au'),
        <String>[
          'track.shop.com.au',
          'shop.com.au',
        ],
      );
      expect(
        DomainInputParser.buildParentDomains('192.168.1.10'),
        <String>['192.168.1.10'],
      );
      expect(DomainInputParser.isPublicSuffix('net'), isTrue);
      expect(DomainInputParser.isPublicSuffix('co.uk'), isTrue);
      expect(DomainInputParser.isPublicSuffix('com.au'), isTrue);
      expect(DomainInputParser.buildParentDomains('co.uk'), isEmpty);

      // Depth limit enforced cleanly
      final deep = DomainInputParser.buildParentDomains(
        'l8.l7.l6.l5.l4.l3.l2.l1.example.com',
        maxDepth: 4,
      );
      expect(deep.length, 4);
    });
  });

  group('3-5, 11-13. Real-Time Check, Status Parsing, Concurrency, Cancellation & Zero URL Visit', () {
    test('queries original A/AAAA + parents with concurrency <= 3, resolves list sources, never visits pasted tracking URL, and never marks failures as allowed', () async {
      // Trap server simulating the tracking URL in the input: must NEVER be hit!
      final trapServer = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() => trapServer.close(force: true));
      var trapHitCount = 0;
      trapServer.listen((req) {
        trapHitCount++;
        req.response.close();
      });

      final trackingUrl =
          'http://127.0.0.1:${trapServer.port}/ls/click?upn=SHOULD_NOT_BE_VISITED_OR_LOGGED';
      final parsedTrap = DomainInputParser.parseSingleInput(trackingUrl);
      expect(parsedTrap.ok, isTrue);
      expect(trapHitCount, 0);

      // Also test full SendGrid chain against mock checkHost
      final parsedSg = DomainInputParser.parseSingleInput(
        'https://u56112681.ct.sendgrid.net/ls/click?upn=TOP_SECRET_CLICK_TOKEN',
      );
      expect(parsedSg.ok, isTrue);

      var inFlight = 0;
      var maxObservedConcurrency = 0;
      final queried = <String>[];

      final report = await RuleBatchChecker.checkDomainFamily(
        parsed: parsedSg,
        isCancelled: () => false,
        filterNames: const {12: 'AdGuard DNS filter'},
        whitelistNames: const {99: 'My Allowlist'},
        checker: (host, qtype) async {
          inFlight++;
          if (inFlight > maxObservedConcurrency) {
            maxObservedConcurrency = inFlight;
          }
          queried.add('$host:$qtype');
          await Future<void>.delayed(const Duration(milliseconds: 20));
          inFlight--;

          if (host == 'u56112681.ct.sendgrid.net' && qtype == 'A') {
            return const ApiResponse(
              successful: true,
              content: {
                'reason': 'FilteredBlackList',
                'rules': [
                  {'text': '||ct.sendgrid.net^', 'filter_list_id': 12},
                  {'text': '||sendgrid.net^', 'filter_list_id': 0},
                  {'text': '||unknown.list^', 'filter_list_id': 777},
                ],
              },
            );
          }
          if (host == 'sendgrid.net') {
            return const ApiResponse(successful: false, statusCode: 404);
          }
          return const ApiResponse(
            successful: true,
            content: {'reason': 'NotFilteredNotFound', 'rules': []},
          );
        },
      );

      expect(maxObservedConcurrency, lessThanOrEqualTo(3));
      expect(report, isNotNull);
      expect(report!.effectiveOriginal.status, RuleCheckStatus.blocked);
      expect(report.effectiveOriginal.rules.length, 3);
      expect(report.effectiveOriginal.rules[0].sourceName, 'AdGuard DNS filter');
      expect(report.effectiveOriginal.rules[1].sourceName, '自定义规则');
      expect(report.effectiveOriginal.rules[2].sourceName, '来源 ID 777');
      expect(report.parentResults[0].host, 'ct.sendgrid.net');
      expect(report.parentResults[1].status, RuleCheckStatus.unsupported);

      // Query failure MUST NOT be treated as allowed / normal
      final failRes = HostCheckResult.fromApiResponse(
        host: 'x.example',
        response: const ApiResponse(successful: false, content: 'timeout'),
        isOriginal: true,
      );
      expect(failRes.status, RuleCheckStatus.failed);
      expect(failRes.statusLabel, isNot(contains('正常')));
      expect(failRes.statusLabel, isNot(contains('放行')));

      // Stale request discarded when cancelled
      var cancelled = false;
      final staleFuture = RuleBatchChecker.checkDomainFamily(
        parsed: parsedSg,
        isCancelled: () => cancelled,
        checker: (host, qtype) async {
          await Future<void>.delayed(const Duration(milliseconds: 60));
          return const ApiResponse(
            successful: true,
            content: {'reason': 'NotFilteredNotFound', 'rules': []},
          );
        },
      );
      cancelled = true;
      expect(await staleFuture, isNull);

      // Token redactor also catches tracking token if ever present in logs
      final safe = DiagnosticRedactor.redact(
        'https://u56112681.ct.sendgrid.net/ls/click?upn=TOP_SECRET_CLICK_TOKEN',
      );
      expect(safe, isNot(contains('TOP_SECRET_CLICK_TOKEN')));
      expect(trapHitCount, 0);
    });
  });

  group('4, 6, 12. SNI Classification, Event Aggregation & Core Blocked Summary', () {
    test('classifies FilteredSNI first, aggregates same-second duplicates before truncation while keeping distinct rules/protos/clients separate, and parses bounded Core summary', () {
      final t1 = DateTime.utc(2026, 11, 16, 21, 19, 36, 100);
      final t1b = DateTime.utc(2026, 11, 16, 21, 19, 36, 900);
      final t2 = DateTime.utc(2026, 11, 16, 21, 19, 37, 100);

      final rawLogs = <Log>[
        // 18 duplicates in same second 21:19:36 for ogads
        for (var i = 0; i < 18; i++)
          Log(
            cached: false,
            client: '10.0.0.2',
            clientProto: '',
            elapsedMs: '1',
            question: Question(
              questionClass: 'IN',
              name: 'ogads-pa.clients6.google.com',
              type: 'A',
            ),
            reason: 'FilteredBlackList',
            rules: [Rule(filterListId: 1, text: '||ogads-pa.clients6.google.com^')],
            time: i % 2 == 0 ? t1 : t1b,
            upstream: '',
            answer: const [],
          ),
        // Same second & domain, DIFFERENT client_proto/reason (FilteredSNI) -> separate group!
        Log(
          cached: false,
          client: '10.0.0.2',
          clientProto: '',
          elapsedMs: '0',
          question: Question(
            questionClass: 'IN',
            name: 'u56112681.ct.sendgrid.net',
            type: 'A',
          ),
          reason: 'FilteredSNI',
          rules: [Rule(filterListId: 42, text: '||ct.sendgrid.net^')],
          time: t1,
          upstream: '',
          destination: '1.2.3.4:443',
          answer: const [],
        ),
        // Different client for ogads -> separate group!
        Log(
          cached: false,
          client: '10.0.0.99',
          clientProto: '',
          elapsedMs: '1',
          question: Question(
            questionClass: 'IN',
            name: 'ogads-pa.clients6.google.com',
            type: 'A',
          ),
          reason: 'FilteredBlackList',
          rules: [Rule(filterListId: 1, text: '||ogads-pa.clients6.google.com^')],
          time: t2,
          upstream: '',
          answer: const [],
        ),
      ];

      final groups = BlockedEventAggregator.aggregateRawLogs(
        rawLogs,
        filterNames: const {1: 'Base', 42: 'SendGrid Blocklist'},
        maxGroups: 3,
      );
      expect(groups.length, 3);

      final sniGroup = groups.firstWhere((g) => g.domain == 'u56112681.ct.sendgrid.net');
      expect(sniGroup.isSni, isTrue);
      expect(sniGroup.reason, 'FilteredSNI');
      expect(sniGroup.matchedRules.first.sourceName, 'SendGrid Blocklist');

      final ogGroup = groups.firstWhere(
        (g) => g.domain == 'ogads-pa.clients6.google.com' && g.count == 18,
      );
      expect(ogGroup.isSni, isFalse);
      expect(ogGroup.rawEvents.length, 18);

      final coreSummary = BlockedSummaryData.fromJson({
        'max_entries': 256,
        'ttl_seconds': 300,
        'data': [
          {
            'domain': 'u56112681.ct.sendgrid.net',
            'reason': 'FilteredSNI',
            'is_sni': true,
            'count': 2,
            'first_time': t1.toIso8601String(),
            'time': t2.toIso8601String(),
            'client': '10.0.0.2',
            'rules': [
              {'filter_list_id': 42, 'text': '||ct.sendgrid.net^'}
            ],
          }
        ],
      });
      expect(coreSummary.maxEntries, 256);
      expect(coreSummary.ttlSeconds, 300);
      expect(coreSummary.entries.single.isSni, isTrue);
      expect(coreSummary.entries.single.count, 2);
    });
  });

  group('7-10. WhitelistPlanner, ExceptionRuleCoordinator Write/Verify/Undo & Mock Server', () {
    test('extracts safe anchor rule target, disables unsafe regex/wildcard/path/suffix, and never expands to registrable root', () {
      expect(WhitelistPlanner.extractSafeAnchorDomain('||ct.sendgrid.net^'), 'ct.sendgrid.net');
      expect(WhitelistPlanner.extractSafeAnchorDomain('||ct.sendgrid.net^\$important'), 'ct.sendgrid.net');
      expect(WhitelistPlanner.extractSafeAnchorDomain('/^u.*\\.sendgrid\\.net\$/'), isNull);
      expect(WhitelistPlanner.extractSafeAnchorDomain('||*.sendgrid.net^'), isNull);
      expect(WhitelistPlanner.extractSafeAnchorDomain('||ct.sendgrid.net/ls/click^'), isNull);
      expect(WhitelistPlanner.extractSafeAnchorDomain('||co.uk^'), isNull);
      expect(WhitelistPlanner.extractSafeAnchorDomain('||net^'), isNull);

      final sg = WhitelistPlanner.buildSuggestion(
        originalHost: 'u56112681.ct.sendgrid.net',
        matchedRules: const [
          MatchedRuleInfo(
            text: '||ct.sendgrid.net^',
            filterListId: 42,
            sourceName: 'Block',
          ),
        ],
      );
      expect(sg.narrowRule, '@@||u56112681.ct.sendgrid.net^');
      expect(sg.narrowDescription, contains('不放行'));
      expect(sg.narrowDescription, isNot(contains('仅精确这一台主机')));
      expect(sg.broadRule, '@@||ct.sendgrid.net^');
      expect(sg.broadTargetHost, isNot('sendgrid.net'));

      final regexSug = WhitelistPlanner.buildSuggestion(
        originalHost: 'u56112681.ct.sendgrid.net',
        matchedRules: const [
          MatchedRuleInfo(
            text: '/sendgrid/',
            filterListId: 1,
            sourceName: 'Regex',
          ),
        ],
      );
      expect(regexSug.narrowRule, '@@||u56112681.ct.sendgrid.net^');
      expect(regexSug.broadRule, isNull);
      expect(regexSug.broadDisabledReason, isNotNull);
    });

    test('serialized write preserves pre-existing rules, verifies unblocked vs \$important block, and cleanly undoes only added rule', () async {
      await HttpOverrides.runWithHttpOverrides(() async {
        final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
        addTearDown(() => server.close(force: true));

      final userRules = <String>[
        '! comment preserved',
        '||existing.ad.example^',
        '||imp.example^\$important',
      ];
      var cacheCleared = 0;

      server.listen((req) async {
        final path = req.uri.path;
        if (path == '/control/filtering/status') {
          req.response
            ..statusCode = 200
            ..headers.contentType = ContentType.json
            ..write(jsonEncode({
              'filters': [],
              'whitelist_filters': [],
              'user_rules': userRules,
              'interval': 24,
              'enabled': true,
            }));
          await req.response.close();
          return;
        }
        if (path == '/control/filtering/set_rules') {
          final raw = await utf8.decoder.bind(req).join();
          final body = jsonDecode(raw) as Map<String, dynamic>;
          userRules
            ..clear()
            ..addAll((body['rules'] as List).map((e) => e.toString()));
          req.response
            ..statusCode = 200
            ..write('OK');
          await req.response.close();
          return;
        }
        if (path == '/control/cache_clear') {
          cacheCleared++;
          req.response
            ..statusCode = 200
            ..write('OK');
          await req.response.close();
          return;
        }
        if (path == '/control/filtering/check_host') {
          final host = req.uri.queryParameters['name'] ?? '';
          Map<String, dynamic> resp;
          if (host == 'imp.example' &&
              !userRules.contains('@@||imp.example^\$important')) {
            resp = {
              'reason': 'FilteredBlackList',
              'rules': [
                {'text': '||imp.example^\$important', 'filter_list_id': 0}
              ],
            };
          } else if (host == 'u56112681.ct.sendgrid.net' &&
              !userRules.contains('@@||u56112681.ct.sendgrid.net^')) {
            resp = {
              'reason': 'FilteredBlackList',
              'rules': [
                {'text': '||ct.sendgrid.net^', 'filter_list_id': 42}
              ],
            };
          } else {
            resp = {
              'reason': 'NotFilteredWhiteList',
              'rules': [
                {'text': '@@||$host^', 'filter_list_id': 0}
              ],
            };
          }
          req.response
            ..statusCode = 200
            ..headers.contentType = ContentType.json
            ..write(jsonEncode(resp));
          await req.response.close();
          return;
        }
        req.response.statusCode = 404;
        await req.response.close();
      });

      final apiClient = ApiClientV2(
        server: Server(
          id: 'test-srv',
          name: 'Test',
          connectionMethod: 'http',
          domain: '127.0.0.1',
          port: server.port,
          defaultServer: true,
          runningOnHa: false,
        ),
      );

      final coord = ExceptionRuleCoordinator();

      // 1) Normal exception on SendGrid -> succeeds, preserves all prior rules, cache cleared, post-check confirmed!
      final outOk = await coord.applyExceptionAndVerify(
        apiClient: apiClient,
        verifyHost: 'u56112681.ct.sendgrid.net',
        exceptionRule: '@@||u56112681.ct.sendgrid.net^',
      );
      expect(outOk.writeSucceeded, isTrue);
      expect(outOk.verifiedUnblocked, isTrue);
      expect(outOk.stillBlockedByImportant, isFalse);
      expect(outOk.message, contains('放行已生效'));
      expect(cacheCleared, greaterThanOrEqualTo(1));
      expect(
        userRules,
        <String>[
          '! comment preserved',
          '||existing.ad.example^',
          '||imp.example^\$important',
          '@@||u56112681.ct.sendgrid.net^',
        ],
      );

      // 2) Concurrent writes on different rules -> serialized without losing either!
      final fA = coord.applyExceptionAndVerify(
        apiClient: apiClient,
        verifyHost: 'imp.example',
        exceptionRule: '@@||imp.example^',
      );
      final fB = coord.applyExceptionAndVerify(
        apiClient: apiClient,
        verifyHost: 'sub2.example.org',
        exceptionRule: '@@||sub2.example.org^',
      );
      final results = await Future.wait([fA, fB]);

      // imp.example normal exception MUST detect $important still blocks it and NOT lie as resolved!
      expect(results[0].writeSucceeded, isTrue);
      expect(results[0].verifiedUnblocked, isFalse);
      expect(results[0].stillBlockedByImportant, isTrue);
      expect(userRules, contains('@@||imp.example^'));
      expect(userRules, contains('@@||sub2.example.org^'));

      // 3) Undo removes ONLY added rule and preserves user's original rules
      final undoRes = await coord.undoAddedException(
        apiClient: apiClient,
        addedRule: '@@||u56112681.ct.sendgrid.net^',
      );
      expect(undoRes.ok, isTrue);
      expect(userRules, isNot(contains('@@||u56112681.ct.sendgrid.net^')));
      expect(userRules, contains('! comment preserved'));
      expect(userRules, contains('||existing.ad.example^'));
      expect(userRules, contains('||imp.example^\$important'));
      }, _PassthroughHttpOverrides());
    });

    testWidgets('LiveRuleDiagnosticCard renders original status, parent helper checks, two-level buttons, post-check & undo actions cleanly', (WidgetTester tester) async {
      final applied = <String>[];
      final undone = <String>[];

      const orig = HostCheckResult(
        host: 'u56112681.ct.sendgrid.net',
        isOriginal: true,
        status: RuleCheckStatus.blocked,
        rawReason: 'FilteredBlackList',
        rules: [
          MatchedRuleInfo(
            text: '||ct.sendgrid.net^',
            filterListId: 42,
            sourceName: 'SendGrid Blocklist',
          ),
        ],
      );
      final parsed = DomainInputParser.parseSingleInput('u56112681.ct.sendgrid.net');
      final report = HostFamilyCheckReport(
        parsedInput: parsed,
        originalA: orig,
        parentResults: const [
          HostCheckResult(
            host: 'ct.sendgrid.net',
            isOriginal: false,
            status: RuleCheckStatus.blocked,
            rawReason: 'FilteredBlackList',
            rules: [
              MatchedRuleInfo(
                text: '||ct.sendgrid.net^',
                filterListId: 42,
                sourceName: 'SendGrid Blocklist',
              ),
            ],
          ),
        ],
      );

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SingleChildScrollView(
              child: LiveRuleDiagnosticCard(
                rawQuery: 'u56112681.ct.sendgrid.net',
                checking: false,
                report: report,
                outcomesByRule: const {
                  '@@||u56112681.ct.sendgrid.net^': ExceptionWriteOutcome(
                    writeSucceeded: true,
                    verifiedUnblocked: true,
                    addedRule: '@@||u56112681.ct.sendgrid.net^',
                    message: '放行已生效（旧连接需重连）',
                  ),
                },
                writeBusy: false,
                onApplyException: (r, {required confirmBroad}) async {
                  applied.add('$r:$confirmBroad');
                },
                onUndoException: (r) async {
                  undone.add(r);
                },
              ),
            ),
          ),
        ),
      );

      expect(find.textContaining('实时规则检测：u56112681.ct.sendgrid.net'), findsOneWidget);
      expect(find.textContaining('辅助检查'), findsOneWidget);
      expect(find.text('已生效'), findsOneWidget);
      expect(find.text('放行规则域名'), findsOneWidget);
      expect(find.textContaining('撤销'), findsOneWidget);

      await tester.tap(find.text('放行规则域名'));
      await tester.pump();
      expect(applied, <String>['@@||ct.sendgrid.net^:true']);

      await tester.tap(find.textContaining('撤销'));
      await tester.pump();
      expect(undone, <String>['@@||u56112681.ct.sendgrid.net^']);
    });
  });
}

class _PassthroughHttpOverrides extends HttpOverrides {}
