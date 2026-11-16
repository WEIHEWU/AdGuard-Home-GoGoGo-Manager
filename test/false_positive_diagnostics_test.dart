import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:adguard_home_manager/models/dns_statistics.dart';
import 'package:adguard_home_manager/models/logs.dart';
import 'package:adguard_home_manager/models/filtering_status.dart' as fs;
import 'package:adguard_home_manager/models/server.dart';
import 'package:adguard_home_manager/models/server_status.dart';
import 'package:adguard_home_manager/providers/filtering_provider.dart';
import 'package:adguard_home_manager/providers/servers_provider.dart';
import 'package:adguard_home_manager/providers/status_provider.dart';
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
      var rev = 1;

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
              'user_rules_revision': 'v2:inst:$rev',
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
          rev++;
          req.response
            ..statusCode = 200
            ..headers.set('X-User-Rules-Revision', 'v2:inst:$rev')
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

      // 1) Normal exception on SendGrid -> succeeds, preserves all prior rules, cache cleared, post-check confirmed, and clean undo removes ONLY added rule!
      final outOk = await coord.applyExceptionAndVerify(
        apiClient: apiClient,
        verifyHost: 'u56112681.ct.sendgrid.net',
        exceptionRule: '@@||u56112681.ct.sendgrid.net^',
      );
      expect(outOk.writeSucceeded, isTrue);
      expect(outOk.verifiedUnblocked, isTrue);
      expect(outOk.stillBlockedByImportant, isFalse);
      expect(outOk.message, contains('规则检测确认放行'));
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

      final undoRes = await coord.undoAddedException(
        apiClient: apiClient,
        addedRule: '@@||u56112681.ct.sendgrid.net^',
        undoToken: outOk.undoToken,
      );
      expect(undoRes.ok, isTrue);
      expect(userRules, isNot(contains('@@||u56112681.ct.sendgrid.net^')));
      expect(userRules, contains('! comment preserved'));
      expect(userRules, contains('||existing.ad.example^'));
      expect(userRules, contains('||imp.example^\$important'));

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
                    undoToken: ExceptionUndoToken(
                      serverKey: 'test',
                      rule: '@@||u56112681.ct.sendgrid.net^',
                      addedIndex: 0,
                      confirmedRevision: 'v2:inst:1',
                      confirmedRulesFingerprint: '',
                      confirmedLocalEpoch: 1,
                    ),
                    message: '规则检测确认放行',
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

  group('RC2 Section 1. Full Offline PSL (ICANN + PRIVATE + Wildcards + Exceptions) & Whitelist Boundary', () {
    test('enforces ICANN, PRIVATE, wildcard, exception, unknown-TLD fallback rejection, unrelated rule rejection, and narrow validation', () {
      // Standard & multi-label ICANN suffixes
      expect(DomainInputParser.registrableDomain('u56112681.ct.sendgrid.net'), 'sendgrid.net');
      expect(DomainInputParser.registrableDomain('a.example.co.uk'), 'example.co.uk');
      expect(DomainInputParser.registrableDomain('a.example.com.au'), 'example.com.au');
      expect(DomainInputParser.isPublicSuffix('co.uk'), isTrue);
      expect(DomainInputParser.isPublicSuffix('com.au'), isTrue);

      // PRIVATE PSL section (github.io, appspot.com)
      final ghMatch = DomainInputParser.inspectPublicSuffix('foo.github.io');
      expect(ghMatch, isNotNull);
      expect(ghMatch!.isKnownRule, isTrue);
      expect(ghMatch.isPrivate, isTrue);
      expect(ghMatch.icann, isFalse);
      expect(ghMatch.registrableDomain, 'foo.github.io');
      expect(DomainInputParser.isPublicSuffix('github.io'), isTrue);
      expect(DomainInputParser.registrableDomain('github.io'), isNull);
      expect(DomainInputParser.buildParentDomains('foo.github.io'), <String>['foo.github.io']);

      expect(DomainInputParser.isPublicSuffix('appspot.com'), isTrue);
      expect(DomainInputParser.registrableDomain('foo.appspot.com'), 'foo.appspot.com');
      expect(DomainInputParser.buildParentDomains('foo.appspot.com'), <String>['foo.appspot.com']);

      // Broad whitelist MUST reject PRIVATE suffixes like github.io / appspot.com
      final ghSug = WhitelistPlanner.buildSuggestion(
        originalHost: 'foo.github.io',
        matchedRules: const [
          MatchedRuleInfo(text: '||github.io^', filterListId: 1, sourceName: 'List'),
        ],
      );
      expect(ghSug.narrowRule, '@@||foo.github.io^');
      expect(ghSug.broadRule, isNull);
      expect(WhitelistPlanner.extractSafeAnchorDomain('||github.io^'), isNull);
      expect(WhitelistPlanner.extractSafeAnchorDomain('||appspot.com^'), isNull);

      // PSL wildcard rules (*.ck -> foo.ck is public suffix, bar.foo.ck is registrable)
      expect(DomainInputParser.isPublicSuffix('foo.ck'), isTrue);
      expect(DomainInputParser.registrableDomain('foo.ck'), isNull);
      expect(DomainInputParser.registrableDomain('bar.foo.ck'), 'bar.foo.ck');
      expect(DomainInputParser.buildParentDomains('bar.foo.ck'), <String>['bar.foo.ck']);
      expect(WhitelistPlanner.extractSafeAnchorDomain('||foo.ck^'), isNull);

      // PSL exception rules (!www.ck overrides *.ck, !city.kawasaki.jp overrides *.kawasaki.jp)
      expect(DomainInputParser.isPublicSuffix('www.ck'), isFalse);
      expect(DomainInputParser.registrableDomain('www.ck'), 'www.ck');
      expect(DomainInputParser.isPublicSuffix('other.kawasaki.jp'), isTrue);
      expect(DomainInputParser.isPublicSuffix('city.kawasaki.jp'), isFalse);
      expect(DomainInputParser.registrableDomain('sub.city.kawasaki.jp'), 'city.kawasaki.jp');
      expect(
        DomainInputParser.buildParentDomains('sub.city.kawasaki.jp'),
        <String>['sub.city.kawasaki.jp', 'city.kawasaki.jp'],
      );

      // Unknown / unmanaged suffix MUST NOT fall back to last-2-labels registrable guess and disables broad
      final unknownMatch = DomainInputParser.inspectPublicSuffix('a.b.c.unknowntld');
      expect(unknownMatch, isNotNull);
      expect(unknownMatch!.isKnownRule, isFalse);
      expect(DomainInputParser.registrableDomain('a.b.c.unknowntld'), isNull);
      final unknownSug = WhitelistPlanner.buildSuggestion(
        originalHost: 'a.b.c.unknowntld',
        matchedRules: const [
          MatchedRuleInfo(text: '||b.c.unknowntld^', filterListId: 1, sourceName: 'Custom'),
        ],
      );
      expect(unknownSug.broadRule, isNull);
      expect(unknownSug.broadDisabledReason, contains('PSL'));

      // Unrelated matched rule domain MUST disable broad button even if syntax is ||other^
      final unrelatedSug = WhitelistPlanner.buildSuggestion(
        originalHost: 'u56112681.ct.sendgrid.net',
        matchedRules: const [
          MatchedRuleInfo(text: '||sendgrid.com^', filterListId: 1, sourceName: 'List'),
          MatchedRuleInfo(text: '||unrelated.example^', filterListId: 2, sourceName: 'List2'),
        ],
      );
      expect(unrelatedSug.narrowRule, '@@||u56112681.ct.sendgrid.net^');
      expect(unrelatedSug.broadRule, isNull);
      expect(unrelatedSug.broadDisabledReason, contains('包含关系'));

      // Narrow button rejects invalid domains and public suffixes
      final suffixInputSug = WhitelistPlanner.buildSuggestion(
        originalHost: 'github.io',
        matchedRules: const [],
      );
      expect(suffixInputSug.narrowRule, isNull);
      expect(suffixInputSug.broadRule, isNull);
    });
  });

  group('RC2 Section 2. Post-Write A/AAAA Verification & Classification Matrix', () {
    test('classifies NotFilteredError & unknown reasons safely and covers all 7+ verification outcomes', () async {
      // Static reason classification checks
      expect(HostCheckResult.classifyReason('NotFilteredError'), RuleCheckStatus.failed);
      expect(HostCheckResult.classifyReason('BrandNewUnknownReason'), RuleCheckStatus.unknown);
      expect(HostCheckResult.classifyReason('Rewrite'), RuleCheckStatus.rewritten);
      expect(HostCheckResult.classifyReason('RewriteRule'), RuleCheckStatus.rewritten);
      expect(HostCheckResult.classifyReason('NotFilteredNotFound'), RuleCheckStatus.notBlocked);
      expect(HostCheckResult.classifyReason('NotFilteredWhiteList'), RuleCheckStatus.whitelisted);

      await HttpOverrides.runWithHttpOverrides(() async {
        late ApiResponse Function(String qtype) checkResponder;
        var resetCacheSuccess = true;
        final rules = <String>['||old.example^'];
        var rev = 1;

        final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
        addTearDown(() => server.close(force: true));
        server.listen((req) async {
          final p = req.uri.path;
          if (p == '/control/filtering/status') {
            req.response
              ..statusCode = 200
              ..headers.contentType = ContentType.json
              ..write(jsonEncode({
                'filters': [],
                'whitelist_filters': [],
                'user_rules': rules,
                'user_rules_revision': 'rev:$rev',
                'interval': 24,
                'enabled': true,
              }));
          } else if (p == '/control/filtering/set_rules') {
            final body = jsonDecode(await utf8.decoder.bind(req).join()) as Map<String, dynamic>;
            rules
              ..clear()
              ..addAll((body['rules'] as List).map((e) => e.toString()));
            rev++;
            req.response.statusCode = 200;
          } else if (p == '/control/cache_clear') {
            req.response.statusCode = resetCacheSuccess ? 200 : 500;
          } else if (p == '/control/filtering/check_host') {
            final qtype = req.uri.queryParameters['qtype'] ?? 'A';
            final r = checkResponder(qtype);
            if (!r.successful) {
              req.response.statusCode = r.statusCode ?? 500;
              req.response.write(r.content ?? 'err');
            } else {
              req.response
                ..statusCode = 200
                ..headers.contentType = ContentType.json
                ..write(jsonEncode(r.content));
            }
          } else {
            req.response.statusCode = 404;
          }
          await req.response.close();
        });

        final apiClient = ApiClientV2(
          server: Server(
            id: 'sec2-srv',
            name: 'Sec2',
            connectionMethod: 'http',
            domain: '127.0.0.1',
            port: server.port,
            defaultServer: true,
            runningOnHa: false,
          ),
        );
        final coord = ExceptionRuleCoordinator();

        // 1. A whitelisted, AAAA failed/timeout -> incomplete, NOT green unblocked!
        checkResponder = (q) => q == 'A'
            ? const ApiResponse(successful: true, content: {'reason': 'NotFilteredWhiteList', 'rules': []})
            : const ApiResponse(successful: false, statusCode: 504, content: 'timeout');
        final r1 = await coord.applyExceptionAndVerify(
          apiClient: apiClient,
          verifyHost: 'case1.example',
          exceptionRule: '@@||case1.example^',
        );
        expect(r1.writeSucceeded, isTrue);
        expect(r1.verifiedUnblocked, isFalse);
        expect(r1.verificationIncomplete, isTrue);
        expect(r1.message, contains('核验不完整'));

        // 2. A notBlocked, AAAA still blocked -> reports AAAA blocked + rule!
        checkResponder = (q) => q == 'A'
            ? const ApiResponse(successful: true, content: {'reason': 'NotFilteredNotFound', 'rules': []})
            : const ApiResponse(successful: true, content: {
                'reason': 'FilteredBlackList',
                'rules': [{'text': '||case2.example^', 'filter_list_id': 1}],
              });
        final r2 = await coord.applyExceptionAndVerify(
          apiClient: apiClient,
          verifyHost: 'case2.example',
          exceptionRule: '@@||case2.example^',
        );
        expect(r2.verifiedUnblocked, isFalse);
        expect(r2.postCheckAAAA?.isBlocked, isTrue);
        expect(r2.message, contains('AAAA'));

        // 3. A failed, AAAA normal -> incomplete!
        checkResponder = (q) => q == 'A'
            ? const ApiResponse(successful: false, statusCode: 500)
            : const ApiResponse(successful: true, content: {'reason': 'NotFilteredNotFound', 'rules': []});
        final r3 = await coord.applyExceptionAndVerify(
          apiClient: apiClient,
          verifyHost: 'case3.example',
          exceptionRule: '@@||case3.example^',
        );
        expect(r3.verifiedUnblocked, isFalse);
        expect(r3.verificationIncomplete, isTrue);

        // 4. Unknown reason -> incomplete, NOT unblocked!
        checkResponder = (q) => const ApiResponse(
              successful: true,
              content: {'reason': 'SomeFutureUnknownReason', 'rules': []},
            );
        final r4 = await coord.applyExceptionAndVerify(
          apiClient: apiClient,
          verifyHost: 'case4.example',
          exceptionRule: '@@||case4.example^',
        );
        expect(r4.verifiedUnblocked, isFalse);
        expect(r4.verificationIncomplete, isTrue);
        expect(r4.postCheckA?.status, RuleCheckStatus.unknown);

        // 5. NotFilteredError -> incomplete/failed, NOT unblocked!
        checkResponder = (q) => const ApiResponse(
              successful: true,
              content: {'reason': 'NotFilteredError', 'rules': []},
            );
        final r5 = await coord.applyExceptionAndVerify(
          apiClient: apiClient,
          verifyHost: 'case5.example',
          exceptionRule: '@@||case5.example^',
        );
        expect(r5.verifiedUnblocked, isFalse);
        expect(r5.verificationIncomplete, isTrue);
        expect(r5.postCheckA?.status, RuleCheckStatus.failed);

        // 6. Both A & AAAA clean -> verifiedUnblocked + honest caveat!
        checkResponder = (q) => const ApiResponse(
              successful: true,
              content: {'reason': 'NotFilteredWhiteList', 'rules': []},
            );
        final r6 = await coord.applyExceptionAndVerify(
          apiClient: apiClient,
          verifyHost: 'case6.example',
          exceptionRule: '@@||case6.example^',
        );
        expect(r6.verifiedUnblocked, isTrue);
        expect(r6.cacheFlushFailed, isFalse);
        expect(r6.message, contains('规则检测确认放行'));
        expect(r6.message, contains('不保证邮件跳转'));

        // 7. Cache reset failed -> partial completion!
        resetCacheSuccess = false;
        final r7 = await coord.applyExceptionAndVerify(
          apiClient: apiClient,
          verifyHost: 'case7.example',
          exceptionRule: '@@||case7.example^',
        );
        expect(r7.verifiedUnblocked, isTrue);
        expect(r7.cacheFlushFailed, isTrue);
        expect(r7.message, contains('部分完成'));

        // 8. Rewrite keeps independent state!
        resetCacheSuccess = true;
        checkResponder = (q) => const ApiResponse(
              successful: true,
              content: {'reason': 'Rewrite', 'rules': []},
            );
        final r8 = await coord.applyExceptionAndVerify(
          apiClient: apiClient,
          verifyHost: 'case8.example',
          exceptionRule: '@@||case8.example^',
        );
        expect(r8.verifiedUnblocked, isFalse);
        expect(r8.postCheckA?.status, RuleCheckStatus.rewritten);
      }, _PassthroughHttpOverrides());
    });
  });

  group('RC2 Section 3. Shared Per-Server Queue, Concurrency, 409 Conflict & Verifiable Undo', () {
    test('serializes multi-coordinator & provider writes per server, isolates servers, handles failure/409, and rejects unverifiable undo', () async {
      await HttpOverrides.runWithHttpOverrides(() async {
        ServerRuleWriteQueue.resetForTest();

        final rulesA = <String>['||initial.example^', '@@||already.example^'];
        var revA = 1;
        final rulesB = <String>['||b-init.example^'];
        var revB = 1;
        var injectExternalBetweenReadAndWriteA = false;
        var delayGetStatusAMs = 0;
        var failNextSetRulesA = false;

        Future<HttpServer> startMockServer({
          required List<String> rules,
          required int Function() getRev,
          required void Function() bumpRev,
          int Function()? delayMs,
          bool Function()? shouldFailSet,
          void Function()? onBeforeSetCheck,
        }) async {
          final srv = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
          srv.listen((req) async {
            final p = req.uri.path;
            if (p == '/control/filtering/status') {
              final d = delayMs?.call() ?? 0;
              if (d > 0) await Future<void>.delayed(Duration(milliseconds: d));
              req.response
                ..statusCode = 200
                ..headers.contentType = ContentType.json
                ..write(jsonEncode({
                  'filters': [],
                  'whitelist_filters': [],
                  'user_rules': rules,
                  'user_rules_revision': 'v1:${getRev()}',
                  'interval': 24,
                  'enabled': true,
                }));
            } else if (p == '/control/filtering/set_rules') {
              if (shouldFailSet?.call() == true) {
                req.response.statusCode = 500;
                await req.response.close();
                return;
              }
              onBeforeSetCheck?.call();
              final body = jsonDecode(await utf8.decoder.bind(req).join()) as Map<String, dynamic>;
              final exp = body['expected_revision']?.toString();
              final cur = 'v1:${getRev()}';
              if (exp != null && exp.isNotEmpty && exp != cur) {
                req.response.statusCode = 409;
                req.response.write('conflict');
              } else {
                rules
                  ..clear()
                  ..addAll((body['rules'] as List).map((e) => e.toString()));
                bumpRev();
                req.response
                  ..statusCode = 200
                  ..headers.set('X-User-Rules-Revision', 'v1:${getRev()}');
              }
            } else if (p == '/control/filtering/check_host') {
              req.response
                ..statusCode = 200
                ..headers.contentType = ContentType.json
                ..write(jsonEncode({'reason': 'NotFilteredWhiteList', 'rules': []}));
            } else if (p == '/control/cache_clear') {
              req.response.statusCode = 200;
            } else {
              req.response.statusCode = 404;
            }
            await req.response.close();
          });
          return srv;
        }

        final srvA = await startMockServer(
          rules: rulesA,
          getRev: () => revA,
          bumpRev: () => revA++,
          delayMs: () => delayGetStatusAMs,
          shouldFailSet: () {
            if (failNextSetRulesA) {
              failNextSetRulesA = false;
              return true;
            }
            return false;
          },
          onBeforeSetCheck: () {
            if (injectExternalBetweenReadAndWriteA) {
              injectExternalBetweenReadAndWriteA = false;
              rulesA.add('||external-client.example^');
              revA++;
            }
          },
        );
        addTearDown(() => srvA.close(force: true));

        final srvB = await startMockServer(
          rules: rulesB,
          getRev: () => revB,
          bumpRev: () => revB++,
        );
        addTearDown(() => srvB.close(force: true));

        final serverA = Server(
          id: 'srv-a',
          name: 'Server A',
          connectionMethod: 'http',
          domain: '127.0.0.1',
          port: srvA.port,
          defaultServer: true,
          runningOnHa: false,
        );
        final serverB = Server(
          id: 'srv-b',
          name: 'Server B',
          connectionMethod: 'http',
          domain: '127.0.0.1',
          port: srvB.port,
          defaultServer: false,
          runningOnHa: false,
        );
        final apiA = ApiClientV2(server: serverA);
        final apiB = ApiClientV2(server: serverB);

        // 1. Two separate ExceptionRuleCoordinator instances + FilteringProvider + StatusProvider concurrently on Server A
        final coord1 = ExceptionRuleCoordinator();
        final coord2 = ExceptionRuleCoordinator();

        final serversProv = ServersProvider()..setApiClient2(apiA);
        final statusProv = StatusProvider()
          ..update(serversProv)
          ..setServerStatusData(
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
                interval: 24,
                enabled: true,
              ),
              timeGeneralDisabled: 0,
              generalEnabled: true,
              filteringEnabled: true,
              safeBrowsingEnabled: false,
              parentalControlEnabled: false,
              serverVersion: 'v0.107.0',
              dhcpAvailable: false,
            ),
          );
        final filteringProv = FilteringProvider()..update(serversProv, statusProv);

        final futures = await Future.wait([
          coord1.applyExceptionAndVerify(
            apiClient: apiA,
            verifyHost: 'c1.example',
            exceptionRule: '@@||c1.example^',
          ),
          coord2.applyExceptionAndVerify(
            apiClient: apiA,
            verifyHost: 'c2.example',
            exceptionRule: '@@||c2.example^',
          ),
          filteringProv.addCustomRule('||custom-ui.example^'),
          statusProv.blockUnblockDomain(domain: 'status-ui.example', newStatus: 'unblock'),
        ]);
        expect((futures[0] as ExceptionWriteOutcome).writeSucceeded, isTrue);
        expect((futures[1] as ExceptionWriteOutcome).writeSucceeded, isTrue);
        expect(futures[2], isTrue);
        expect(futures[3], isTrue);
        expect(rulesA, containsAll(<String>[
          '||initial.example^',
          '@@||already.example^',
          '@@||c1.example^',
          '@@||c2.example^',
          '||custom-ui.example^',
          '@@||status-ui.example^\$important',
        ]));

        // 2. Failure on one queued write does NOT stall subsequent writes
        failNextSetRulesA = true;
        final failOut = await coord1.applyExceptionAndVerify(
          apiClient: apiA,
          verifyHost: 'will-fail.example',
          exceptionRule: '@@||will-fail.example^',
        );
        expect(failOut.writeSucceeded, isFalse);
        final afterFailOut = await coord1.applyExceptionAndVerify(
          apiClient: apiA,
          verifyHost: 'after-fail.example',
          exceptionRule: '@@||after-fail.example^',
        );
        expect(afterFailOut.writeSucceeded, isTrue);
        expect(rulesA, contains('@@||after-fail.example^'));

        // 3. Server isolation: slow Server A does NOT block fast Server B
        delayGetStatusAMs = 120;
        final slowA = coord1.applyExceptionAndVerify(
          apiClient: apiA,
          verifyHost: 'slow-a.example',
          exceptionRule: '@@||slow-a.example^',
        );
        final swB = Stopwatch()..start();
        final fastB = await coord1.applyExceptionAndVerify(
          apiClient: apiB,
          verifyHost: 'fast-b.example',
          exceptionRule: '@@||fast-b.example^',
        );
        swB.stop();
        expect(fastB.writeSucceeded, isTrue);
        expect(swB.elapsedMilliseconds, lessThan(100));
        await slowA;
        delayGetStatusAMs = 0;

        // 4. Pre-existing rule MUST set addedRule == null and refuse undo
        final dupOut = await coord1.applyExceptionAndVerify(
          apiClient: apiA,
          verifyHost: 'already.example',
          exceptionRule: '@@||already.example^',
        );
        expect(dupOut.addedRule, isNull);
        expect(dupOut.undoToken, isNull);
        final dupUndo = await coord1.undoAddedException(
          apiClient: apiA,
          addedRule: '@@||already.example^',
        );
        expect(dupUndo.ok, isFalse);
        expect(rulesA, contains('@@||already.example^'));

        // 5. Undo ownership: add -> user deletes & re-adds exact same text -> old undo MUST refuse!
        final addTracked = await coord1.applyExceptionAndVerify(
          apiClient: apiA,
          verifyHost: 'tracked.example',
          exceptionRule: '@@||tracked.example^',
        );
        expect(addTracked.addedRule, '@@||tracked.example^');
        expect(addTracked.undoToken, isNotNull);

        expect(await filteringProv.removeCustomRule('@@||tracked.example^'), isTrue);
        expect(await filteringProv.addCustomRule('@@||tracked.example^'), isTrue);

        final staleUndo = await coord1.undoAddedException(
          apiClient: apiA,
          addedRule: '@@||tracked.example^',
          undoToken: addTracked.undoToken,
        );
        expect(staleUndo.ok, isFalse);
        expect(staleUndo.message, contains('拒绝猜测删除'));
        expect(rulesA, contains('@@||tracked.example^'));

        // 6. External client concurrent modification -> 409 Conflict, re-read fresh rules, external rule intact!
        injectExternalBetweenReadAndWriteA = true;
        final conflictOut = await coord1.applyExceptionAndVerify(
          apiClient: apiA,
          verifyHost: 'race.example',
          exceptionRule: '@@||race.example^',
        );
        expect(conflictOut.writeSucceeded, isFalse);
        expect(conflictOut.conflictDetected, isTrue);
        expect(conflictOut.message, contains('版本冲突'));
        expect(rulesA, contains('||external-client.example^'));
        expect(rulesA, isNot(contains('@@||race.example^')));
      }, _PassthroughHttpOverrides());
    });
  });

  group('RC3. Commit-Bound Revision & Undo Token Verification', () {
    test('covers all 8 commit revision, readback mismatch, conservative legacy Core & restart scenarios', () async {
      await HttpOverrides.runWithHttpOverrides(() async {
        ServerRuleWriteQueue.resetForTest();

        final rules = <String>['||init.example^'];
        var coreInstance = 'instA';
        var epoch = 1;
        String currentRev() => 'v2:$coreInstance:$epoch';

        String? overridePostHeader;
        bool omitPostHeader = false;
        void Function()? onAfterPostBeforeReadback;
        List<String> Function(List<String> cur)? overrideStatusRules;
        String? overrideStatusRev;
        var postCount = 0;

        final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
        addTearDown(() => server.close(force: true));
        server.listen((req) async {
          final p = req.uri.path;
          if (p == '/control/filtering/status') {
            final useReadbackOverride = postCount > 0;
            final respRules = (useReadbackOverride && overrideStatusRules != null)
                ? overrideStatusRules(rules)
                : rules;
            final respRev = (useReadbackOverride && overrideStatusRev != null)
                ? overrideStatusRev
                : (omitPostHeader ? null : currentRev());
            req.response
              ..statusCode = 200
              ..headers.contentType = ContentType.json
              ..write(jsonEncode({
                'filters': [],
                'whitelist_filters': [],
                'user_rules': respRules,
                if (respRev != null) 'user_rules_revision': respRev,
                'interval': 24,
                'enabled': true,
              }));
          } else if (p == '/control/filtering/set_rules') {
            final body = jsonDecode(await utf8.decoder.bind(req).join()) as Map<String, dynamic>;
            final exp = body['expected_revision']?.toString();
            if (exp != null && exp.isNotEmpty && exp != currentRev()) {
              req.response
                ..statusCode = 409
                ..write('conflict');
            } else {
              rules
                ..clear()
                ..addAll((body['rules'] as List).map((e) => e.toString()));
              epoch++;
              postCount++;
              onAfterPostBeforeReadback?.call();
              onAfterPostBeforeReadback = null;
              req.response.statusCode = 200;
              if (!omitPostHeader) {
                req.response.headers.set(
                  'X-User-Rules-Revision',
                  overridePostHeader ?? currentRev(),
                );
              }
            }
          } else if (p == '/control/filtering/check_host') {
            req.response
              ..statusCode = 200
              ..headers.contentType = ContentType.json
              ..write(jsonEncode({'reason': 'NotFilteredWhiteList', 'rules': []}));
          } else if (p == '/control/cache_clear') {
            req.response.statusCode = 200;
          } else {
            req.response.statusCode = 404;
          }
          await req.response.close();
        });

        final api = ApiClientV2(
          server: Server(
            id: 'rc3-srv',
            name: 'RC3',
            connectionMethod: 'http',
            domain: '127.0.0.1',
            port: server.port,
            defaultServer: true,
            runningOnHa: false,
          ),
        );
        final coord = ExceptionRuleCoordinator();

        // 1. POST whitelist succeeds, another client modifies ANOTHER rule before readback:
        // must NOT rollback/overwrite other client's rule, live check continues, NO undoToken issued!
        onAfterPostBeforeReadback = () {
          // Simulates another client modifying index 0 right after our POST returned its header
          rules[0] = '||edited-by-other.example^';
          epoch++;
        };
        overridePostHeader = currentRev();
        // Wait: onAfterPostBeforeReadback runs BEFORE req.response.headers.set, so capture expected post rev before bump!
        final postHeader1 = 'v2:$coreInstance:${epoch + 1}';
        overridePostHeader = postHeader1;
        final out1 = await coord.applyExceptionAndVerify(
          apiClient: api,
          verifyHost: 'case1.rc3.example',
          exceptionRule: '@@||case1.rc3.example^',
        );
        overridePostHeader = null;
        expect(out1.writeSucceeded, isTrue);
        expect(out1.verifiedUnblocked, isTrue);
        expect(out1.undoToken, isNull);
        expect(out1.undoDisabledReason, contains('配置已被其他操作更新'));
        expect(out1.message, contains('无法确认撤销归属'));
        // Other client's rule untouched; our added rule wasn't rolled back either
        expect(rules, <String>['||edited-by-other.example^', '@@||case1.rc3.example^']);

        // 2. POST succeeds, other client deletes & re-adds same exception before readback:
        // list length and slot look identical, but readback revision differs -> NO undoToken!
        final postHeader2 = 'v2:$coreInstance:${epoch + 1}';
        overridePostHeader = postHeader2;
        onAfterPostBeforeReadback = () {
          rules.removeLast();
          epoch++;
          rules.add('@@||case2.rc3.example^');
          epoch++;
        };
        final out2 = await coord.applyExceptionAndVerify(
          apiClient: api,
          verifyHost: 'case2.rc3.example',
          exceptionRule: '@@||case2.rc3.example^',
        );
        overridePostHeader = null;
        expect(out2.undoToken, isNull);
        expect(out2.undoDisabledReason, contains('配置已被其他操作更新'));
        expect(rules, contains('@@||case2.rc3.example^'));

        // 3. Readback list length & added slot match, but revision differs -> NO undoToken!
        postCount = 0;
        overrideStatusRev = 'v2:$coreInstance:different';
        final out3 = await coord.applyExceptionAndVerify(
          apiClient: api,
          verifyHost: 'case3.rc3.example',
          exceptionRule: '@@||case3.rc3.example^',
        );
        overrideStatusRev = null;
        expect(out3.writeSucceeded, isTrue);
        expect(out3.undoToken, isNull);
        expect(out3.undoDisabledReason, contains('无法确认撤销归属'));

        // 4. Readback revision equals POST revision, but full list differs from expected submitted list -> NO undoToken!
        postCount = 0;
        overrideStatusRules = (cur) => <String>[
              ...cur.sublist(0, cur.length - 1).map((e) => '$e!mutated'),
              cur.last,
            ];
        final out4 = await coord.applyExceptionAndVerify(
          apiClient: api,
          verifyHost: 'case4.rc3.example',
          exceptionRule: '@@||case4.rc3.example^',
        );
        overrideStatusRules = null;
        expect(out4.writeSucceeded, isTrue);
        expect(out4.undoToken, isNull);
        expect(out4.undoDisabledReason, contains('无法确认撤销归属'));

        // 5. Legacy Core omits X-User-Rules-Revision -> conservative: live check works, NO undoToken!
        omitPostHeader = true;
        final out5 = await coord.applyExceptionAndVerify(
          apiClient: api,
          verifyHost: 'legacy.rc3.example',
          exceptionRule: '@@||legacy.rc3.example^',
        );
        omitPostHeader = false;
        expect(out5.writeSucceeded, isTrue);
        expect(out5.verifiedUnblocked, isTrue);
        expect(out5.undoToken, isNull);
        expect(out5.undoDisabledReason, contains('未返回提交版本号'));

        // 6. Normal commit + normal readback + normal undo removes ONLY added rule!
        final out6 = await coord.applyExceptionAndVerify(
          apiClient: api,
          verifyHost: 'ok.rc3.example',
          exceptionRule: '@@||ok.rc3.example^',
        );
        expect(out6.writeSucceeded, isTrue);
        expect(out6.verifiedUnblocked, isTrue);
        expect(out6.undoToken, isNotNull);
        expect(out6.undoToken!.confirmedRevision, currentRev());
        final undo6 = await coord.undoAddedException(
          apiClient: api,
          addedRule: '@@||ok.rc3.example^',
          undoToken: out6.undoToken,
        );
        expect(undo6.ok, isTrue);
        expect(rules, isNot(contains('@@||ok.rc3.example^')));
        expect(rules, contains('||edited-by-other.example^'));

        // 7. Core restarts with identical rules AND identical epoch counter, only instance ID changes:
        // old instance undoToken MUST be refused and all rules preserved!
        final out7 = await coord.applyExceptionAndVerify(
          apiClient: api,
          verifyHost: 'restart.rc3.example',
          exceptionRule: '@@||restart.rc3.example^',
        );
        expect(out7.undoToken, isNotNull);
        final savedEpoch = epoch;
        coreInstance = 'instB_restarted';
        epoch = savedEpoch; // Same epoch & identical rules, only instance changed!
        final snapshotBeforeUndo = List<String>.from(rules);

        final undoRestart = await coord.undoAddedException(
          apiClient: api,
          addedRule: '@@||restart.rc3.example^',
          undoToken: out7.undoToken,
        );
        expect(undoRestart.ok, isFalse);
        expect(undoRestart.message, contains('拒绝猜测删除'));
        expect(rules, snapshotBeforeUndo);
      }, _PassthroughHttpOverrides());
    });
  });
}

class _PassthroughHttpOverrides extends HttpOverrides {}
