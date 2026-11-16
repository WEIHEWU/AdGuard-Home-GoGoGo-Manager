import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import 'package:adguard_home_manager/models/filtering.dart';
import 'package:adguard_home_manager/providers/app_config_provider.dart';
import 'package:adguard_home_manager/providers/filtering_provider.dart';
import 'package:adguard_home_manager/providers/servers_provider.dart';
import 'package:adguard_home_manager/functions/copy_clipboard.dart';
import 'package:adguard_home_manager/functions/snackbar.dart';
import 'package:adguard_home_manager/services/host_rule_diagnostics.dart';
import 'package:adguard_home_manager/services/manual_rule_provenance_service.dart';
import 'package:adguard_home_manager/widgets/rule_provenance_badge.dart';

enum _ManualRulesFilter {
  all('全部'),
  allow('手动放行'),
  block('手动拦截'),
  other('手动规则'),
  claimed('用户认领'),
  missingOrUnconfirmed('已不存在/未确认');

  final String label;
  const _ManualRulesFilter(this.label);
}

enum _LiveEffectivenessKind {
  checking,
  matchedThisManualRule,
  matchedOtherRule,
  coveredByImportantBlock,
  blockedByOtherRule,
  complexUnsupported,
  missingInCore,
  checkFailed,
}

class _LiveEffectivenessState {
  final _LiveEffectivenessKind kind;
  final String summary;

  const _LiveEffectivenessState({
    required this.kind,
    required this.summary,
  });
}

/// “我的手动规则”集中管理页：展示来源、添加/认领时间、入口、作用域、备注、真实核验及安全移除。
class MyManualRulesScreen extends StatefulWidget {
  final ManualRuleProvenanceService? provenanceService;

  const MyManualRulesScreen({
    super.key,
    this.provenanceService,
  });

  @override
  State<MyManualRulesScreen> createState() => _MyManualRulesScreenState();
}

class _MyManualRulesScreenState extends State<MyManualRulesScreen> {
  late final ManualRuleProvenanceService _provenanceService;
  final TextEditingController _searchController = TextEditingController();

  _ManualRulesFilter _filter = _ManualRulesFilter.all;
  String _searchQuery = '';
  bool _newestFirst = true;
  bool _syncingCore = false;
  final Map<String, _LiveEffectivenessState> _effectivenessByRecordId = {};

  @override
  void initState() {
    super.initState();
    _provenanceService =
        widget.provenanceService ?? ManualRuleProvenanceService.instance;
    _provenanceService.addListener(_onServiceChanged);
    WidgetsBinding.instance.addPostFrameCallback((_) => _initAndSync());
  }

  @override
  void dispose() {
    _provenanceService.removeListener(_onServiceChanged);
    _searchController.dispose();
    super.dispose();
  }

  void _onServiceChanged() {
    if (mounted) {
      setState(() {});
    }
  }

  Future<void> _initAndSync() async {
    await _provenanceService.ensureLoaded();
    if (!mounted) return;
    await _refreshAndSyncWithCore();
  }

  Future<void> _refreshAndSyncWithCore() async {
    final serversProvider =
        Provider.of<ServersProvider>(context, listen: false);
    final filteringProvider =
        Provider.of<FilteringProvider>(context, listen: false);
    final server = serversProvider.selectedServer;
    if (server == null) return;

    setState(() => _syncingCore = true);
    try {
      await filteringProvider.fetchFilters(showLoading: false);
      final latestFiltering = filteringProvider.filtering;
      if (latestFiltering != null) {
        await _provenanceService.syncWithCoreRules(
          serverKey: ServerRuleWriteQueue.serverKeyFor(server),
          coreRules: latestFiltering.userRules,
          currentRevision: latestFiltering.userRulesRevision,
        );
      }
    } finally {
      if (mounted) {
        setState(() => _syncingCore = false);
      }
    }
  }

  List<ManualRuleRecord> _filteredRecords(String serverKey) {
    final all = List<ManualRuleRecord>.from(
      _provenanceService.recordsForServer(serverKey),
    );
    final q = _searchQuery.trim().toLowerCase();

    final filtered = all.where((rec) {
      switch (_filter) {
        case _ManualRulesFilter.all:
          break;
        case _ManualRulesFilter.allow:
          if (rec.action != ManualRuleAction.allow) return false;
          break;
        case _ManualRulesFilter.block:
          if (rec.action != ManualRuleAction.block) return false;
          break;
        case _ManualRulesFilter.other:
          if (rec.action != ManualRuleAction.other) return false;
          break;
        case _ManualRulesFilter.claimed:
          if (rec.source != ManualRuleSource.claimed) return false;
          break;
        case _ManualRulesFilter.missingOrUnconfirmed:
          if (rec.syncStatus == ManualRuleSyncStatus.present) return false;
          break;
      }

      if (q.isNotEmpty) {
        final inRule = rec.ruleText.toLowerCase().contains(q);
        final inScope =
            rec.classification.scopeSummary.toLowerCase().contains(q);
        final inNote = (rec.note ?? '').toLowerCase().contains(q);
        final inEntry = rec.entryPoint.toLowerCase().contains(q);
        if (!inRule && !inScope && !inNote && !inEntry) {
          return false;
        }
      }
      return true;
    }).toList();

    filtered.sort((a, b) {
      final cmp = a.sortTimestamp.compareTo(b.sortTimestamp);
      return _newestFirst ? -cmp : cmp;
    });
    return filtered;
  }

  Future<void> _checkRecordEffectiveness(ManualRuleRecord rec) async {
    final cls = rec.classification;
    if (!cls.isCheckHostTestable || cls.extractableHost == null) {
      setState(() {
        _effectivenessByRecordId[rec.recordId] = const _LiveEffectivenessState(
          kind: _LiveEffectivenessKind.complexUnsupported,
          summary: '复杂规则暂不支持单域名探活，仅展示来源记录与规则原文',
        );
      });
      return;
    }

    if (rec.syncStatus == ManualRuleSyncStatus.missing) {
      setState(() {
        _effectivenessByRecordId[rec.recordId] = const _LiveEffectivenessState(
          kind: _LiveEffectivenessKind.missingInCore,
          summary: '该规则已不在 Core 自定义规则中，当前不会由本条手动规则触发匹配',
        );
      });
      return;
    }

    final serversProvider =
        Provider.of<ServersProvider>(context, listen: false);
    final filteringProvider =
        Provider.of<FilteringProvider>(context, listen: false);
    final api = serversProvider.apiClient2;
    if (api == null) {
      setState(() {
        _effectivenessByRecordId[rec.recordId] = const _LiveEffectivenessState(
          kind: _LiveEffectivenessKind.checkFailed,
          summary: '未连接服务器，无法向 Core 核验规则状态',
        );
      });
      return;
    }

    setState(() {
      _effectivenessByRecordId[rec.recordId] = const _LiveEffectivenessState(
        kind: _LiveEffectivenessKind.checking,
        summary: '正在向 Core 查询 A / AAAA 实时规则匹配...',
      );
    });

    final host = cls.extractableHost!;
    final filtering = filteringProvider.filtering;
    final filterNames = <int, String>{
      if (filtering != null)
        for (final f in filtering.filters) f.id: f.name,
    };
    final whitelistNames = <int, String>{
      if (filtering != null)
        for (final f in filtering.whitelistFilters) f.id: f.name,
    };

    try {
      final resA = HostCheckResult.fromApiResponse(
        host: host,
        response: await api.checkHostFiltered(host: host, qtype: 'A'),
        isOriginal: true,
        qtype: 'A',
        filterNames: filterNames,
        whitelistNames: whitelistNames,
      );
      final resAAAA = HostCheckResult.fromApiResponse(
        host: host,
        response: await api.checkHostFiltered(host: host, qtype: 'AAAA'),
        isOriginal: true,
        qtype: 'AAAA',
        filterNames: filterNames,
        whitelistNames: whitelistNames,
      );

      if (!mounted) return;

      // 若任一记录请求失败/未知，不报“已生效”
      if (resA.status == RuleCheckStatus.failed ||
          resA.status == RuleCheckStatus.unknown ||
          resA.status == RuleCheckStatus.unsupported ||
          resAAAA.status == RuleCheckStatus.failed ||
          resAAAA.status == RuleCheckStatus.unknown ||
          resAAAA.status == RuleCheckStatus.unsupported) {
        setState(() {
          _effectivenessByRecordId[rec.recordId] = _LiveEffectivenessState(
            kind: _LiveEffectivenessKind.checkFailed,
            summary:
                '实时检测不完整（A=${resA.statusLabel}，AAAA=${resAAAA.statusLabel}）',
          );
        });
        return;
      }

      final allMatched = <MatchedRuleInfo>[...resA.rules, ...resAAAA.rules];
      final matchedExactThisManual = allMatched.any(
        (r) => r.filterListId == 0 && r.text.trim() == rec.ruleText.trim(),
      );

      if (rec.action == ManualRuleAction.allow) {
        final blocked = [
          if (resA.isBlocked) resA,
          if (resAAAA.isBlocked) resAAAA,
        ];
        if (blocked.isNotEmpty) {
          final hasImp = blocked.any((r) => r.hasImportantBlock);
          final firstBlocked = blocked.first;
          final blockerText = firstBlocked.rules.isNotEmpty
              ? '${firstBlocked.rules.first.sourceName}: ${firstBlocked.rules.first.text}'
              : firstBlocked.rawReason;
          setState(() {
            _effectivenessByRecordId[rec.recordId] = _LiveEffectivenessState(
              kind: hasImp
                  ? _LiveEffectivenessKind.coveredByImportantBlock
                  : _LiveEffectivenessKind.blockedByOtherRule,
              summary: hasImp
                  ? '未生效：仍被更高优先级 \$important 规则覆盖（$blockerText）'
                  : '未生效：当前仍被拦截规则命中（$blockerText）',
            );
          });
          return;
        }
        if (matchedExactThisManual) {
          setState(() {
            _effectivenessByRecordId[rec.recordId] = const _LiveEffectivenessState(
              kind: _LiveEffectivenessKind.matchedThisManualRule,
              summary: '当前检测 A / AAAA 均命中本条手动放行规则并放行',
            );
          });
          return;
        }
        final otherSummary = allMatched.isNotEmpty
            ? allMatched.map((e) => '[${e.sourceName}] ${e.text}').toSet().join('；')
            : '当前未被任何拦截规则命中（NotFiltered）';
        setState(() {
          _effectivenessByRecordId[rec.recordId] = _LiveEffectivenessState(
            kind: _LiveEffectivenessKind.matchedOtherRule,
            summary: '当前未被本条规则显式命中（实际命中：$otherSummary）',
          );
        });
        return;
      }

      // action == block
      final isBlockedBoth = resA.isBlocked || resAAAA.isBlocked;
      if (matchedExactThisManual && isBlockedBoth) {
        setState(() {
          _effectivenessByRecordId[rec.recordId] = const _LiveEffectivenessState(
            kind: _LiveEffectivenessKind.matchedThisManualRule,
            summary: '当前检测确认命中本条手动拦截规则并拦截',
          );
        });
      } else if (resA.status == RuleCheckStatus.whitelisted ||
          resAAAA.status == RuleCheckStatus.whitelisted) {
        final wl = resA.status == RuleCheckStatus.whitelisted ? resA : resAAAA;
        final wlDesc = wl.rules.isNotEmpty
            ? '[${wl.rules.first.sourceName}] ${wl.rules.first.text}'
            : wl.rawReason;
        setState(() {
          _effectivenessByRecordId[rec.recordId] = _LiveEffectivenessState(
            kind: _LiveEffectivenessKind.matchedOtherRule,
            summary: '当前被其他放行规则放行（$wlDesc），本条拦截未主导生效',
          );
        });
      } else {
        final matchedDesc = allMatched.isNotEmpty
            ? allMatched.map((e) => '[${e.sourceName}] ${e.text}').toSet().join('；')
            : 'NotFiltered（未触发拦截）';
        setState(() {
          _effectivenessByRecordId[rec.recordId] = _LiveEffectivenessState(
            kind: _LiveEffectivenessKind.matchedOtherRule,
            summary: '检测实际命中其他状态（$matchedDesc），并非本条手动拦截规则命中',
          );
        });
      }
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _effectivenessByRecordId[rec.recordId] = _LiveEffectivenessState(
          kind: _LiveEffectivenessKind.checkFailed,
          summary: '实时规则检查异常：$e',
        );
      });
    }
  }

  Future<void> _editNoteDialog(ManualRuleRecord rec) async {
    final appConfigProvider =
        Provider.of<AppConfigProvider>(context, listen: false);
    final updatedNote = await showDialog<String?>(
      context: context,
      builder: (_) => _EditNoteDialog(
        ruleText: rec.ruleText,
        initialNote: rec.note ?? '',
      ),
    );
    if (updatedNote == null || !mounted) return;

    final ok = await _provenanceService.updateNote(
      serverKey: rec.serverKey,
      recordId: rec.recordId,
      note: updatedNote,
    );
    if (!mounted) return;
    showSnackbar(
      appConfigProvider: appConfigProvider,
      label: ok ? '备注已保存到本地管理记录' : '备注保存失败（存储状态异常）',
      color: ok ? Colors.green : Colors.red,
    );
  }

  Future<void> _removeMetadataOnlyDialog(ManualRuleRecord rec) async {
    final appConfigProvider =
        Provider.of<AppConfigProvider>(context, listen: false);
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('移除管理记录，保留规则'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              '此操作仅删除本地“手动规则来源记录”和备注，不会修改 Core 的过滤规则；Core 中的规则将继续生效且不会被删除。',
            ),
            const SizedBox(height: 10),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: Theme.of(ctx).colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(6),
              ),
              child: Text(
                rec.ruleText,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('仅移除管理记录'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    final ok = await _provenanceService.removeProvenanceRecordOnly(
      serverKey: rec.serverKey,
      recordId: rec.recordId,
    );
    if (!mounted) return;
    showSnackbar(
      appConfigProvider: appConfigProvider,
      label: ok ? '已移除管理记录，Core 中的规则继续保留' : '移除管理记录失败',
      color: ok ? Colors.green : Colors.red,
    );
  }

  Future<void> _removeRuleFromCoreDialog(ManualRuleRecord rec) async {
    final filteringProvider =
        Provider.of<FilteringProvider>(context, listen: false);
    final appConfigProvider =
        Provider.of<AppConfigProvider>(context, listen: false);

    if (rec.syncStatus == ManualRuleSyncStatus.duplicateAmbiguous) {
      await showDialog<void>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('存在重复规则，归属未确认'),
          content: const Text(
            'Core 自定义规则中存在多条完全相同的该规则文本。为避免按索引猜删错行，已拒绝在此自动移除。请前往“过滤器 -> 自定义规则”的批量规则编辑器中核对后手工处理。',
          ),
          actions: [
            FilledButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('知道了'),
            ),
          ],
        ),
      );
      return;
    }

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('确认从 Core 移除该规则？'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('完整规则原文：', style: TextStyle(fontWeight: FontWeight.w600)),
            const SizedBox(height: 6),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: Theme.of(ctx).colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(8),
              ),
              child: SelectableText(
                rec.ruleText,
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 12.5,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
            const SizedBox(height: 10),
            Text(
              '影响说明：移除后该规则将立即从 Core 自定义规则中删除（${rec.classification.scopeSummary}），对应域名可能恢复为订阅规则默认拦截/放行策略。',
              style: TextStyle(
                fontSize: 12.5,
                color: Theme.of(ctx).colorScheme.error,
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('取消'),
          ),
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: Theme.of(ctx).colorScheme.error,
              foregroundColor: Theme.of(ctx).colorScheme.onError,
            ),
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('确认移除规则'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    final res = await filteringProvider.removeCustomRuleDetailed(rec.ruleText);
    if (!mounted) return;
    if (res.ok) {
      _effectivenessByRecordId.remove(rec.recordId);
      showSnackbar(
        appConfigProvider: appConfigProvider,
        label: res.provenanceSaveFailed
            ? 'Core 中的规则已移除，但本地来源记录更新失败'
            : '已确认从 Core 移除该规则并更新来源状态',
        color: res.provenanceSaveFailed ? Colors.orange : Colors.green,
      );
    } else {
      showSnackbar(
        appConfigProvider: appConfigProvider,
        label: res.message ?? '移除规则失败',
        color: Colors.red,
      );
    }
  }

  Future<void> _openClaimExistingRulesSheet(String serverKey) async {
    final filteringProvider =
        Provider.of<FilteringProvider>(context, listen: false);
    final appConfigProvider =
        Provider.of<AppConfigProvider>(context, listen: false);
    final Filtering? filtering = filteringProvider.filtering;
    if (filtering == null) {
      showSnackbar(
        appConfigProvider: appConfigProvider,
        label: '尚未获取到 Core 自定义规则列表，请先刷新',
        color: Colors.orange,
      );
      return;
    }

    final counts = RuleListDiffResult.countExactRules(filtering.userRules);
    final candidates = counts.keys.where((rule) {
      final disp = _provenanceService.resolveCustomListRowDisplay(
        serverKey: serverKey,
        rawRule: rule,
        duplicateCountInCore: counts[rule] ?? 1,
      );
      return disp.isUnrecordedCustom;
    }).toList();

    if (!mounted) return;
    await showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      builder: (ctx) => DraggableScrollableSheet(
        expand: false,
        initialChildSize: 0.65,
        minChildSize: 0.4,
        maxChildSize: 0.9,
        builder: (sheetCtx, scrollController) => Padding(
          padding: const EdgeInsets.fromLTRB(16, 4, 16, 16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                '认领尚未记录来源的自定义规则',
                style: TextStyle(fontSize: 16.5, fontWeight: FontWeight.w700),
              ),
              const SizedBox(height: 6),
              Text(
                '重要说明：主动认领仅记录“认领时间”，系统无法追溯历史原始添加者及最初添加时间。认领不会修改 Core 规则本身。',
                style: TextStyle(
                  fontSize: 12.5,
                  color: Theme.of(sheetCtx).colorScheme.onSurfaceVariant,
                ),
              ),
              const SizedBox(height: 12),
              Expanded(
                child: candidates.isEmpty
                    ? const Center(
                        child: Text('当前没有“来源未记录”的自定义规则'),
                      )
                    : ListView.separated(
                        controller: scrollController,
                        itemCount: candidates.length,
                        separatorBuilder: (_, __) => const Divider(height: 1),
                        itemBuilder: (_, idx) {
                          final rule = candidates[idx];
                          final cls = RuleClassification.classify(rule);
                          return ListTile(
                            contentPadding:
                                const EdgeInsets.symmetric(vertical: 4),
                            title: Text(
                              rule,
                              style: const TextStyle(
                                fontFamily: 'monospace',
                                fontSize: 12.5,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                            subtitle: Text(cls.scopeSummary),
                            trailing: OutlinedButton(
                              onPressed: () async {
                                final ok = await filteringProvider
                                    .claimExistingCustomRule(rule);
                                if (!sheetCtx.mounted) return;
                                Navigator.pop(sheetCtx);
                                if (!mounted) return;
                                showSnackbar(
                                  appConfigProvider: appConfigProvider,
                                  label: ok
                                      ? '已认领规则：$rule（标注为“用户认领”）'
                                      : '认领失败，请先刷新规则列表',
                                  color: ok ? Colors.green : Colors.red,
                                );
                              },
                              child: const Text('认领'),
                            ),
                          );
                        },
                      ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Future<void> _exportBackupDialog(String serverKey) async {
    final appConfigProvider =
        Provider.of<AppConfigProvider>(context, listen: false);
    final action = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('导出手动规则来源备份'),
        content: const Text(
          '导出范围与隐私说明：\n'
          '• 仅包含本地手动规则来源记录、创建时间与备注；\n'
          '• 绝不包含服务器密码、认证 Token 或 Core DNS 查询日志；\n'
          '• 导入时也只恢复来源管理记录，不会自动向 Core 下发过滤规则。',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('取消'),
          ),
          OutlinedButton(
            onPressed: () => Navigator.pop(ctx, 'copy'),
            child: const Text('复制备份 JSON'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, 'share'),
            child: const Text('导出并分享文件'),
          ),
        ],
      ),
    );
    if (action == null || !mounted) return;

    try {
      if (action == 'copy') {
        final jsonText = await _provenanceService.exportBackupJson();
        if (!mounted) return;
        await Clipboard.setData(ClipboardData(text: jsonText));
        if (!mounted) return;
        showSnackbar(
          appConfigProvider: appConfigProvider,
          label: '已复制手动规则来源备份 JSON',
          color: Colors.green,
        );
      } else {
        await _provenanceService.prepareAndShareBackupJson();
        if (!mounted) return;
        showSnackbar(
          appConfigProvider: appConfigProvider,
          label: '已准备备份文件用于分享',
          color: Colors.green,
        );
      }
    } catch (e) {
      if (!mounted) return;
      showSnackbar(
        appConfigProvider: appConfigProvider,
        label: '导出备份失败：$e',
        color: Colors.red,
      );
    }
  }

  Future<void> _importBackupDialog(String serverKey) async {
    final appConfigProvider =
        Provider.of<AppConfigProvider>(context, listen: false);
    final payload = await showDialog<(String, bool)?>(
      context: context,
      builder: (_) => const _ImportBackupDialog(),
    );
    if (payload == null || !mounted) return;

    final (rawJson, mapToCurrent) = payload;
    final filteringProvider =
        Provider.of<FilteringProvider>(context, listen: false);
    try {
      final res = await _provenanceService.importBackupJson(
        rawJson,
        importIntoServerKey: mapToCurrent ? serverKey : null,
        currentCoreRulesForTargetServer:
            mapToCurrent ? filteringProvider.filtering?.userRules : null,
        overwriteStorageIfCorrupted: _provenanceService.hasStorageError,
      );
      await _refreshAndSyncWithCore();
      if (!mounted) return;
      showSnackbar(
        appConfigProvider: appConfigProvider,
        label:
            '导入成功：新增 ${res.importedCount} 条，更新 ${res.updatedCount} 条（默认待确认，未改动 Core 规则）',
        color: Colors.green,
      );
    } catch (e) {
      if (!mounted) return;
      showSnackbar(
        appConfigProvider: appConfigProvider,
        label: '导入校验失败，未修改现有记录：$e',
        color: Colors.red,
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final serversProvider = Provider.of<ServersProvider>(context);
    final server = serversProvider.selectedServer;
    final serverKey = server == null
        ? null
        : ServerRuleWriteQueue.serverKeyFor(server);
    final colorScheme = Theme.of(context).colorScheme;
    final records =
        serverKey == null ? const <ManualRuleRecord>[] : _filteredRecords(serverKey);

    return Scaffold(
      appBar: AppBar(
        title: const Text('我的手动规则'),
        actions: [
          IconButton(
            onPressed: _syncingCore ? null : _refreshAndSyncWithCore,
            tooltip: '与 Core 规则同步',
            icon: _syncingCore
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.sync_rounded),
          ),
          if (serverKey != null)
            IconButton(
              onPressed: () => _openClaimExistingRulesSheet(serverKey),
              tooltip: '认领未记录规则',
              icon: const Icon(Icons.bookmark_add_outlined),
            ),
          PopupMenuButton<String>(
            tooltip: '备份与排序',
            onSelected: (value) {
              if (value == 'sort') {
                setState(() => _newestFirst = !_newestFirst);
              } else if (value == 'export' && serverKey != null) {
                _exportBackupDialog(serverKey);
              } else if (value == 'import' && serverKey != null) {
                _importBackupDialog(serverKey);
              }
            },
            itemBuilder: (_) => [
              PopupMenuItem(
                value: 'sort',
                child: Text(_newestFirst ? '切换为最早添加优先' : '切换为最新添加优先'),
              ),
              const PopupMenuItem(
                value: 'export',
                child: Text('导出备份 JSON / 分享'),
              ),
              const PopupMenuItem(
                value: 'import',
                child: Text('导入备份 JSON'),
              ),
            ],
          ),
        ],
      ),
      body: Column(
        children: [
          if (_provenanceService.hasStorageError)
            Container(
              width: double.infinity,
              margin: const EdgeInsets.fromLTRB(12, 8, 12, 0),
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: colorScheme.errorContainer,
                borderRadius: BorderRadius.circular(10),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    '本地来源记录文件读取异常（已安全降级为“来源未确认”，Core 规则完全未受影响）',
                    style: TextStyle(
                      fontWeight: FontWeight.w700,
                      color: colorScheme.onErrorContainer,
                    ),
                  ),
                  const SizedBox(height: 6),
                  Wrap(
                    spacing: 8,
                    children: [
                      if (serverKey != null)
                        OutlinedButton(
                          onPressed: () => _importBackupDialog(serverKey),
                          child: const Text('从备份导入覆盖'),
                        ),
                      TextButton(
                        onPressed: () async {
                          await _provenanceService
                              .resetCorruptedStoreForRecovery();
                          await _refreshAndSyncWithCore();
                        },
                        child: const Text('重建空白来源库'),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          Padding(
            padding: const EdgeInsets.fromLTRB(12, 10, 12, 6),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                TextField(
                  controller: _searchController,
                  onChanged: (v) => setState(() => _searchQuery = v),
                  decoration: InputDecoration(
                    prefixIcon: const Icon(Icons.search_rounded),
                    suffixIcon: _searchQuery.isNotEmpty
                        ? IconButton(
                            onPressed: () {
                              _searchController.clear();
                              setState(() => _searchQuery = '');
                            },
                            icon: const Icon(Icons.clear_rounded),
                          )
                        : null,
                    hintText: '搜索规则原文、域名、入口或备注...',
                    isDense: true,
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(10),
                    ),
                  ),
                ),
                const SizedBox(height: 8),
                SingleChildScrollView(
                  scrollDirection: Axis.horizontal,
                  child: Row(
                    children: [
                      for (final f in _ManualRulesFilter.values)
                        Padding(
                          padding: const EdgeInsets.only(right: 6),
                          child: ChoiceChip(
                            label: Text(
                              f.label,
                              style: const TextStyle(fontSize: 12),
                            ),
                            selected: _filter == f,
                            visualDensity: VisualDensity.compact,
                            onSelected: (_) => setState(() => _filter = f),
                          ),
                        ),
                    ],
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  '说明：来源记录与备注保存在本机应用数据目录，覆盖升级与重启均保留；卸载或清除应用数据前请先导出备份。',
                  style: TextStyle(
                    fontSize: 11.5,
                    color: colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ),
          ),
          const Divider(height: 1),
          Expanded(
            child: serverKey == null
                ? const Center(child: Text('请先选择或连接服务器'))
                : records.isEmpty
                    ? Center(
                        child: Padding(
                          padding: const EdgeInsets.all(24),
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Icon(
                                Icons.rule_folder_outlined,
                                size: 42,
                                color: colorScheme.onSurfaceVariant,
                              ),
                              const SizedBox(height: 10),
                              const Text(
                                '当前筛选下没有手动管理规则记录',
                                style: TextStyle(fontWeight: FontWeight.w600),
                              ),
                              const SizedBox(height: 6),
                              Text(
                                '如果你升级前已有自定义规则，或由其他端添加过规则，可点击右上角“认领未记录规则”主动纳入管理。',
                                textAlign: TextAlign.center,
                                style: TextStyle(
                                  fontSize: 12.5,
                                  color: colorScheme.onSurfaceVariant,
                                ),
                              ),
                              const SizedBox(height: 12),
                              OutlinedButton.icon(
                                onPressed: () =>
                                    _openClaimExistingRulesSheet(serverKey),
                                icon: const Icon(Icons.bookmark_add_outlined),
                                label: const Text('查看未记录来源的规则'),
                              ),
                            ],
                          ),
                        ),
                      )
                    : ListView.builder(
                        padding: const EdgeInsets.fromLTRB(12, 8, 12, 24),
                        itemCount: records.length,
                        itemBuilder: (ctx, idx) =>
                            _buildRecordCard(ctx, records[idx]),
                      ),
          ),
        ],
      ),
    );
  }

  Future<void> _claimUnconfirmedRecordDialog(ManualRuleRecord rec) async {
    final filteringProvider =
        Provider.of<FilteringProvider>(context, listen: false);
    final appConfigProvider =
        Provider.of<AppConfigProvider>(context, listen: false);

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('主动认领以建立当前管理关联？'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              '当前记录仅保留历史信息（可能由外部变更、核心重启或备份导入引入）。主动认领后将标为“用户认领”并记录当前认领时间，仅建立当前管理关联，不会修改 Core 过滤规则。',
            ),
            const SizedBox(height: 10),
            Text(
              rec.ruleText,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('确认认领'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    await filteringProvider.fetchFilters(showLoading: false);
    if (!mounted) return;
    final ok = await filteringProvider.claimExistingCustomRule(
      rec.ruleText,
      note: rec.note,
    );
    if (!mounted) return;
    showSnackbar(
      appConfigProvider: appConfigProvider,
      label: ok ? '已建立新的“用户认领”管理关联' : '认领失败：Core 中未找到唯一匹配规则',
      color: ok ? Colors.green : Colors.red,
    );
  }

  Widget _buildRecordCard(BuildContext context, ManualRuleRecord rec) {
    final cs = Theme.of(context).colorScheme;
    final cls = rec.classification;
    final display = RuleSourceDisplay(
      label: rec.primaryLabel,
      secondaryHint: _syncSecondaryHint(rec),
      record: rec,
      isManualOrigin: rec.source == ManualRuleSource.manual,
      isClaimedOrigin: rec.source == ManualRuleSource.claimed,
      isUnconfirmedOrAmbiguous:
          rec.syncStatus == ManualRuleSyncStatus.unconfirmed ||
              rec.syncStatus == ManualRuleSyncStatus.duplicateAmbiguous,
      isDuplicateAmbiguous:
          rec.syncStatus == ManualRuleSyncStatus.duplicateAmbiguous,
    );
    final live = _effectivenessByRecordId[rec.recordId];

    return Card(
      margin: const EdgeInsets.only(bottom: 10),
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: cs.outlineVariant.withValues(alpha: 0.7)),
      ),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Expanded(child: RuleProvenanceBadge(display: display)),
                const SizedBox(width: 8),
                IconButton(
                  visualDensity: VisualDensity.compact,
                  tooltip: '复制规则原文',
                  icon: const Icon(Icons.copy_rounded, size: 17),
                  onPressed: () => copyToClipboard(
                    value: rec.ruleText,
                    successMessage: '已复制规则原文',
                  ),
                ),
              ],
            ),
            const SizedBox(height: 6),
            Text(
              '历史来源：${rec.historicalOriginLabel}（${rec.historicalActionLabel}） · 当前关联：${rec.associationStatusLabel}',
              style: TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w600,
                color: cs.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 8),
            SelectableText(
              rec.ruleText,
              style: const TextStyle(
                fontFamily: 'monospace',
                fontSize: 13.5,
                fontWeight: FontWeight.w700,
              ),
            ),
            const SizedBox(height: 6),
            Text(
              '作用范围：${cls.scopeSummary}',
              style: TextStyle(fontSize: 12.5, color: cs.onSurface),
            ),
            const SizedBox(height: 3),
            Text(
              rec.source == ManualRuleSource.claimed
                  ? '入口：${rec.entryPoint} · 原添加时间未知（认领于 ${formatManualRuleTimestamp(rec.claimedAt)}）'
                  : '入口：${rec.entryPoint} · 添加于 ${formatManualRuleTimestamp(rec.createdAt)}',
              style: TextStyle(fontSize: 12, color: cs.onSurfaceVariant),
            ),
            if (rec.confirmedRevision != null) ...[
              const SizedBox(height: 2),
              Text(
                '确认版本：${rec.confirmedRevision}',
                style: TextStyle(fontSize: 11.5, color: cs.onSurfaceVariant),
              ),
            ],
            if (rec.note != null && rec.note!.isNotEmpty) ...[
              const SizedBox(height: 6),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: cs.surfaceContainerHighest.withValues(alpha: 0.65),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(
                  '备注：${rec.note!}',
                  style: TextStyle(fontSize: 12, color: cs.onSurface),
                ),
              ),
            ],
            if (live != null) ...[
              const SizedBox(height: 8),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: _liveBgColor(live.kind, cs),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(
                  live.summary,
                  style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w500,
                    color: _liveFgColor(live.kind, cs),
                  ),
                ),
              ),
            ],
            const SizedBox(height: 10),
            Wrap(
              spacing: 8,
              runSpacing: 6,
              children: [
                if (rec.syncStatus == ManualRuleSyncStatus.unconfirmed)
                  FilledButton.tonalIcon(
                    onPressed: () => _claimUnconfirmedRecordDialog(rec),
                    icon: const Icon(Icons.bookmark_added_outlined, size: 16),
                    label: const Text('主动认领'),
                  ),
                OutlinedButton.icon(
                  onPressed: live?.kind == _LiveEffectivenessKind.checking
                      ? null
                      : () => _checkRecordEffectiveness(rec),
                  icon: const Icon(Icons.fact_check_outlined, size: 16),
                  label: const Text('检查是否生效'),
                ),
                OutlinedButton.icon(
                  onPressed: () => _editNoteDialog(rec),
                  icon: const Icon(Icons.edit_note_rounded, size: 16),
                  label: const Text('编辑备注'),
                ),
                TextButton(
                  onPressed: () => _removeMetadataOnlyDialog(rec),
                  child: const Text('移除管理记录，保留规则'),
                ),
                if (rec.syncStatus != ManualRuleSyncStatus.missing)
                  TextButton.icon(
                    style: TextButton.styleFrom(foregroundColor: cs.error),
                    onPressed: () => _removeRuleFromCoreDialog(rec),
                    icon: const Icon(Icons.delete_outline_rounded, size: 16),
                    label: const Text('移除规则'),
                  ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  String? _syncSecondaryHint(ManualRuleRecord rec) {
    switch (rec.syncStatus) {
      case ManualRuleSyncStatus.present:
        return null;
      case ManualRuleSyncStatus.missing:
        return '历史来源：${rec.historicalActionLabel} · 已不在 Core 中';
      case ManualRuleSyncStatus.unconfirmed:
        return '历史来源：${rec.historicalActionLabel} · 外部变更或重启后待确认';
      case ManualRuleSyncStatus.duplicateAmbiguous:
        return '历史来源：${rec.historicalActionLabel} · Core 存在重复相同行';
    }
  }

  Color _liveBgColor(_LiveEffectivenessKind kind, ColorScheme cs) {
    switch (kind) {
      case _LiveEffectivenessKind.matchedThisManualRule:
        return Colors.teal.withValues(alpha: 0.14);
      case _LiveEffectivenessKind.coveredByImportantBlock:
      case _LiveEffectivenessKind.blockedByOtherRule:
        return Colors.red.withValues(alpha: 0.12);
      case _LiveEffectivenessKind.matchedOtherRule:
      case _LiveEffectivenessKind.missingInCore:
        return Colors.amber.withValues(alpha: 0.16);
      case _LiveEffectivenessKind.complexUnsupported:
      case _LiveEffectivenessKind.checking:
        return cs.surfaceContainerHighest;
      case _LiveEffectivenessKind.checkFailed:
        return cs.errorContainer;
    }
  }

  Color _liveFgColor(_LiveEffectivenessKind kind, ColorScheme cs) {
    switch (kind) {
      case _LiveEffectivenessKind.matchedThisManualRule:
        return Colors.teal.shade900;
      case _LiveEffectivenessKind.coveredByImportantBlock:
      case _LiveEffectivenessKind.blockedByOtherRule:
        return Colors.red.shade900;
      case _LiveEffectivenessKind.matchedOtherRule:
      case _LiveEffectivenessKind.missingInCore:
        return Colors.amber.shade900;
      case _LiveEffectivenessKind.complexUnsupported:
      case _LiveEffectivenessKind.checking:
        return cs.onSurface;
      case _LiveEffectivenessKind.checkFailed:
        return cs.onErrorContainer;
    }
  }
}

class _EditNoteDialog extends StatefulWidget {
  final String ruleText;
  final String initialNote;

  const _EditNoteDialog({
    required this.ruleText,
    required this.initialNote,
  });

  @override
  State<_EditNoteDialog> createState() => _EditNoteDialogState();
}

class _EditNoteDialogState extends State<_EditNoteDialog> {
  late final TextEditingController _controller;

  @override
  void initState() {
    super.initState();
    _controller = TextEditingController(text: widget.initialNote);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('编辑备注'),
      content: SingleChildScrollView(
        child: SizedBox(
          width: double.maxFinite,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                widget.ruleText,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _controller,
                maxLines: 3,
                decoration: const InputDecoration(
                  labelText: '备注（仅本地管理使用，不会发送给 Core）',
                  border: OutlineInputBorder(),
                ),
              ),
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('取消'),
        ),
        FilledButton(
          onPressed: () => Navigator.pop(context, _controller.text),
          child: const Text('保存备注'),
        ),
      ],
    );
  }
}

class _ImportBackupDialog extends StatefulWidget {
  const _ImportBackupDialog();

  @override
  State<_ImportBackupDialog> createState() => _ImportBackupDialogState();
}

class _ImportBackupDialogState extends State<_ImportBackupDialog> {
  late final TextEditingController _controller;
  bool _importIntoCurrentServer = true;

  @override
  void initState() {
    super.initState();
    _controller = TextEditingController();
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('导入手动规则来源备份'),
      content: SingleChildScrollView(
        child: SizedBox(
          width: double.maxFinite,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                '安全约束：导入仅恢复本地来源记录和备注，绝不向 Core 提交或覆盖过滤规则。',
                style: TextStyle(fontSize: 12.5),
              ),
              const SizedBox(height: 10),
              CheckboxListTile(
                value: _importIntoCurrentServer,
                contentPadding: EdgeInsets.zero,
                title: const Text(
                  '映射导入到当前服务器',
                  style: TextStyle(fontSize: 13.5),
                ),
                subtitle: const Text(
                  '勾选后可用于迁移恢复；不勾选则按原 server_key 导入',
                  style: TextStyle(fontSize: 11.5),
                ),
                onChanged: (v) {
                  setState(() {
                    _importIntoCurrentServer = v ?? true;
                  });
                },
              ),
              const SizedBox(height: 8),
              TextField(
                controller: _controller,
                maxLines: 6,
                decoration: const InputDecoration(
                  hintText: '粘贴备份 JSON 内容...',
                  border: OutlineInputBorder(),
                ),
                style: const TextStyle(fontFamily: 'monospace', fontSize: 11.5),
              ),
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('取消'),
        ),
        FilledButton(
          onPressed: () => Navigator.pop(
            context,
            (_controller.text, _importIntoCurrentServer),
          ),
          child: const Text('校验并导入'),
        ),
      ],
    );
  }
}
