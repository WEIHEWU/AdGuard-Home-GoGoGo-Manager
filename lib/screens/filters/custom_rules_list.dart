// ignore_for_file: use_build_context_synchronously

import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:provider/provider.dart';
import 'package:adguard_home_manager/l10n/app_localizations.dart';

import 'package:adguard_home_manager/screens/filters/add_button.dart';
import 'package:adguard_home_manager/screens/filters/modals/custom_rules/sort_rules.dart';
import 'package:adguard_home_manager/screens/filters/my_manual_rules_screen.dart';
import 'package:adguard_home_manager/widgets/rule_provenance_badge.dart';
import 'package:adguard_home_manager/widgets/tab_content_list.dart';

import 'package:adguard_home_manager/functions/snackbar.dart';
import 'package:adguard_home_manager/models/filtering.dart';
import 'package:adguard_home_manager/providers/app_config_provider.dart';
import 'package:adguard_home_manager/constants/enums.dart';
import 'package:adguard_home_manager/providers/filtering_provider.dart';
import 'package:adguard_home_manager/providers/servers_provider.dart';
import 'package:adguard_home_manager/services/host_rule_diagnostics.dart';
import 'package:adguard_home_manager/services/manual_rule_provenance_service.dart';

class CustomRulesList extends StatefulWidget {
  final LoadStatus loadStatus;
  final ScrollController? scrollController;
  final List<String> data;
  final PrecomputedCustomRules? precomputedRules;
  final void Function(String) onRemoveCustomRule;

  const CustomRulesList({
    super.key,
    required this.loadStatus,
    this.scrollController,
    required this.data,
    this.precomputedRules,
    required this.onRemoveCustomRule,
  });

  @override
  State<CustomRulesList> createState() => _CustomRulesListState();
}

class _CustomRulesListState extends State<CustomRulesList>
    with AutomaticKeepAliveClientMixin {
  static const int _initialPageSize = 150;
  static const int _pageIncrement = 200;

  late final ScrollController _internalScrollController;
  final ValueNotifier<bool> _fabVisible = ValueNotifier<bool>(true);

  CustomRulesSorting _sortingMethod = CustomRulesSorting.topBottom;
  String _ruleFilter = 'active'; // 'active' | 'allow' | 'block' | 'all'
  int _pagedLimit = _initialPageSize;
  int _lastTotalFilteredLength = 0;

  PrecomputedCustomRules? _fallbackPrecomputed;
  List<String>? _fallbackSourceData;

  ScrollController get _effectiveScrollController =>
      widget.scrollController ?? _internalScrollController;

  @override
  bool get wantKeepAlive => true;

  PrecomputedCustomRules _resolvePrecomputed() {
    if (widget.precomputedRules != null) {
      return widget.precomputedRules!;
    }
    if (identical(_fallbackSourceData, widget.data) &&
        _fallbackPrecomputed != null) {
      return _fallbackPrecomputed!;
    }
    _fallbackSourceData = widget.data;
    _fallbackPrecomputed = PrecomputedCustomRules.fromRawRules(widget.data);
    return _fallbackPrecomputed!;
  }

  void _onScroll() {
    if (!_effectiveScrollController.hasClients) return;
    final position = _effectiveScrollController.position;
    final direction = position.userScrollDirection;
    if (direction == ScrollDirection.reverse) {
      if (_fabVisible.value) {
        _fabVisible.value = false;
      }
    } else if (direction == ScrollDirection.forward) {
      if (!_fabVisible.value) {
        _fabVisible.value = true;
      }
    }

    if (_pagedLimit < _lastTotalFilteredLength &&
        position.pixels >= position.maxScrollExtent - 600) {
      setState(() {
        _pagedLimit = math.min(
          _lastTotalFilteredLength,
          _pagedLimit + _pageIncrement,
        );
      });
    }
  }

  final ManualRuleProvenanceService _provenanceService =
      ManualRuleProvenanceService.instance;

  void _onProvenanceChanged() {
    if (mounted) setState(() {});
  }

  @override
  void initState() {
    super.initState();
    _internalScrollController = ScrollController();
    _effectiveScrollController.addListener(_onScroll);
    _provenanceService.addListener(_onProvenanceChanged);
    _provenanceService.ensureLoaded();
  }

  @override
  void dispose() {
    _provenanceService.removeListener(_onProvenanceChanged);
    _effectiveScrollController.removeListener(_onScroll);
    if (widget.scrollController == null) {
      _internalScrollController.dispose();
    }
    _fabVisible.dispose();
    super.dispose();
  }

  Future<void> _showRuleProvenanceDialog({
    required BuildContext context,
    required String rule,
    required RuleSourceDisplay display,
    required FilteringProvider filteringProvider,
    required AppConfigProvider appConfigProvider,
    required String? serverKey,
  }) async {
    final cls = RuleClassification.classify(rule);
    final rec = display.record;
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('自定义规则详情与来源'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              RuleProvenanceBadge(display: display),
              const SizedBox(height: 10),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: Theme.of(ctx).colorScheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: SelectableText(
                  rule,
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 12.5,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
              const SizedBox(height: 8),
              Text('作用范围：${cls.scopeSummary}'),
              if (rec != null) ...[
                const SizedBox(height: 4),
                Text(
                  rec.source == ManualRuleSource.claimed
                      ? '入口：${rec.entryPoint} · 原添加时间未知（认领于 ${formatManualRuleTimestamp(rec.claimedAt)}）'
                      : '入口：${rec.entryPoint} · 添加时间：${formatManualRuleTimestamp(rec.createdAt)}',
                  style: TextStyle(
                    fontSize: 12,
                    color: Theme.of(ctx).colorScheme.onSurfaceVariant,
                  ),
                ),
                if (rec.note != null && rec.note!.isNotEmpty) ...[
                  const SizedBox(height: 6),
                  Text('备注：${rec.note!}'),
                ],
              ] else ...[
                const SizedBox(height: 6),
                Text(
                  display.isUnconfirmedOrAmbiguous
                      ? (display.secondaryHint ?? '来源记录当前无法确认，请检查本地备份或批量规则')
                      : '暂未记录操作来源（可能由升级前添加、外部 Web 控制台或配置同步引入）。你可以主动将其认领为我的手动规则，系统仅记录认领时间而不伪造历史添加时间。',
                  style: TextStyle(
                    fontSize: 12,
                    color: Theme.of(ctx).colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ],
          ),
        ),
        actions: [
          if (display.isUnrecordedCustom && serverKey != null)
            TextButton(
              onPressed: () async {
                Navigator.pop(ctx);
                final noteResult = await showDialog<String?>(
                  context: context,
                  builder: (_) => const _ClaimExistingRuleDialog(),
                );
                if (noteResult == null || !context.mounted) return;
                final ok = await filteringProvider.claimExistingCustomRule(
                  rule,
                  note: noteResult,
                );
                if (!context.mounted) return;
                showSnackbar(
                  appConfigProvider: appConfigProvider,
                  label: ok ? '已标记为“用户认领”' : '认领失败，请刷新后重试',
                  color: ok ? Colors.green : Colors.red,
                );
              },
              child: const Text('标记为我的手动管理规则'),
            ),
          if (rec != null && rec.syncStatus != ManualRuleSyncStatus.missing)
            TextButton(
              onPressed: () {
                Navigator.pop(ctx);
                Navigator.push(
                  context,
                  MaterialPageRoute(builder: (_) => const MyManualRulesScreen()),
                );
              },
              child: const Text('在“我的手动规则”管理'),
            ),
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('关闭'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final filteringProvider =
        Provider.of<FilteringProvider>(context, listen: false);
    final appConfigProvider =
        Provider.of<AppConfigProvider>(context, listen: false);
    final serversProvider =
        Provider.of<ServersProvider>(context, listen: false);
    final server = serversProvider.selectedServer;
    final serverKey =
        server == null ? null : ServerRuleWriteQueue.serverKeyFor(server);
    final coreRuleCounts = RuleListDiffResult.countExactRules(widget.data);
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    final precomputed = _resolvePrecomputed();
    final renderEntries = precomputed.getEntries(
      filter: _ruleFilter,
      sorting: _sortingMethod,
    );
    _lastTotalFilteredLength = renderEntries.length;
    final visibleCount = math.min(_pagedLimit, renderEntries.length);

    final activeCount = precomputed.activeCount;
    final allowCount = precomputed.allowCount;
    final blockCount = precomputed.blockCount;
    final totalCount = precomputed.totalCount;

    final allowedSubtitle = Text(
      l10n.allowed,
      style: const TextStyle(
        color: Colors.green,
        fontSize: 12,
        fontWeight: FontWeight.w600,
      ),
    );
    final commentSubtitle = Text(
      l10n.comment,
      style: const TextStyle(
        color: Colors.grey,
        fontSize: 12,
      ),
    );
    final blockedSubtitle = Text(
      l10n.blocked,
      style: const TextStyle(
        color: Colors.red,
        fontSize: 12,
        fontWeight: FontWeight.w600,
      ),
    );
    final commentTitleStyle = TextStyle(
      color: colorScheme.onSurface.withValues(alpha: 0.55),
      fontWeight: FontWeight.normal,
      fontFamily: 'monospace',
      fontSize: 13.5,
    );
    final activeTitleStyle = TextStyle(
      color: colorScheme.onSurface,
      fontWeight: FontWeight.w500,
      fontFamily: 'monospace',
      fontSize: 13.5,
    );

    void showSortingMethodModal() {
      showDialog(
        context: context,
        builder: (ctx) => SortCustomRulesModal(
          sortingMethod: _sortingMethod,
          onSelect: (value) => setState(() {
            _sortingMethod = value;
            _pagedLimit = _initialPageSize;
          }),
        ),
      );
    }

    Widget buildFilterBar() {
      final chips = [
        (key: 'active', label: '全部生效 ($activeCount)'),
        (key: 'allow', label: '仅看放行 ($allowCount)'),
        (key: 'block', label: '仅看拦截 ($blockCount)'),
        (key: 'all', label: '显示注释 ($totalCount)'),
      ];
      return SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        padding: const EdgeInsets.fromLTRB(16, 10, 16, 6),
        child: Row(
          children: chips.map((c) {
            final selected = _ruleFilter == c.key;
            return Padding(
              padding: const EdgeInsets.only(right: 8),
              child: ChoiceChip(
                label: Text(
                  c.label,
                  style: TextStyle(
                    fontSize: 12,
                    fontWeight: selected ? FontWeight.w600 : FontWeight.w500,
                  ),
                ),
                selected: selected,
                visualDensity: VisualDensity.compact,
                onSelected: (_) => setState(() {
                  _ruleFilter = c.key;
                  _pagedLimit = _initialPageSize;
                }),
              ),
            );
          }).toList(growable: false),
        ),
      );
    }

    final hasAnyRules = totalCount > 0;
    final listCount = !hasAnyRules
        ? 0
        : (renderEntries.isEmpty ? 1 : visibleCount);

    return CustomTabContentList(
      scrollController: _effectiveScrollController,
      headerWidget: hasAnyRules ? buildFilterBar() : null,
      itemExtent: null,
      loadingGenerator: () => SizedBox(
        width: double.maxFinite,
        height: MediaQuery.of(context).size.height - 171,
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            const CircularProgressIndicator(),
            const SizedBox(height: 30),
            Text(
              l10n.loadingFilters,
              style: TextStyle(
                fontSize: 22,
                color: colorScheme.onSurfaceVariant,
              ),
            )
          ],
        ),
      ),
      itemsCount: listCount,
      contentWidget: (index) {
        if (renderEntries.isEmpty) {
          return Padding(
            padding: const EdgeInsets.symmetric(vertical: 48, horizontal: 24),
            child: Center(
              child: Text(
                '当前筛选下暂无规则',
                style: TextStyle(
                  fontSize: 15,
                  color: colorScheme.onSurfaceVariant,
                ),
              ),
            ),
          );
        }
        final entry = renderEntries[index];
        final Widget typeLabel;
        switch (entry.type) {
          case CustomRuleType.allow:
            typeLabel = allowedSubtitle;
            break;
          case CustomRuleType.comment:
            typeLabel = commentSubtitle;
            break;
          case CustomRuleType.block:
            typeLabel = blockedSubtitle;
            break;
        }
        final cleanRule = entry.raw.trim();
        final dupCount = coreRuleCounts[cleanRule] ?? 1;
        final display = entry.isComment
            ? null
            : _provenanceService.resolveCustomListRowDisplay(
                serverKey: serverKey,
                rawRule: cleanRule,
                duplicateCountInCore: dupCount,
              );
        final noteSnippet = display?.record?.note;

        return ListTile(
          key: ValueKey<String>('${index}_${entry.raw}'),
          dense: true,
          onTap: entry.isComment || display == null
              ? null
              : () => _showRuleProvenanceDialog(
                    context: context,
                    rule: entry.raw,
                    display: display,
                    filteringProvider: filteringProvider,
                    appConfigProvider: appConfigProvider,
                    serverKey: serverKey,
                  ),
          title: Text(
            entry.raw,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: entry.isComment ? commentTitleStyle : activeTitleStyle,
          ),
          subtitle: entry.isComment || display == null
              ? typeLabel
              : Padding(
                  padding: const EdgeInsets.only(top: 3),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Wrap(
                        spacing: 6,
                        runSpacing: 4,
                        crossAxisAlignment: WrapCrossAlignment.center,
                        children: [
                          typeLabel,
                          RuleProvenanceBadge(display: display, compact: true),
                        ],
                      ),
                      if (noteSnippet != null && noteSnippet.isNotEmpty)
                        Padding(
                          padding: const EdgeInsets.only(top: 2),
                          child: Text(
                            '备注：$noteSnippet',
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: TextStyle(
                              fontSize: 11,
                              color: colorScheme.onSurfaceVariant,
                            ),
                          ),
                        ),
                    ],
                  ),
                ),
          trailing: IconButton(
            onPressed: () => widget.onRemoveCustomRule(entry.raw),
            icon: const Icon(Icons.delete_outline_rounded, size: 20),
          ),
        );
      },
      noData: Container(
        width: double.maxFinite,
        padding: const EdgeInsets.symmetric(horizontal: 16),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Flexible(
              child: Text(
                l10n.noCustomFilters,
                textAlign: TextAlign.center,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  fontSize: 24,
                  color: colorScheme.onSurfaceVariant,
                ),
              ),
            ),
            const SizedBox(height: 30),
            TextButton.icon(
              onPressed: () async {
                final result = await filteringProvider.fetchFilters();
                if (result == false && context.mounted) {
                  showSnackbar(
                    appConfigProvider: appConfigProvider,
                    label: l10n.errorLoadFilters,
                    color: Colors.red,
                  );
                }
              },
              icon: const Icon(Icons.refresh_rounded),
              label: Text(l10n.refresh),
            )
          ],
        ),
      ),
      errorGenerator: () => SizedBox(
        width: double.maxFinite,
        height: MediaQuery.of(context).size.height - 171,
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            const Icon(
              Icons.error,
              color: Colors.red,
              size: 50,
            ),
            const SizedBox(height: 30),
            Text(
              l10n.filtersNotLoaded,
              style: TextStyle(
                fontSize: 22,
                color: colorScheme.onSurfaceVariant,
              ),
            )
          ],
        ),
      ),
      loadStatus: widget.loadStatus,
      onRefresh: () async {
        final result = await filteringProvider.fetchFilters();
        if (result == false && context.mounted) {
          showSnackbar(
            appConfigProvider: appConfigProvider,
            label: l10n.errorLoadFilters,
            color: Colors.red,
          );
        }
      },
      fab: Column(
        children: [
          FloatingActionButton.small(
            heroTag: 'custom_rules_sort_fab',
            onPressed: showSortingMethodModal,
            child: const Icon(Icons.sort_rounded),
          ),
          const SizedBox(height: 16),
          AddFiltersButton(
            type: 'edit_custom_rule',
            widget: (fn) => FloatingActionButton.small(
              heroTag: 'custom_rules_edit_fab',
              onPressed: fn,
              child: const Icon(Icons.edit_rounded),
            ),
          ),
          const SizedBox(height: 16),
          AddFiltersButton(
            type: 'add_custom_rule',
            widget: (fn) => FloatingActionButton(
              heroTag: 'custom_rules_add_fab',
              onPressed: fn,
              child: const Icon(Icons.add),
            ),
          ),
        ],
      ),
      heightFabHidden: -180,
      fabVisibleListenable: _fabVisible,
    );
  }
}

class _ClaimExistingRuleDialog extends StatefulWidget {
  const _ClaimExistingRuleDialog();

  @override
  State<_ClaimExistingRuleDialog> createState() =>
      _ClaimExistingRuleDialogState();
}

class _ClaimExistingRuleDialogState extends State<_ClaimExistingRuleDialog> {
  late final TextEditingController _controller;

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
      title: const Text('标记为我的手动管理规则'),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              '这是主动认领，无法追溯原始添加者及添加时间；确认后将标为“用户认领”并记录当前认领时间，不会修改 Core 规则本身。',
            ),
            const SizedBox(height: 10),
            TextField(
              controller: _controller,
              maxLines: 2,
              decoration: const InputDecoration(
                labelText: '可选备注（如：用于放行某服务）',
                border: OutlineInputBorder(),
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('取消'),
        ),
        FilledButton(
          onPressed: () => Navigator.pop(context, _controller.text),
          child: const Text('确认认领'),
        ),
      ],
    );
  }
}
