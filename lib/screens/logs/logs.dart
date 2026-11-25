// ignore_for_file: use_build_context_synchronously

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:adguard_home_manager/l10n/app_localizations.dart';

import 'package:adguard_home_manager/classes/process_modal.dart';
import 'package:adguard_home_manager/screens/logs/log_tile.dart';
import 'package:adguard_home_manager/widgets/floating_search_bar.dart';
import 'package:adguard_home_manager/widgets/log_status_indicator.dart';
import 'package:adguard_home_manager/widgets/options_menu.dart';
import 'package:adguard_home_manager/widgets/rule_provenance_badge.dart';
import 'package:adguard_home_manager/constants/enums.dart';
import 'package:adguard_home_manager/functions/copy_clipboard.dart';
import 'package:adguard_home_manager/functions/format_time.dart';
import 'package:adguard_home_manager/functions/get_filtered_status.dart';
import 'package:adguard_home_manager/functions/snackbar.dart';
import 'package:adguard_home_manager/models/applied_filters.dart';
import 'package:adguard_home_manager/models/filtering.dart';
import 'package:adguard_home_manager/models/logs.dart';
import 'package:adguard_home_manager/models/menu_option.dart';
import 'package:adguard_home_manager/providers/app_config_provider.dart';
import 'package:adguard_home_manager/providers/filtering_provider.dart';
import 'package:adguard_home_manager/providers/logs_provider.dart';
import 'package:adguard_home_manager/providers/servers_provider.dart';
import 'package:adguard_home_manager/providers/status_provider.dart';
import 'package:adguard_home_manager/services/host_rule_diagnostics.dart';
import 'package:adguard_home_manager/services/manual_rule_provenance_service.dart';

class Logs extends StatefulWidget {
  const Logs({super.key});

  @override
  State<Logs> createState() => _LogsState();
}

class _LogsState extends State<Logs> {
  final GlobalKey _searchButtonKey = GlobalKey();
  bool _clearing = false;
  bool _aggregateDuplicates = true;
  List<Log>? _cachedRawItems;
  Filtering? _cachedFiltering;
  bool? _cachedAggregateFlag;
  Map<int, String> _cachedFilterNames = const {};
  Map<int, String> _cachedWhitelistNames = const {};
  List<AggregatedLogGroup> _cachedAggregated = const [];

  @override
  void initState() {
    super.initState();
    ManualRuleProvenanceService.instance.ensureLoaded();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      Provider.of<LogsProvider>(context, listen: false).fetchLogs();
      final fp = Provider.of<FilteringProvider>(context, listen: false);
      if (fp.filtering == null) {
        fp.fetchFilters(showLoading: false);
      }
    });
  }

  Future<void> _handleClearLogs() async {
    if (_clearing) return;
    setState(() => _clearing = true);
    final logsProvider = Provider.of<LogsProvider>(context, listen: false);
    final appConfigProvider =
        Provider.of<AppConfigProvider>(context, listen: false);
    final l10n = AppLocalizations.of(context)!;

    final ok = await logsProvider.clearAllLogs();
    if (!mounted) return;
    setState(() => _clearing = false);
    showSnackbar(
      appConfigProvider: appConfigProvider,
      label: ok ? l10n.logsCleared : l10n.logsNotCleared,
      color: ok ? Colors.green : Colors.red,
    );
  }

  void _showSearchDialog(LogsProvider logsProvider) {
    showDialog(
      context: context,
      builder: (context) => FloatingSearchBar(
        existingSearchValue: logsProvider.appliedFilters.searchText ?? '',
        searchButtonRenderBox:
            _searchButtonKey.currentContext?.findRenderObject() as RenderBox?,
        onSearchCompleted: (v) {
          final text = v.trim().isNotEmpty ? v.trim() : null;
          logsProvider.setAppliedFilters(AppliedFiters(
            selectedResultStatus:
                logsProvider.appliedFilters.selectedResultStatus,
            searchText: text,
            clients: const [],
          ));
          logsProvider.filterLogs();
        },
        onSearchFieldUpdated: (v) {
          logsProvider.setSearchText(v.trim().isEmpty ? null : v.trim());
        },
        onSearchFieldCleared: () {
          logsProvider.setSearchText(null);
        },
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final logsProvider = Provider.of<LogsProvider>(context);
    final filteringProvider = Provider.of<FilteringProvider>(context);
    final l10n = AppLocalizations.of(context)!;
    final colorScheme = Theme.of(context).colorScheme;
    final items = logsProvider.logsData?.data ?? const [];
    final filteringModel = filteringProvider.filtering;
    if (!identical(_cachedFiltering, filteringModel)) {
      _cachedFiltering = filteringModel;
      _cachedFilterNames = RuleBatchChecker.buildFilterNameMap(
        filteringModel?.filters ?? const [],
      );
      _cachedWhitelistNames = RuleBatchChecker.buildFilterNameMap(
        filteringModel?.whitelistFilters ?? const [],
      );
      _cachedRawItems = null;
    }
    final filterNames = _cachedFilterNames;
    final whitelistNames = _cachedWhitelistNames;
    if (!identical(_cachedRawItems, items) ||
        _cachedAggregateFlag != _aggregateDuplicates) {
      _cachedRawItems = items;
      _cachedAggregateFlag = _aggregateDuplicates;
      _cachedAggregated = _aggregateDuplicates
          ? BlockedEventAggregator.aggregateRawLogs(
              items,
              filterNames: filterNames,
              whitelistNames: whitelistNames,
            )
          : const <AggregatedLogGroup>[];
    }
    final aggregated = _cachedAggregated;

    return Scaffold(
      appBar: AppBar(
        centerTitle: false,
        title: Text(l10n.logs),
        actions: [
          IconButton(
            key: _searchButtonKey,
            onPressed: () => _showSearchDialog(logsProvider),
            icon: const Icon(Icons.search_rounded),
            tooltip: l10n.search,
          ),
          IconButton(
            onPressed: () => logsProvider.fetchLogs(showLoading: true),
            icon: const Icon(Icons.refresh_rounded),
            tooltip: l10n.refresh,
          ),
          IconButton(
            onPressed: _clearing ? null : _handleClearLogs,
            icon: const Icon(Icons.delete_sweep_rounded),
            tooltip: l10n.clearLogs,
          ),
          const SizedBox(width: 4),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(46),
          child: SizedBox(
            height: 46,
            child: ListView(
              scrollDirection: Axis.horizontal,
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
              children: [
                for (final entry in const [
                  MapEntry('all', '全部'),
                  MapEntry('blocked', '已拦截'),
                  MapEntry('processed', '已放行'),
                ])
                  Padding(
                    padding: const EdgeInsets.only(right: 8),
                    child: ChoiceChip(
                      label: Text(
                        entry.value,
                        style: const TextStyle(fontSize: 12.5),
                      ),
                      selected:
                          logsProvider.appliedFilters.selectedResultStatus ==
                              entry.key,
                      visualDensity: VisualDensity.compact,
                      showCheckmark: false,
                      onSelected: (selected) {
                        if (!selected &&
                            logsProvider.appliedFilters.selectedResultStatus ==
                                entry.key) {
                          return;
                        }
                        logsProvider.setSelectedResultStatus(
                          value: entry.key,
                          refetch: true,
                        );
                      },
                    ),
                  ),
                if (logsProvider.appliedFilters.searchText != null)
                  Padding(
                    padding: const EdgeInsets.only(right: 8),
                    child: Chip(
                      visualDensity: VisualDensity.compact,
                      avatar: const Icon(Icons.search_rounded, size: 16),
                      label: Text(
                        logsProvider.appliedFilters.searchText!,
                        style: const TextStyle(fontSize: 12.5),
                      ),
                      deleteIcon: const Icon(Icons.clear, size: 16),
                      onDeleted: () {
                        logsProvider.setSearchText(null);
                        logsProvider.fetchLogs(showLoading: true);
                      },
                    ),
                  ),
                Padding(
                  padding: const EdgeInsets.only(right: 8),
                  child: FilterChip(
                    visualDensity: VisualDensity.compact,
                    label: Text(
                      _aggregateDuplicates ? '聚合重复' : '原始逐条',
                      style: const TextStyle(fontSize: 12.5),
                    ),
                    selected: _aggregateDuplicates,
                    onSelected: (v) => setState(() => _aggregateDuplicates = v),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
      body: RefreshIndicator(
        onRefresh: () => logsProvider.fetchLogs(showLoading: false),
        child: switch (logsProvider.loadStatus) {
          LoadStatus.loading => Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const CircularProgressIndicator(),
                  const SizedBox(height: 24),
                  Text(
                    l10n.loadingLogs,
                    style: TextStyle(
                      fontSize: 18,
                      color: colorScheme.onSurfaceVariant,
                    ),
                  ),
                ],
              ),
            ),
          LoadStatus.loaded => items.isEmpty
              ? ListView(
                  physics: const AlwaysScrollableScrollPhysics(),
                  children: [
                    SizedBox(
                      height: MediaQuery.of(context).size.height * 0.55,
                      child: Center(
                        child: Text(
                          l10n.noLogsDisplay,
                          style: TextStyle(
                            fontSize: 18,
                            color: colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ),
                    ),
                  ],
                )
              : _aggregateDuplicates
                  ? ListView.builder(
                      physics: const AlwaysScrollableScrollPhysics(),
                      itemCount: aggregated.length,
                      addAutomaticKeepAlives: false,
                      itemBuilder: (context, index) {
                        final group = aggregated[index];
                        if (group.count <= 1 && group.rawEvents.isNotEmpty) {
                          return LogTile(
                            key: ValueKey(
                                '${group.time.microsecondsSinceEpoch}_$index'),
                            log: group.rawEvents.first,
                            filterNames: filterNames,
                            whitelistNames: whitelistNames,
                          );
                        }
                        return _AggregatedLogsPageTile(
                          group: group,
                          filterNames: filterNames,
                          whitelistNames: whitelistNames,
                        );
                      },
                    )
                  : ListView.builder(
                      physics: const AlwaysScrollableScrollPhysics(),
                      itemCount: items.length,
                      addAutomaticKeepAlives: false,
                      itemBuilder: (context, index) {
                        final log = items[index];
                        if (log.question.name == null) {
                          return const SizedBox.shrink();
                        }
                        return LogTile(
                          key: ValueKey('${log.time.microsecondsSinceEpoch}_$index'),
                          log: log,
                          filterNames: filterNames,
                          whitelistNames: whitelistNames,
                        );
                      },
                    ),
          LoadStatus.error => Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const Icon(Icons.error, color: Colors.red, size: 48),
                  const SizedBox(height: 20),
                  Text(
                    l10n.logsNotLoaded,
                    style: TextStyle(
                      fontSize: 18,
                      color: colorScheme.onSurfaceVariant,
                    ),
                  ),
                ],
              ),
            ),
        },
      ),
    );
  }
}

class _AggregatedLogsPageTile extends StatelessWidget {
  final AggregatedLogGroup group;
  final Map<int, String> filterNames;
  final Map<int, String> whitelistNames;

  const _AggregatedLogsPageTile({
    required this.group,
    required this.filterNames,
    required this.whitelistNames,
  });

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final badgeColor = group.isSni ? Colors.purple : Colors.blue;
    final protoLabel = group.isSni ? 'SNI' : 'DNS';
    final timeStr = convertTimestampLocalTimezone(group.time, 'HH:mm:ss');
    final ruleSummary = group.matchedRules.isNotEmpty
        ? (group.matchedRules.first.sourceName.isNotEmpty
            ? '${group.matchedRules.first.sourceName}: ${group.matchedRules.first.text}'
            : group.matchedRules.first.text)
        : group.reason;

    final l10n = AppLocalizations.of(context)!;
    final appConfigProvider =
        Provider.of<AppConfigProvider>(context, listen: false);
    final statusProvider = Provider.of<StatusProvider>(context, listen: false);
    final domainBlocked = isDomainBlocked(group.reason);
    final hasPredictedBlocked = group.rawEvents.any((e) => e.predictedBlocked);

    Future<void> blockUnblock({
      required String domain,
      required String newStatus,
    }) async {
      if (!context.mounted) return;
      final processModal = ProcessModal();
      processModal.open(l10n.savingUserFilters);

      final outcome = await statusProvider.blockUnblockDomainDetailed(
        domain: domain,
        newStatus: newStatus,
        entryPoint: '日志详情',
      );

      processModal.close();
      if (!context.mounted) return;
      if (outcome.ok) {
        unawaited(
          Provider.of<FilteringProvider>(context, listen: false)
              .fetchFilters(showLoading: false),
        );
        if (outcome.provenanceInterrupted ||
            outcome.provenanceSaveFailed ||
            outcome.provenanceLegacyUnconfirmed ||
            outcome.readbackFailed) {
          showSnackbar(
            appConfigProvider: appConfigProvider,
            label: outcome.message ?? l10n.userFilteringRulesUpdated,
            color: Colors.orange,
          );
        } else {
          showSnackbar(
            appConfigProvider: appConfigProvider,
            label: l10n.userFilteringRulesUpdated,
            color: Colors.green,
          );
        }
      } else {
        showSnackbar(
          appConfigProvider: appConfigProvider,
          label: outcome.message ?? l10n.userFilteringRulesNotUpdated,
          color: Colors.red,
        );
      }
    }

    final menuOptions = <MenuOption>[
      MenuOption(
        title: domainBlocked ? l10n.unblockDomain : l10n.blockDomain,
        icon: domainBlocked ? Icons.check_rounded : Icons.block_rounded,
        action: () => blockUnblock(
          domain: group.domain,
          newStatus: domainBlocked ? 'unblock' : 'block',
        ),
      ),
      MenuOption(
        title: l10n.copyClipboard,
        icon: Icons.copy_rounded,
        action: () => copyToClipboard(
          value: group.domain,
          successMessage: l10n.copiedClipboard,
        ),
      ),
    ];

    return Material(
      color: Colors.transparent,
      child: OptionsMenu(
        options: (_) => menuOptions,
        onTap: (_) {
          showDialog(
            context: context,
            builder: (ctx) => AlertDialog(
              title: Text(group.domain, style: const TextStyle(fontSize: 15.5)),
              content: SizedBox(
                width: double.maxFinite,
                child: SingleChildScrollView(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('来源: $protoLabel · reason=${group.reason} · 重复 ${group.count} 次'),
                      if (hasPredictedBlocked) ...[
                        const SizedBox(height: 4),
                        const Text(
                          '规则预测: 规则命中阻断，但因保护暂停实际已放行',
                          style: TextStyle(fontSize: 12, color: Colors.orange),
                        ),
                      ],
                      if (group.matchedRules.isNotEmpty) ...[
                        const SizedBox(height: 8),
                        const Text('命中规则:', style: TextStyle(fontWeight: FontWeight.w600)),
                        for (final r in group.matchedRules)
                          Builder(
                            builder: (builderCtx) {
                              String? srvKey;
                              try {
                                srvKey = ManualRuleProvenanceService
                                    .serverKeyForNullable(
                                  Provider.of<ServersProvider>(builderCtx,
                                          listen: false)
                                      .selectedServer,
                                );
                              } catch (_) {
                                srvKey = null;
                              }
                              final disp = ManualRuleProvenanceService.instance
                                  .resolveMatchedRuleDisplay(
                                serverKey: srvKey,
                                ruleText: r.text,
                                filterListId: r.filterListId,
                                subscriptionDisplayName: r.sourceName,
                              );
                              return Padding(
                                padding: const EdgeInsets.only(top: 4),
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    RuleProvenanceBadge(
                                      compact: true,
                                      display: disp,
                                    ),
                                    const SizedBox(height: 2),
                                    Text(
                                      r.text,
                                      style: const TextStyle(
                                        fontFamily: 'monospace',
                                        fontSize: 12,
                                      ),
                                    ),
                                  ],
                                ),
                              );
                            },
                          ),
                      ],
                      const SizedBox(height: 10),
                      const Text('原始事件详情:', style: TextStyle(fontWeight: FontWeight.w600)),
                      for (final raw in group.rawEvents.take(20))
                        Padding(
                          padding: const EdgeInsets.only(top: 3),
                          child: Text(
                            '${convertTimestampLocalTimezone(raw.time, "HH:mm:ss.SSS")} · client=${raw.client}${raw.destination?.isNotEmpty == true ? " · dst=${raw.destination}" : ""}',
                            style: const TextStyle(fontSize: 11.5),
                          ),
                        ),
                      if (group.rawEvents.length > 20)
                        Padding(
                          padding: const EdgeInsets.only(top: 4),
                          child: Text('仅展示前 20 条（共 ${group.rawEvents.length} 条）',
                              style: TextStyle(fontSize: 11, color: colorScheme.onSurfaceVariant)),
                        ),
                    ],
                  ),
                ),
              ),
              actions: [
                TextButton(
                  onPressed: () {
                    Navigator.pop(ctx);
                    copyToClipboard(
                      value: group.domain,
                      successMessage: l10n.copiedClipboard,
                    );
                  },
                  child: Text(l10n.copyClipboard),
                ),
                TextButton(
                  onPressed: () => Navigator.pop(ctx),
                  child: const Text('关闭'),
                ),
                FilledButton.icon(
                  onPressed: () {
                    Navigator.pop(ctx);
                    blockUnblock(
                      domain: group.domain,
                      newStatus: domainBlocked ? 'unblock' : 'block',
                    );
                  },
                  icon: Icon(
                    domainBlocked ? Icons.check_rounded : Icons.block_rounded,
                    size: 18,
                  ),
                  label: Text(
                    domainBlocked ? l10n.unblockDomain : l10n.blockDomain,
                  ),
                ),
              ],
            ),
          );
        },
        child: Padding(
          padding: const EdgeInsets.fromLTRB(16, 10, 10, 10),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      group.domain,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(
                        fontSize: 15,
                        height: 1.3,
                        fontWeight: FontWeight.w500,
                        color: colorScheme.onSurface,
                      ),
                    ),
                    Padding(
                      padding: const EdgeInsets.only(top: 4),
                      child: Row(
                        children: [
                          Container(
                            padding: const EdgeInsets.symmetric(
                                horizontal: 5, vertical: 1),
                            decoration: BoxDecoration(
                              color: badgeColor.withValues(alpha: 0.12),
                              borderRadius: BorderRadius.circular(4),
                            ),
                            child: Text(
                              protoLabel,
                              style: TextStyle(
                                fontSize: 10.5,
                                fontWeight: FontWeight.bold,
                                color: badgeColor,
                              ),
                            ),
                          ),
                          const SizedBox(width: 6),
                          Expanded(
                            child: Text(
                              ruleSummary.isNotEmpty
                                  ? '$timeStr · $ruleSummary'
                                  : timeStr,
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: TextStyle(
                                color: colorScheme.onSurfaceVariant,
                                fontSize: 12,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 4),
              LogStatusIndicator(
                reason: group.reason,
                repeatCount: group.count,
              ),
            ],
          ),
        ),
      ),
    );
  }
}
