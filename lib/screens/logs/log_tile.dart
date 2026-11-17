// ignore_for_file: use_build_context_synchronously

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:adguard_home_manager/l10n/app_localizations.dart';

import 'package:adguard_home_manager/widgets/log_status_indicator.dart';
import 'package:adguard_home_manager/widgets/options_menu.dart';
import 'package:adguard_home_manager/widgets/rule_provenance_badge.dart';
import 'package:adguard_home_manager/providers/servers_provider.dart';
import 'package:adguard_home_manager/providers/status_provider.dart';
import 'package:adguard_home_manager/classes/process_modal.dart';
import 'package:adguard_home_manager/functions/snackbar.dart';
import 'package:adguard_home_manager/functions/copy_clipboard.dart';
import 'package:adguard_home_manager/models/menu_option.dart';
import 'package:adguard_home_manager/providers/app_config_provider.dart';
import 'package:adguard_home_manager/functions/get_filtered_status.dart';
import 'package:adguard_home_manager/models/logs.dart';
import 'package:adguard_home_manager/functions/format_time.dart';
import 'package:adguard_home_manager/services/host_rule_diagnostics.dart';
import 'package:adguard_home_manager/services/manual_rule_provenance_service.dart';

class LogTile extends StatelessWidget {
  final Log log;
  final Map<int, String> filterNames;
  final Map<int, String> whitelistNames;

  const LogTile({
    super.key,
    required this.log,
    this.filterNames = const {},
    this.whitelistNames = const {},
  });

  @override
  Widget build(BuildContext context) {
    final appConfigProvider =
        Provider.of<AppConfigProvider>(context, listen: false);
    final statusProvider = Provider.of<StatusProvider>(context, listen: false);
    final l10n = AppLocalizations.of(context)!;
    final colorScheme = Theme.of(context).colorScheme;

    final filter =
        getFilteredStatus(context, appConfigProvider, log.reason, false);
    final domainBlocked = isDomainBlocked(log.reason);
    final isSniLog = BlockedEventAggregator.isSniEvent(log);

    final badgeColor = isSniLog ? Colors.purple : Colors.blue;
    final badgeLabel = isSniLog
        ? 'SNI'
        : (log.question.type.isNotEmpty ? log.question.type : 'DNS');
    final matchedRules = BlockedEventAggregator.extractRulesFromLog(
      log,
      filterNames: filterNames,
      whitelistNames: whitelistNames,
    );
    final ruleHint =
        matchedRules.isNotEmpty ? matchedRules.first.text : '';
    String? elapsedText;
    if (log.elapsedMs.isNotEmpty) {
      final parsed = double.tryParse(log.elapsedMs);
      if (parsed != null) {
        elapsedText =
            '${parsed < 10 ? parsed.toStringAsFixed(1) : parsed.toStringAsFixed(0)} ms';
      }
    }

    String? serverKey;
    try {
      serverKey = ManualRuleProvenanceService.serverKeyForNullable(
        Provider.of<ServersProvider>(context, listen: false).selectedServer,
      );
    } catch (_) {
      serverKey = null;
    }

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

    final domain = log.question.name;
    final menuOptions = <MenuOption>[
      if (domain != null)
        MenuOption(
          title: domainBlocked ? l10n.unblockDomain : l10n.blockDomain,
          icon: domainBlocked ? Icons.check_rounded : Icons.block_rounded,
          action: () => blockUnblock(
            domain: domain,
            newStatus: domainBlocked ? 'unblock' : 'block',
          ),
        ),
      if (domain != null)
        MenuOption(
          title: l10n.copyClipboard,
          icon: Icons.copy_rounded,
          action: () => copyToClipboard(
            value: domain,
            successMessage: l10n.copiedClipboard,
          ),
        ),
    ];

    return Material(
      color: Colors.transparent,
      child: OptionsMenu(
        options: (_) => menuOptions,
        onTap: (_) {
          if (domain == null) return;
          showDialog(
            context: context,
            builder: (ctx) => AlertDialog(
              title: Text(
                domain,
                style: const TextStyle(fontSize: 16),
              ),
              content: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('状态: ${filter['label']} (${log.reason})'),
                  if (log.predictedBlocked) ...[
                    const SizedBox(height: 4),
                    const Text(
                      '规则预测: 规则命中阻断，但因保护暂停实际已放行',
                      style: TextStyle(fontSize: 12, color: Colors.orange),
                    ),
                  ],
                  if (matchedRules.isNotEmpty) ...[
                    const SizedBox(height: 8),
                    for (final mr in matchedRules) ...[
                      Padding(
                        padding: const EdgeInsets.only(top: 4),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            RuleProvenanceBadge(
                              compact: true,
                              display: ManualRuleProvenanceService.instance
                                  .resolveMatchedRuleDisplay(
                                serverKey: serverKey,
                                ruleText: mr.text,
                                filterListId: mr.filterListId,
                                subscriptionDisplayName: mr.sourceName,
                              ),
                            ),
                            const SizedBox(height: 2),
                            Text(
                              mr.text,
                              style: const TextStyle(
                                fontFamily: 'monospace',
                                fontSize: 12.5,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ],
                ],
              ),
              actions: [
                TextButton(
                  onPressed: () {
                    Navigator.pop(ctx);
                    copyToClipboard(
                      value: domain,
                      successMessage: l10n.copiedClipboard,
                    );
                  },
                  child: Text(l10n.copyClipboard),
                ),
                FilledButton.icon(
                  onPressed: () {
                    Navigator.pop(ctx);
                    blockUnblock(
                      domain: domain,
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
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      domain ?? 'N/A',
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
                              badgeLabel,
                              style: TextStyle(
                                fontSize: 10.5,
                                fontWeight: FontWeight.bold,
                                color: badgeColor,
                              ),
                            ),
                          ),
                          const SizedBox(width: 8),
                          Flexible(
                            child: Text(
                              convertTimestampLocalTimezone(log.time, 'HH:mm:ss'),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: TextStyle(
                                color: colorScheme.onSurfaceVariant,
                                fontSize: 12,
                              ),
                            ),
                          ),
                          if (elapsedText != null) ...[
                            const SizedBox(width: 8),
                            Flexible(
                              child: Text(
                                '· $elapsedText',
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: TextStyle(
                                  color: colorScheme.onSurfaceVariant,
                                  fontSize: 12,
                                ),
                              ),
                            ),
                          ],
                          if (ruleHint.isNotEmpty) ...[
                            const SizedBox(width: 8),
                            Expanded(
                              child: Text(
                                '· $ruleHint',
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: TextStyle(
                                  color: colorScheme.onSurfaceVariant,
                                  fontSize: 12,
                                ),
                              ),
                            ),
                          ],
                        ],
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 10),
              LogStatusIndicator(
                reason: log.reason,
                showExpandArrow: false,
              ),
            ],
          ),
        ),
      ),
    );
  }
}
