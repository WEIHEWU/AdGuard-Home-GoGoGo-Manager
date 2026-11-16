import 'package:flutter/material.dart';

import 'package:adguard_home_manager/functions/format_time.dart';
import 'package:adguard_home_manager/services/host_rule_diagnostics.dart';

/// 置顶实时规则检测卡片（与历史事件严格分离，不受日志刷屏挤出视野）。
class LiveRuleDiagnosticCard extends StatelessWidget {
  final String rawQuery;
  final String? parseError;
  final bool checking;
  final HostFamilyCheckReport? report;
  final Map<String, ExceptionWriteOutcome> outcomesByRule;
  final bool writeBusy;
  final Future<void> Function(String rule, {required bool confirmBroad}) onApplyException;
  final Future<void> Function(String addedRule) onUndoException;

  const LiveRuleDiagnosticCard({
    super.key,
    required this.rawQuery,
    this.parseError,
    required this.checking,
    this.report,
    required this.outcomesByRule,
    required this.writeBusy,
    required this.onApplyException,
    required this.onUndoException,
  });

  static Color statusColor(RuleCheckStatus status) {
    switch (status) {
      case RuleCheckStatus.blocked:
        return Colors.red;
      case RuleCheckStatus.whitelisted:
        return Colors.green;
      case RuleCheckStatus.rewritten:
        return Colors.blue;
      case RuleCheckStatus.notBlocked:
        return Colors.teal;
      case RuleCheckStatus.unsupported:
      case RuleCheckStatus.unknown:
      case RuleCheckStatus.failed:
        return Colors.orange.shade800;
    }
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    if (parseError != null) {
      return Card(
        margin: const EdgeInsets.fromLTRB(12, 8, 12, 6),
        color: colorScheme.errorContainer.withValues(alpha: 0.35),
        elevation: 0,
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Row(
            children: [
              Icon(Icons.warning_amber_rounded,
                  size: 18, color: colorScheme.error),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  parseError!,
                  style: TextStyle(fontSize: 12.5, color: colorScheme.error),
                ),
              ),
            ],
          ),
        ),
      );
    }

    if (checking && report == null) {
      return const Padding(
        padding: EdgeInsets.fromLTRB(16, 10, 16, 6),
        child: Row(
          children: [
            SizedBox(
              width: 16,
              height: 16,
              child: CircularProgressIndicator(strokeWidth: 2),
            ),
            SizedBox(width: 10),
            Expanded(
              child: Text(
                '正在实时检测原域名与可注册父域名规则命中…',
                style: TextStyle(fontSize: 12.5),
              ),
            ),
          ],
        ),
      );
    }

    final rep = report;
    if (rep == null) return const SizedBox.shrink();

    final orig = rep.effectiveOriginal;
    final stColor = statusColor(orig.status);
    final suggestion = orig.isBlocked
        ? WhitelistPlanner.buildSuggestion(
            originalHost: orig.host,
            matchedRules: orig.rules,
          )
        : null;

    return Card(
      margin: const EdgeInsets.fromLTRB(12, 8, 12, 6),
      elevation: 0,
      color: colorScheme.surfaceContainerLow,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(14),
        side: BorderSide(color: stColor.withValues(alpha: 0.35)),
      ),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(
                    color: stColor.withValues(alpha: 0.14),
                    borderRadius: BorderRadius.circular(6),
                  ),
                  child: Text(
                    orig.statusLabel,
                    style: TextStyle(
                      fontSize: 11,
                      fontWeight: FontWeight.bold,
                      color: stColor,
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    '实时规则检测：${orig.host}',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(
                      fontSize: 13.5,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
                if (checking)
                  const SizedBox(
                    width: 14,
                    height: 14,
                    child: CircularProgressIndicator(strokeWidth: 1.8),
                  ),
              ],
            ),
            if (rep.parsedInput.unicodeHost != null) ...[
              const SizedBox(height: 2),
              Text(
                '原始国际化域名: ${rep.parsedInput.unicodeHost}',
                style: TextStyle(
                  fontSize: 11,
                  color: colorScheme.onSurfaceVariant,
                ),
              ),
            ],
            if (orig.secondaryQtypeNote != null) ...[
              const SizedBox(height: 3),
              Text(
                '记录类型差异: ${orig.secondaryQtypeNote}',
                style: TextStyle(
                  fontSize: 11.5,
                  color: Colors.amber.shade900,
                ),
              ),
            ],
            const SizedBox(height: 4),
            Text(
              '仅表示当前核心规则匹配状态，不代表已证实历史 TLS 连接被 SNI 阻断（历史证据见下方「历史事件」）。',
              style: TextStyle(
                fontSize: 11,
                color: colorScheme.onSurfaceVariant,
              ),
            ),
            if (orig.rules.isNotEmpty) ...[
              const SizedBox(height: 8),
              for (final r in orig.rules)
                Padding(
                  padding: const EdgeInsets.only(bottom: 3),
                  child: Text(
                    '· [${r.sourceName}] ${r.text}',
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 11.5,
                    ),
                  ),
                ),
            ],
            if (suggestion != null) ...[
              const Divider(height: 14),
              TwoLevelWhitelistControls(
                suggestion: suggestion,
                outcomesByRule: outcomesByRule,
                writeBusy: writeBusy,
                onApplyException: onApplyException,
                onUndoException: onUndoException,
              ),
            ],
            if (rep.parentResults.isNotEmpty) ...[
              const Divider(height: 14),
              Text(
                '辅助检查（父域名规则命中，不替代原域名结论）：',
                style: TextStyle(
                  fontSize: 11.5,
                  fontWeight: FontWeight.w600,
                  color: colorScheme.onSurfaceVariant,
                ),
              ),
              const SizedBox(height: 4),
              for (final p in rep.parentResults)
                Padding(
                  padding: const EdgeInsets.only(bottom: 3),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 5, vertical: 1),
                        decoration: BoxDecoration(
                          color: statusColor(p.status).withValues(alpha: 0.12),
                          borderRadius: BorderRadius.circular(4),
                        ),
                        child: Text(
                          p.statusLabel,
                          style: TextStyle(
                            fontSize: 10,
                            fontWeight: FontWeight.bold,
                            color: statusColor(p.status),
                          ),
                        ),
                      ),
                      const SizedBox(width: 6),
                      Expanded(
                        child: Text(
                          p.rules.isNotEmpty
                              ? '${p.host} · [${p.rules.first.sourceName}] ${p.rules.first.text}'
                              : p.host,
                          style: const TextStyle(fontSize: 11.5),
                        ),
                      ),
                    ],
                  ),
                ),
            ],
          ],
        ),
      ),
    );
  }
}

/// 两级安全放行控件：区分“放行此子域名（含下级）”与“放行命中规则域名（需二次确认）”，展示写后核验与撤销。
class TwoLevelWhitelistControls extends StatelessWidget {
  final WhitelistSuggestion suggestion;
  final Map<String, ExceptionWriteOutcome> outcomesByRule;
  final bool writeBusy;
  final Future<void> Function(String rule, {required bool confirmBroad}) onApplyException;
  final Future<void> Function(String addedRule) onUndoException;

  const TwoLevelWhitelistControls({
    super.key,
    required this.suggestion,
    required this.outcomesByRule,
    required this.writeBusy,
    required this.onApplyException,
    required this.onUndoException,
  });

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final narrowRule = suggestion.narrowRule;
    final broadRule = suggestion.broadRule;
    final narrowOutcome =
        narrowRule != null ? outcomesByRule[narrowRule] : null;
    final broadOutcome = broadRule != null ? outcomesByRule[broadRule] : null;

    final impNarrowRule =
        narrowRule != null ? '$narrowRule\$important' : null;
    final impBroadRule = broadRule != null ? '$broadRule\$important' : null;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (narrowRule != null) ...[
          Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      '按钮 A · 放行此子域名：$narrowRule',
                      style: const TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    Text(
                      suggestion.narrowDescription,
                      style: TextStyle(
                        fontSize: 11,
                        color: colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 8),
              FilledButton.tonal(
                onPressed: writeBusy || narrowOutcome?.verifiedUnblocked == true
                    ? null
                    : () => onApplyException(narrowRule, confirmBroad: false),
                style: FilledButton.styleFrom(
                  visualDensity: VisualDensity.compact,
                ),
                child: Text(
                  narrowOutcome?.verifiedUnblocked == true ? '已生效' : '放行子域名',
                  style: const TextStyle(fontSize: 11.5),
                ),
              ),
            ],
          ),
          if (narrowOutcome != null)
            _OutcomeStatusRow(
              outcome: narrowOutcome,
              importantRule: impNarrowRule,
              writeBusy: writeBusy,
              onApplyImportant: (r) => onApplyException(r, confirmBroad: true),
              onUndo: onUndoException,
            ),
        ],
        const SizedBox(height: 8),
        if (broadRule != null) ...[
          Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      '按钮 B · 放行命中规则域名：$broadRule',
                      style: const TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    if (suggestion.broadDescription != null)
                      Text(
                        suggestion.broadDescription!,
                        style: TextStyle(
                          fontSize: 11,
                          color: Colors.orange.shade900,
                        ),
                      ),
                  ],
                ),
              ),
              const SizedBox(width: 8),
              OutlinedButton(
                onPressed: writeBusy || broadOutcome?.verifiedUnblocked == true
                    ? null
                    : () => onApplyException(broadRule, confirmBroad: true),
                style: OutlinedButton.styleFrom(
                  visualDensity: VisualDensity.compact,
                ),
                child: Text(
                  broadOutcome?.verifiedUnblocked == true ? '已生效' : '放行规则域名',
                  style: const TextStyle(fontSize: 11.5),
                ),
              ),
            ],
          ),
          if (broadOutcome != null)
            _OutcomeStatusRow(
              outcome: broadOutcome,
              importantRule: impBroadRule,
              writeBusy: writeBusy,
              onApplyImportant: (r) => onApplyException(r, confirmBroad: true),
              onUndo: onUndoException,
            ),
        ] else if (suggestion.broadDisabledReason != null) ...[
          Text(
            '宽范围按钮已禁用：${suggestion.broadDisabledReason}',
            style: TextStyle(
              fontSize: 11,
              color: colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ],
    );
  }
}

class _OutcomeStatusRow extends StatelessWidget {
  final ExceptionWriteOutcome outcome;
  final String? importantRule;
  final bool writeBusy;
  final Future<void> Function(String rule) onApplyImportant;
  final Future<void> Function(String rule) onUndo;

  const _OutcomeStatusRow({
    required this.outcome,
    required this.importantRule,
    required this.writeBusy,
    required this.onApplyImportant,
    required this.onUndo,
  });

  @override
  Widget build(BuildContext context) {
    final fullSuccess = outcome.verifiedUnblocked && !outcome.cacheFlushFailed;
    final color = fullSuccess
        ? Colors.green.shade800
        : ((outcome.verifiedUnblocked ||
                outcome.verificationIncomplete ||
                outcome.stillBlockedByImportant ||
                outcome.conflictDetected)
            ? Colors.orange.shade900
            : Colors.red.shade700);
    return Padding(
      padding: const EdgeInsets.only(top: 4),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            outcome.message,
            style: TextStyle(fontSize: 11, color: color),
          ),
          const SizedBox(height: 2),
          Wrap(
            spacing: 8,
            children: [
              if (outcome.addedRule != null && outcome.undoToken != null)
                TextButton(
                  onPressed: writeBusy ? null : () => onUndo(outcome.addedRule!),
                  style: TextButton.styleFrom(
                    visualDensity: VisualDensity.compact,
                    padding: const EdgeInsets.symmetric(horizontal: 8),
                  ),
                  child: Text('撤销 (${outcome.addedRule})',
                      style: const TextStyle(fontSize: 11)),
                ),
              if (outcome.stillBlockedByImportant && importantRule != null)
                TextButton(
                  onPressed:
                      writeBusy ? null : () => onApplyImportant(importantRule!),
                  style: TextButton.styleFrom(
                    visualDensity: VisualDensity.compact,
                    padding: const EdgeInsets.symmetric(horizontal: 8),
                    foregroundColor: Colors.deepOrange,
                  ),
                  child: const Text('确认添加 \$important 例外',
                      style: TextStyle(fontSize: 11)),
                ),
            ],
          ),
        ],
      ),
    );
  }
}

/// 弹窗展示可展开的聚合历史阻断条目及其原始事件时间戳，并提供两级加白入口。
Future<void> showAggregatedGroupDetailDialog(
  BuildContext context, {
  required AggregatedLogGroup group,
  required Future<void> Function(String rule, {required bool confirmBroad})
      onApplyException,
}) {
  final protoLabel = group.isSni ? 'SNI' : 'DNS';
  final suggestion = WhitelistPlanner.buildSuggestion(
    originalHost: group.domain,
    matchedRules: group.matchedRules,
  );
  return showDialog<void>(
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
              Text(
                '协议: $protoLabel · reason=${group.reason} · 次数=${group.count}',
                style: const TextStyle(fontSize: 12.5),
              ),
              if (group.isFromCoreSummary)
                const Text(
                  '来源: 核心近期阻断摘要（内存有限保留，超出容量/5分钟仍会淘汰）',
                  style: TextStyle(fontSize: 11.5, color: Colors.teal),
                ),
              if (group.matchedRules.isNotEmpty) ...[
                const SizedBox(height: 8),
                const Text('命中规则与来源:',
                    style: TextStyle(fontWeight: FontWeight.w600, fontSize: 12.5)),
                for (final r in group.matchedRules)
                  Padding(
                    padding: const EdgeInsets.only(top: 2),
                    child: Text(
                      '[${r.sourceName}] ${r.text}',
                      style: const TextStyle(fontFamily: 'monospace', fontSize: 11.5),
                    ),
                  ),
              ],
              const SizedBox(height: 10),
              const Text('原始记录时间:',
                  style: TextStyle(fontWeight: FontWeight.w600, fontSize: 12.5)),
              for (final raw in group.rawEvents.take(15))
                Padding(
                  padding: const EdgeInsets.only(top: 2),
                  child: Text(
                    '${convertTimestampLocalTimezone(raw.time, "HH:mm:ss")} · client=${raw.client}${raw.destination?.isNotEmpty == true ? " · dst=${raw.destination}" : ""}',
                    style: const TextStyle(fontSize: 11.5),
                  ),
                ),
              if (suggestion.narrowRule != null) ...[
                const Divider(height: 16),
                Text(
                  suggestion.narrowDescription,
                  style: const TextStyle(fontSize: 11.5),
                ),
              ],
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(ctx),
          child: const Text('关闭'),
        ),
        if (suggestion.narrowRule != null)
          FilledButton.tonal(
            onPressed: () async {
              Navigator.pop(ctx);
              await onApplyException(suggestion.narrowRule!, confirmBroad: false);
            },
            child: const Text('放行此子域名'),
          ),
        if (suggestion.broadRule != null)
          OutlinedButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await onApplyException(suggestion.broadRule!, confirmBroad: true);
            },
            child: const Text('放行规则域名'),
          ),
      ],
    ),
  );
}
