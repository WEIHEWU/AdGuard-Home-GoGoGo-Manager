import 'package:flutter/material.dart';

import 'package:adguard_home_manager/services/manual_rule_provenance_service.dart';

/// 通用规则来源徽章组件，统一呈现手动放行 / 手动拦截 / 手动规则 / 用户认领 / 订阅名 / 来源未记录 / 未确认。
class RuleProvenanceBadge extends StatelessWidget {
  final RuleSourceDisplay display;
  final bool compact;

  const RuleProvenanceBadge({
    super.key,
    required this.display,
    this.compact = false,
  });

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final (bg, fg, icon) = _resolveColors(cs);

    final badge = Container(
      padding: EdgeInsets.symmetric(
        horizontal: compact ? 6 : 8,
        vertical: compact ? 2 : 3,
      ),
      decoration: BoxDecoration(
        color: bg,
        borderRadius: BorderRadius.circular(compact ? 4 : 6),
        border: Border.all(color: fg.withValues(alpha: 0.25), width: 0.7),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: compact ? 11 : 12.5, color: fg),
          const SizedBox(width: 4),
          Flexible(
            child: Text(
              display.label,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                fontSize: compact ? 10.5 : 11,
                fontWeight: FontWeight.w600,
                color: fg,
                height: 1.2,
              ),
            ),
          ),
        ],
      ),
    );

    if (display.secondaryHint == null || display.secondaryHint!.trim().isEmpty) {
      return badge;
    }

    return Wrap(
      spacing: 6,
      runSpacing: 4,
      crossAxisAlignment: WrapCrossAlignment.center,
      children: [
        badge,
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
          decoration: BoxDecoration(
            color: cs.secondaryContainer.withValues(alpha: 0.65),
            borderRadius: BorderRadius.circular(4),
          ),
          child: Text(
            display.secondaryHint!,
            style: TextStyle(
              fontSize: compact ? 10 : 10.5,
              color: cs.onSecondaryContainer,
              fontWeight: FontWeight.w500,
            ),
          ),
        ),
      ],
    );
  }

  (Color bg, Color fg, IconData icon) _resolveColors(ColorScheme cs) {
    if (display.isUnconfirmedOrAmbiguous) {
      return (
        Colors.amber.withValues(alpha: 0.16),
        Colors.amber.shade900,
        Icons.help_outline_rounded,
      );
    }
    if (display.isUnrecordedCustom) {
      return (
        cs.surfaceContainerHighest.withValues(alpha: 0.8),
        cs.onSurfaceVariant,
        Icons.edit_note_rounded,
      );
    }
    if (display.isSubscriptionOrigin) {
      return (
        cs.primaryContainer.withValues(alpha: 0.5),
        cs.primary,
        Icons.list_alt_rounded,
      );
    }
    if (display.isClaimedOrigin) {
      return (
        Colors.deepPurple.withValues(alpha: 0.12),
        Colors.deepPurple.shade700,
        Icons.bookmark_added_rounded,
      );
    }
    final action = display.record?.action;
    if (action == ManualRuleAction.allow) {
      return (
        Colors.teal.withValues(alpha: 0.14),
        Colors.teal.shade800,
        Icons.verified_user_rounded,
      );
    }
    if (action == ManualRuleAction.block) {
      return (
        Colors.red.withValues(alpha: 0.12),
        Colors.red.shade800,
        Icons.block_rounded,
      );
    }
    return (
      Colors.indigo.withValues(alpha: 0.12),
      Colors.indigo.shade700,
      Icons.tune_rounded,
    );
  }
}

/// 统一格式化来源管理界面的时间显示（YYYY-MM-DD HH:mm）。
String formatManualRuleTimestamp(DateTime? dt) {
  if (dt == null) return '未知（认领规则无历史创建记录）';
  final local = dt.toLocal();
  String two(int n) => n.toString().padLeft(2, '0');
  return '${local.year}-${two(local.month)}-${two(local.day)} '
      '${two(local.hour)}:${two(local.minute)}';
}
