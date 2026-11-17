import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'package:adguard_home_manager/functions/get_filtered_status.dart';
import 'package:adguard_home_manager/providers/app_config_provider.dart';

/// 普通日志与聚合日志共用的右侧状态指示组件，内部复用 [getFilteredStatus]。
class LogStatusIndicator extends StatelessWidget {
  final String reason;
  final bool isRow;
  final bool showExpandArrow;
  final double statusMaxWidth;
  final AppConfigProvider? appConfigProvider;

  const LogStatusIndicator({
    super.key,
    required this.reason,
    this.isRow = false,
    this.showExpandArrow = false,
    this.statusMaxWidth = 84,
    this.appConfigProvider,
  });

  @override
  Widget build(BuildContext context) {
    final cfg = appConfigProvider ?? Provider.of<AppConfigProvider>(context);
    final filter = getFilteredStatus(context, cfg, reason, isRow);
    final color = filter['color'] as Color;
    final icon = filter['icon'] as IconData;
    final rawLabel = (filter['label'] ?? '').toString();
    final label = rawLabel.trim().isEmpty ? 'Unknown' : rawLabel;

    final statusColumn = ConstrainedBox(
      constraints: BoxConstraints(
        minWidth: 48,
        maxWidth: statusMaxWidth,
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            icon,
            color: color,
            size: 14,
          ),
          const SizedBox(height: 4),
          Text(
            label,
            textAlign: TextAlign.center,
            softWrap: true,
            style: TextStyle(
              color: color,
              fontSize: 11.5,
              height: 1.2,
            ),
          ),
        ],
      ),
    );

    if (!showExpandArrow) {
      return statusColumn;
    }

    return Row(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        statusColumn,
        const SizedBox(width: 4),
        Icon(
          Icons.expand_more_rounded,
          size: 18,
          color: Theme.of(context).colorScheme.onSurfaceVariant,
        ),
      ],
    );
  }
}
