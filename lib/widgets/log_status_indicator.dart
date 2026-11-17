import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'package:adguard_home_manager/functions/get_filtered_status.dart';
import 'package:adguard_home_manager/providers/app_config_provider.dart';

/// 普通日志与聚合日志共用的右侧状态指示组件，内部复用 [getFilteredStatus]。
///
/// 普通行与聚合行共享完全一致的 `[状态区] [固定间距] [箭头槽]` 结构：
/// 普通行保留等宽空箭头槽，确保同一屏幕与文字缩放下所有行的状态列中心垂直对齐。
class LogStatusIndicator extends StatelessWidget {
  static const Key statusAreaKey = ValueKey('log_status_indicator_status_area');
  static const Key arrowSlotKey = ValueKey('log_status_indicator_arrow_slot');
  static const double defaultStatusWidth = 76;
  static const double arrowSlotGap = 4;
  static const double arrowSlotWidth = 22;

  final String reason;
  final bool isRow;
  final bool showExpandArrow;
  final double? statusWidth;
  final AppConfigProvider? appConfigProvider;

  const LogStatusIndicator({
    super.key,
    required this.reason,
    this.isRow = false,
    this.showExpandArrow = false,
    this.statusWidth,
    this.appConfigProvider,
  });

  /// 基于当前视口宽度与文字缩放计算所有行共用的状态区宽度。
  static double resolveStatusWidth(BuildContext context) {
    final rawWidth = MediaQuery.sizeOf(context).width;
    final viewportWidth = rawWidth > 0 ? rawWidth : 360.0;
    final textScaleFactor =
        (MediaQuery.textScalerOf(context).scale(11.5) / 11.5).clamp(1.0, 2.0);
    final scaledWidth = defaultStatusWidth * textScaleFactor.clamp(1.0, 1.45);
    final maxAllowed = (viewportWidth * 0.34).clamp(64.0, 114.0);
    return scaledWidth.clamp(64.0, maxAllowed);
  }

  @override
  Widget build(BuildContext context) {
    final cfg = appConfigProvider ?? Provider.of<AppConfigProvider>(context);
    final filter = getFilteredStatus(context, cfg, reason, isRow);
    final color = filter['color'] as Color;
    final icon = filter['icon'] as IconData;
    final rawLabel = (filter['label'] ?? '').toString();
    final label = rawLabel.trim().isEmpty ? 'Unknown' : rawLabel;
    final resolvedStatusWidth = statusWidth ?? resolveStatusWidth(context);

    return Row(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        SizedBox(
          key: statusAreaKey,
          width: resolvedStatusWidth,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.center,
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
        ),
        const SizedBox(width: arrowSlotGap),
        SizedBox(
          key: arrowSlotKey,
          width: arrowSlotWidth,
          height: arrowSlotWidth,
          child: showExpandArrow
              ? Center(
                  child: Icon(
                    Icons.expand_more_rounded,
                    size: 18,
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                )
              : null,
        ),
      ],
    );
  }
}
