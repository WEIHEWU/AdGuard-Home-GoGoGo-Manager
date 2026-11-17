import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'package:adguard_home_manager/functions/get_filtered_status.dart';
import 'package:adguard_home_manager/providers/app_config_provider.dart';

/// 普通日志与聚合日志共用的紧凑右侧状态指示组件，内部复用 [getFilteredStatus]。
///
/// 普通行与聚合行共享完全一致的紧凑状态列宽与中心线，不保留独立箭头列或空占位：
/// - 状态图标 + 状态文字垂直居中排列；
/// - 当 [repeatCount] > 1 时，在状态文字下方显示次要颜色的 `×N`（较大数字采用紧凑形式）；
/// - 为读屏软件提供包含状态、重复次数与点按操作提示的完整无障碍语义。
class LogStatusIndicator extends StatelessWidget {
  static const Key statusAreaKey = ValueKey('log_status_indicator_status_area');
  static const Key repeatCountKey = ValueKey('log_status_indicator_repeat_count');
  static const double defaultStatusWidth = 68;

  final String reason;
  final bool isRow;
  final int repeatCount;
  final double? statusWidth;
  final AppConfigProvider? appConfigProvider;

  const LogStatusIndicator({
    super.key,
    required this.reason,
    this.isRow = false,
    this.repeatCount = 1,
    this.statusWidth,
    this.appConfigProvider,
  });

  /// 格式化重复次数：大数字使用紧凑格式，防止撑宽整列；详情弹窗保留精确次数。
  static String formatRepeatCount(int count) {
    if (count <= 1) return '';
    if (count >= 10000) {
      final k = count / 1000;
      return count % 1000 == 0
          ? '×${count ~/ 1000}k'
          : '×${k.toStringAsFixed(1)}k';
    }
    return '×$count';
  }

  /// 基于当前视口宽度与文字缩放计算所有行共用的紧凑状态区宽度（目标 ~64-72px，窄屏大字号受限适度自适应）。
  static double resolveStatusWidth(BuildContext context) {
    final rawWidth = MediaQuery.sizeOf(context).width;
    final viewportWidth = rawWidth > 0 ? rawWidth : 360.0;
    final textScaleFactor =
        (MediaQuery.textScalerOf(context).scale(11.5) / 11.5).clamp(1.0, 2.0);
    final scaledWidth = defaultStatusWidth * textScaleFactor.clamp(1.0, 1.35);
    final maxAllowed = (viewportWidth * 0.28).clamp(58.0, 92.0);
    return scaledWidth.clamp(58.0, maxAllowed);
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

    final isZh = Localizations.localeOf(context).languageCode == 'zh';
    final cleanLabel = label.replaceAll('\n', ' ');
    final String semanticLabel;
    if (isZh) {
      semanticLabel = repeatCount > 1
          ? '$cleanLabel，重复 $repeatCount 次，点按查看详情'
          : '$cleanLabel，点按查看详情';
    } else {
      semanticLabel = repeatCount > 1
          ? '$cleanLabel, repeated $repeatCount times, tap to view details'
          : '$cleanLabel, tap to view details';
    }

    return Semantics(
      label: semanticLabel,
      excludeSemantics: true,
      child: SizedBox(
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
            const SizedBox(height: 3),
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
            if (repeatCount > 1) ...[
              const SizedBox(height: 2),
              Text(
                formatRepeatCount(repeatCount),
                key: repeatCountKey,
                textAlign: TextAlign.center,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                  fontSize: 10.5,
                  fontWeight: FontWeight.w600,
                  height: 1.1,
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
