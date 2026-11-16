import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import 'package:adguard_home_manager/functions/snackbar.dart';
import 'package:adguard_home_manager/providers/app_config_provider.dart';
import 'package:adguard_home_manager/services/diagnostic_bundle_service.dart';

/// 导出诊断包交互流程：
/// 说明收集范围与隐私 -> 单飞生成（期间禁用防重入） -> 展示脱敏结果摘要/预览 -> 复制或通过系统面板分享
Future<void> showDiagnosticExportFlow(
  BuildContext context, {
  bool? isZhOverride,
  DiagnosticBundleService? bundleService,
}) async {
  final isZh = isZhOverride ??
      Localizations.localeOf(context).languageCode.startsWith('zh');
  final service = bundleService ?? DiagnosticBundleService();
  final appConfigProvider =
      Provider.of<AppConfigProvider>(context, listen: false);
  final cancelToken = DiagnosticCancelToken();

  final result = await showDialog<DiagnosticBundleResult>(
    context: context,
    barrierColor: Colors.black.withValues(alpha: 0.5),
    builder: (ctx) {
      var generating = DiagnosticBundleService.isExporting;
      String? errorText;

      return StatefulBuilder(
        builder: (ctx, setModalState) {
          return AlertDialog(
            title: Text(isZh ? '导出诊断包' : 'Export Diagnostic Bundle'),
            content: SizedBox(
              width: 500,
              child: SingleChildScrollView(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      isZh
                          ? '将仅按白名单收集以下只读诊断信息（耗时上限 20 秒，导出过程不获取操作锁、不修改规则、不重启核心）：'
                          : 'Collects read-only whitelist diagnostics (20s budget; never acquires operation locks or restarts core):',
                      style: const TextStyle(fontSize: 13),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      isZh
                          ? '• 模块运行日志（当前与上一份）及崩溃日志尾段（先脱敏）\n'
                              '• 运行模式、端口、SNI 开关与规则文件数量/SHA-256 摘要\n'
                              '• 锁诊断（含 lock_timeout 场景：诊断 PID 线索与模块锁 FD 摘要）\n'
                              '• 仅模块自有 iptables 链摘要与核心资源单次快照\n'
                              '• 管理器近期操作状态记录'
                          : '• Current & rotated module logs and crash log tail (redacted)\n'
                              '• Module state summary & filter count/SHA-256 digests only\n'
                              '• Lock diagnostics (non-blocking during lock_timeout)\n'
                              '• Module-owned firewall chain summary & resource snapshot\n'
                              '• Recent manager operation status records',
                      style: TextStyle(
                        fontSize: 12,
                        color: Theme.of(ctx).colorScheme.onSurfaceVariant,
                      ),
                    ),
                    const SizedBox(height: 10),
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(10),
                      decoration: BoxDecoration(
                        color: Theme.of(ctx)
                            .colorScheme
                            .surfaceContainerHighest
                            .withValues(alpha: 0.55),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Text(
                        isZh
                            ? '默认不收集：DNS 查询历史、完整 AdGuardHome.yaml、规则正文、已安装应用列表、完整系统进程表、完整 logcat/bugreport、第三方代理配置及原备份、环境变量、密码/Token/Cookie。'
                            : 'Excluded: DNS query history, full YAML, filter rule contents, app list, full ps/logcat/bugreport, proxy configs/backups, environ, passwords/tokens/cookies.',
                        style: const TextStyle(fontSize: 12),
                      ),
                    ),
                    if (generating) ...[
                      const SizedBox(height: 14),
                      const LinearProgressIndicator(),
                      const SizedBox(height: 6),
                      Text(
                        isZh
                            ? '正在采集并执行脱敏打包…'
                            : 'Collecting and redacting diagnostics…',
                        style: const TextStyle(fontSize: 12),
                      ),
                    ],
                    if (errorText != null) ...[
                      const SizedBox(height: 10),
                      Text(
                        errorText!,
                        style: TextStyle(
                          fontSize: 12,
                          color: Theme.of(ctx).colorScheme.error,
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ),
            actions: [
              TextButton(
                onPressed: () {
                  cancelToken.cancel();
                  Navigator.of(ctx).pop(null);
                },
                child: Text(isZh ? '取消' : 'Cancel'),
              ),
              FilledButton.icon(
                onPressed: generating
                    ? null
                    : () async {
                        setModalState(() {
                          generating = true;
                          errorText = null;
                        });
                        final res = await service.exportBundle(
                          cancelToken: cancelToken,
                        );
                        if (!ctx.mounted) return;
                        if (res.cancelled) {
                          Navigator.of(ctx).pop(null);
                          return;
                        }
                        if (!res.succeeded) {
                          setModalState(() {
                            generating = false;
                            errorText = res.errorMessage.isNotEmpty
                                ? res.errorMessage
                                : (isZh ? '生成诊断包失败' : 'Export failed');
                          });
                          return;
                        }
                        Navigator.of(ctx).pop(res);
                      },
                icon: const Icon(Icons.archive_outlined, size: 18),
                label: Text(
                  generating
                      ? (isZh ? '生成中…' : 'Generating…')
                      : (isZh ? '生成诊断包' : 'Generate'),
                ),
              ),
            ],
          );
        },
      );
    },
  );

  // 对话框被关闭或已取消时同步取消后续采集，且不在已销毁组件上弹窗
  cancelToken.cancel();
  if (result == null || !result.succeeded || !context.mounted) return;

  final sizeKb = (result.zipBytes / 1024).toStringAsFixed(1);
  await showDialog<void>(
    context: context,
    barrierColor: Colors.black.withValues(alpha: 0.5),
    builder: (ctx) {
      bool sharing = false;
      return StatefulBuilder(
        builder: (ctx, setPreviewState) {
          return AlertDialog(
            title: Text(
              result.partialSuccess
                  ? (isZh ? '部分诊断包已生成' : 'Partial Bundle Ready')
                  : (isZh ? '诊断包已生成' : 'Diagnostic Bundle Ready'),
            ),
            content: SizedBox(
              width: 520,
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    '${result.fileName} ($sizeKb KiB)',
                    style: const TextStyle(
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 6),
                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: Colors.amber.withValues(alpha: 0.14),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Text(
                      isZh
                          ? '已按默认规则脱敏，但仍请检查内容后再分享。'
                          : 'Redacted with default rules. Please review contents before sharing.',
                      style: const TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                  const SizedBox(height: 10),
                  Container(
                    height: 260,
                    width: double.maxFinite,
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: Theme.of(ctx)
                          .colorScheme
                          .surfaceContainerHighest
                          .withValues(alpha: 0.5),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: SingleChildScrollView(
                      child: SelectableText(
                        result.previewText,
                        style: const TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 11.5,
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),
            actions: [
              TextButton(
                onPressed: () async {
                  await Clipboard.setData(
                    ClipboardData(text: result.summaryText),
                  );
                  if (context.mounted) {
                    showSnackbar(
                      appConfigProvider: appConfigProvider,
                      label: isZh ? '已复制诊断摘要' : 'Summary copied',
                      color: Colors.green,
                    );
                  }
                },
                child: Text(isZh ? '复制摘要' : 'Copy Summary'),
              ),
              FilledButton.icon(
                onPressed: sharing
                    ? null
                    : () async {
                        setPreviewState(() => sharing = true);
                        await service.shareBundle(
                          result.zipPath,
                          title: isZh
                              ? '分享 AdGuard Home 诊断包'
                              : 'Share AdGuard Home Diagnostic Bundle',
                        );
                        if (ctx.mounted) {
                          setPreviewState(() => sharing = false);
                        }
                      },
                icon: const Icon(Icons.share_rounded, size: 18),
                label: Text(isZh ? '分享' : 'Share'),
              ),
              TextButton(
                onPressed: () => Navigator.of(ctx).pop(),
                child: Text(isZh ? '关闭' : 'Close'),
              ),
            ],
          );
        },
      );
    },
  );
}
