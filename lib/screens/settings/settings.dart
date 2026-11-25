import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:adguard_home_manager/l10n/app_localizations.dart';

import 'package:adguard_home_manager/screens/settings/dns/dns.dart';
import 'package:adguard_home_manager/screens/settings/module/app_allowlist_modal.dart';
import 'package:adguard_home_manager/widgets/section_label.dart';
import 'package:adguard_home_manager/widgets/custom_list_tile.dart';
import 'package:adguard_home_manager/functions/snackbar.dart';
import 'package:adguard_home_manager/widgets/module_diagnostics_sheet.dart';
import 'package:adguard_home_manager/providers/filtering_provider.dart';
import 'package:adguard_home_manager/providers/status_provider.dart';
import 'package:adguard_home_manager/providers/servers_provider.dart';
import 'package:adguard_home_manager/providers/app_config_provider.dart';
import 'package:adguard_home_manager/services/module_config_service.dart';

class Settings extends StatefulWidget {
  const Settings({super.key});

  @override
  State<Settings> createState() => _SettingsWidgetState();
}

class _SettingsWidgetState extends State<Settings> {
  final _proxyUrlController = TextEditingController();

  bool _proxyUrlLoading = true;
  bool _proxyUrlSaving = false;
  bool _diagLoading = true;
  bool _cleaningAdCache = false;
  bool _restoringRules = false;
  Map<String, dynamic> _diag = {
    'running': false,
    'pid': '',
    'dnsPort': '',
    'natOk': false,
    'sniEnabled': true,
    'sniOk': false,
    'vpnMode': 'off',
    'rssMb': '',
    'allowlistCount': 0,
  };

  @override
  void initState() {
    super.initState();
    _loadProxyUrl();
    _loadDiagnostics();
  }

  @override
  void dispose() {
    _proxyUrlController.dispose();
    super.dispose();
  }

  Future<void> _loadProxyUrl() async {
    final url = await ModuleConfigService().readProxyUrl();
    if (!mounted) return;
    setState(() {
      _proxyUrlController.text = url;
      _proxyUrlLoading = false;
    });
  }

  Future<void> _loadDiagnostics({bool forceRefresh = false}) async {
    final diag = await ModuleConfigService()
        .getModuleDiagnostics(forceRefresh: forceRefresh);
    if (!mounted) return;
    setState(() {
      _diag = diag;
      _diagLoading = false;
    });
  }

  String _buildDiagSummary(String moduleAddr, bool isZh) {
    if (_diagLoading) return isZh ? '正在检测…' : 'Checking status…';
    final running = _diag['running'] == true;
    final natOk = _diag['natOk'] == true;
    final sniEnabled = _diag['sniEnabled'] == true;
    final sniOk = !sniEnabled || (_diag['sniOk'] == true);
    final vpnMode = (_diag['vpnMode'] ?? 'off').toString();
    final rssMb = (_diag['rssMb'] ?? '').toString();
    final addrSuffix = moduleAddr.isNotEmpty ? ' · $moduleAddr' : '';
    if (!running) {
      return isZh
          ? '未运行（点击查看日志或修复）$addrSuffix'
          : 'Stopped (tap to view logs or fix)$addrSuffix';
    }
    var vpnText = '';
    if (vpnMode == 'takeover') {
      vpnText = isZh ? ' · VPN 接管去广告' : ' · VPN DNS Takeover';
    } else if (vpnMode == 'bypass') {
      vpnText = isZh ? ' · VPN 兼容防环路' : ' · VPN Loop-Safe';
    }
    final memText = rssMb.isNotEmpty ? ' · $rssMb' : '';
    if (natOk && sniOk) {
      if (sniEnabled) {
        return isZh
            ? '运行中 · DNS + SNI 双链生效$memText$vpnText$addrSuffix'
            : 'Running · DNS + SNI Active$memText$vpnText$addrSuffix';
      }
      return isZh
          ? '运行中 · 转发正常$memText$vpnText$addrSuffix'
          : 'Running · Forwarding OK$memText$vpnText$addrSuffix';
    }
    final issues = <String>[
      if (!natOk) isZh ? 'DNS 未接管' : 'DNS NAT off',
      if (sniEnabled && !sniOk) isZh ? 'SNI 未生效' : 'SNI filter off',
    ].join(' / ');
    return isZh
        ? '运行中 · $issues$memText$vpnText$addrSuffix'
        : 'Running · $issues$memText$vpnText$addrSuffix';
  }

  Future<void> _showLogsAndDiagModal(bool isZh) async {
    final service = ModuleConfigService();
    final appConfigProvider =
        Provider.of<AppConfigProvider>(context, listen: false);
    final results = await Future.wait([
      service.readModuleLogs(maxLines: 150),
      service.readDebugLogConfig(),
      _loadDiagnostics(forceRefresh: true),
    ]);
    String logs = results[0] as String;
    DebugLogConfig debugCfg = results[1] as DebugLogConfig;
    if (!mounted) return;

    showDialog(
      context: context,
      barrierColor: Colors.black.withValues(alpha: 0.5),
      builder: (ctx) {
        bool reloading = false;
        bool togglingDebug = false;
        int selectedDurationMin = DebugLogConfig.defaultDurationMinutes;
        return StatefulBuilder(
          builder: (ctx, setModalState) {
            final now = DateTime.now();
            final debugActive = debugCfg.isActiveAt(now);
            final remMin = debugCfg.remainingMinutesAt(now);
            return AlertDialog(
              title: Text(isZh ? '模块自检与运行日志' : 'Module Diagnostics & Logs'),
              content: SizedBox(
                width: 520,
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      _buildDiagSummary(
                          appConfigProvider.moduleHttpAddress, isZh),
                      style: TextStyle(
                        fontSize: 13,
                        fontWeight: FontWeight.w600,
                        color: (_diag['running'] == true &&
                                _diag['natOk'] == true &&
                                (!(_diag['sniEnabled'] == true) ||
                                    _diag['sniOk'] == true))
                            ? Colors.green
                            : Colors.orange,
                      ),
                    ),
                    const SizedBox(height: 10),
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.symmetric(
                        horizontal: 10,
                        vertical: 8,
                      ),
                      decoration: BoxDecoration(
                        color: Theme.of(ctx)
                            .colorScheme
                            .surfaceContainerHighest
                            .withValues(alpha: 0.45),
                        borderRadius: BorderRadius.circular(10),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Expanded(
                                child: Text(
                                  isZh ? '详细调试日志' : 'Detailed Debug Log',
                                  style: const TextStyle(
                                    fontSize: 13.5,
                                    fontWeight: FontWeight.w600,
                                  ),
                                ),
                              ),
                              if (!debugActive)
                                DropdownButton<int>(
                                  value: selectedDurationMin,
                                  isDense: true,
                                  underline: const SizedBox.shrink(),
                                  items: DebugLogConfig
                                      .selectableDurationsMinutes
                                      .map(
                                        (m) => DropdownMenuItem<int>(
                                          value: m,
                                          child: Text(
                                            isZh ? '$m 分钟' : '${m}m',
                                            style:
                                                const TextStyle(fontSize: 12),
                                          ),
                                        ),
                                      )
                                      .toList(),
                                  onChanged: togglingDebug
                                      ? null
                                      : (val) {
                                          if (val != null) {
                                            setModalState(() =>
                                                selectedDurationMin = val);
                                          }
                                        },
                                ),
                              const SizedBox(width: 6),
                              Switch(
                                value: debugActive,
                                onChanged: togglingDebug
                                    ? null
                                    : (nextVal) async {
                                        setModalState(
                                            () => togglingDebug = true);
                                        final updated =
                                            await service.setDebugLogConfig(
                                          enabled: nextVal,
                                          durationMinutes: selectedDurationMin,
                                        );
                                        if (!ctx.mounted) return;
                                        setModalState(() {
                                          togglingDebug = false;
                                          if (updated != null) {
                                            debugCfg = updated;
                                          }
                                        });
                                        if (mounted) {
                                          showSnackbar(
                                            appConfigProvider:
                                                appConfigProvider,
                                            label: updated == null
                                                ? (isZh
                                                    ? '保存调试日志开关失败'
                                                    : 'Failed to save debug setting')
                                                : (nextVal
                                                    ? (isZh
                                                        ? '已开启详细调试日志（$selectedDurationMin 分钟后自动关闭，不影响核心/防火墙）'
                                                        : 'Debug logging enabled (${selectedDurationMin}m auto-off)')
                                                    : (isZh
                                                        ? '已关闭详细调试日志（重要错误仍保留记录）'
                                                        : 'Debug logging disabled')),
                                            color: updated == null
                                                ? Colors.red
                                                : Colors.green,
                                          );
                                        }
                                      },
                              ),
                            ],
                          ),
                          Text(
                            isZh
                                ? '临时记录操作阶段及错误信息，便于排查问题。不记录 DNS 查询历史。建议排查后关闭。'
                                : 'Temporarily records stage & error details. Never records DNS query history. Disable after troubleshooting.',
                            style: TextStyle(
                              fontSize: 11.5,
                              color: Theme.of(ctx)
                                  .colorScheme
                                  .onSurfaceVariant,
                            ),
                          ),
                          const SizedBox(height: 2),
                          Text(
                            debugActive
                                ? (isZh
                                    ? '当前已开启 · 约 $remMin 分钟后自动关闭 · 不影响 AdGuard Home 查询日志开关'
                                    : 'Active · auto-off in ~${remMin}m · independent from AGH query log')
                                : (isZh
                                    ? '仅控制模块脚本调试输出，不改变 AdGuard Home 查询日志开关。'
                                    : 'Module script debug only; does not alter AGH query log setting.'),
                            style: TextStyle(
                              fontSize: 11,
                              color: debugActive
                                  ? Colors.orange.shade700
                                  : Theme.of(ctx)
                                      .colorScheme
                                      .onSurfaceVariant,
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 10),
                    Container(
                      height: 230,
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
                        reverse: true,
                        child: SelectableText(
                          logs.isEmpty
                              ? (isZh
                                  ? '暂无日志记录（/data/adb/agh/agh.log 为空）'
                                  : 'No logs found (/data/adb/agh/agh.log is empty)')
                              : logs,
                          style: const TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 12,
                          ),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
              actions: [
                TextButton.icon(
                  onPressed: () {
                    showDiagnosticExportFlow(ctx, isZhOverride: isZh);
                  },
                  icon: const Icon(Icons.archive_outlined, size: 17),
                  label: Text(isZh ? '导出诊断包' : 'Export Bundle'),
                ),
                TextButton(
                  onPressed: reloading
                      ? null
                      : () async {
                          setModalState(() => reloading = true);
                          try {
                            final reloadRes =
                                await service.reloadFirewallRulesDetailed();
                            await Future.delayed(const Duration(seconds: 1));
                            await _loadDiagnostics(forceRefresh: true);
                            logs = await service.readModuleLogs(maxLines: 150);
                            if (ctx.mounted) {
                              setModalState(() => reloading = false);
                            }
                            if (mounted) {
                              if (reloadRes.unconfirmed) {
                                showSnackbar(
                                  appConfigProvider: appConfigProvider,
                                  label: isZh
                                      ? '执行结果未确认，已同步当前实际状态'
                                      : 'Result unconfirmed, status refreshed',
                                  color: Colors.orange,
                                );
                              } else {
                                final diagHealthy = _diag['running'] == true &&
                                    _diag['natOk'] == true &&
                                    (_diag['sniEnabled'] != true ||
                                        _diag['sniOk'] == true);
                                final ok = reloadRes.succeeded && diagHealthy;
                                showSnackbar(
                                  appConfigProvider: appConfigProvider,
                                  label: ok
                                      ? (isZh
                                          ? '已验证防火墙与守护规则重载生效'
                                          : 'Firewall & daemon rules reloaded and verified')
                                      : (isZh
                                          ? '重载失败（${reloadRes.stage}），请查看上方日志'
                                          : 'Reload failed (${reloadRes.stage}), check logs'),
                                  color: ok ? Colors.green : Colors.red,
                                );
                              }
                            }
                          } catch (_) {
                            if (ctx.mounted) {
                              setModalState(() => reloading = false);
                            }
                          }
                        },
                  child: Text(isZh ? '重载防火墙规则' : 'Reload Firewall'),
                ),
                TextButton(
                  onPressed: () async {
                    await service.clearModuleLogs();
                    logs = '';
                    setModalState(() {});
                  },
                  child: Text(isZh ? '清空日志' : 'Clear'),
                ),
                TextButton(
                  onPressed: () async {
                    final refreshed = await Future.wait([
                      service.readModuleLogs(maxLines: 150),
                      service.readDebugLogConfig(),
                      _loadDiagnostics(forceRefresh: true),
                    ]);
                    logs = refreshed[0] as String;
                    debugCfg = refreshed[1] as DebugLogConfig;
                    if (ctx.mounted) setModalState(() {});
                  },
                  child: Text(isZh ? '刷新' : 'Refresh'),
                ),
                FilledButton(
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

  Future<void> _openAppAllowlist() async {
    await showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      barrierColor: Colors.black.withValues(alpha: 0.5),
      builder: (ctx) => const AppAllowlistModal(),
    );
    if (mounted) {
      _loadDiagnostics(forceRefresh: true);
    }
  }

  Future<void> _showProxyUrlModal(bool isZh) async {
    final result = await showDialog<String>(
      context: context,
      barrierColor: Colors.black.withValues(alpha: 0.5),
      builder: (_) => _ProxyUrlEditDialog(
        initialValue: _proxyUrlController.text,
        isZh: isZh,
      ),
    );
    if (result == null || !mounted) return;
    _proxyUrlController.text = result;
    await _saveProxyUrl(isZh);
  }

  Future<void> _handleCleanAdCaches(bool isZh) async {
    if (_cleaningAdCache) return;
    final appConfigProvider =
        Provider.of<AppConfigProvider>(context, listen: false);
    setState(() => _cleaningAdCache = true);
    final ok = await ModuleConfigService().cleanAppAdCaches();
    if (!mounted) return;
    setState(() => _cleaningAdCache = false);
    showSnackbar(
      appConfigProvider: appConfigProvider,
      label: ok
          ? (isZh
              ? '已清理国内外应用开屏及广告 SDK 缓存'
              : 'Cleaned app splash & ad SDK caches')
          : (isZh ? '清理失败，请检查 Root 权限' : 'Clean failed, check Root access'),
      color: ok ? Colors.green : Colors.red,
    );
  }

  Future<void> _handleRestoreFactoryRules(bool isZh) async {
    if (_restoringRules) return;
    final mode = await showDialog<String>(
      context: context,
      barrierColor: Colors.black.withValues(alpha: 0.5),
      builder: (ctx) => AlertDialog(
        title: Text(isZh ? '恢复默认自定义规则' : 'Restore Default Rules'),
        content: Text(
          isZh
              ? '请选择恢复方式：\n\n'
                  '• 智能补全（推荐）：保留你自己手动添加的规则，仅补全被误删的模块默认防广告规则。\n'
                  '• 完全重置：清除所有手动改动的规则，完全恢复为模块出厂默认规则。'
              : 'Choose restore mode:\n\n'
                  '• Smart Merge (Recommended): Keep your custom rules and restore any missing default module rules.\n'
                  '• Full Reset: Replace all custom rules with the factory default rules.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: Text(isZh ? '取消' : 'Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.of(ctx).pop('reset'),
            child: Text(isZh ? '完全重置' : 'Full Reset'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop('merge'),
            child: Text(isZh ? '智能补全（推荐）' : 'Smart Merge'),
          ),
        ],
      ),
    );
    if (mode == null || !mounted) return;

    final appConfigProvider =
        Provider.of<AppConfigProvider>(context, listen: false);
    final serversProvider =
        Provider.of<ServersProvider>(context, listen: false);
    final filteringProvider =
        Provider.of<FilteringProvider>(context, listen: false);

    if (serversProvider.apiClient2 == null) {
      showSnackbar(
        appConfigProvider: appConfigProvider,
        label: isZh
            ? '未连接到本地 AdGuard Home 服务'
            : 'Not connected to local AdGuard Home service',
        color: Colors.red,
      );
      return;
    }

    setState(() => _restoringRules = true);
    final factoryRules = await ModuleConfigService().readFactoryUserRules();
    if (factoryRules.isEmpty) {
      if (!mounted) return;
      setState(() => _restoringRules = false);
      showSnackbar(
        appConfigProvider: appConfigProvider,
        label: isZh ? '未能读取到模块默认规则备份' : 'Factory rules backup not found',
        color: Colors.red,
      );
      return;
    }

    final mutRes = await filteringProvider.restoreFactoryUserRules(
      factoryRules: factoryRules,
      mergeExisting: mode == 'merge',
      deprecatedFactoryRules: ModuleConfigService.deprecatedFactoryRules,
    );
    if (!mounted) return;
    setState(() => _restoringRules = false);
    showSnackbar(
      appConfigProvider: appConfigProvider,
      label: mutRes.ok
          ? (mutRes.readbackFailed
              ? (mutRes.message ??
                  (isZh ? '已恢复默认规则（回读未确认）' : 'Default rules restored'))
              : (mode == 'merge'
                  ? (isZh ? '已智能补全模块默认自定义规则' : 'Default rules merged')
                  : (isZh ? '已完全重置为模块出厂默认规则' : 'Factory rules restored')))
          : (mutRes.message ??
              (isZh ? '恢复规则失败，请稍后重试' : 'Failed to restore rules')),
      color: mutRes.ok
          ? (mutRes.readbackFailed ? Colors.orange : Colors.green)
          : Colors.red,
    );
  }

  Future<void> _saveProxyUrl(bool isZh) async {
    final appConfigProvider =
        Provider.of<AppConfigProvider>(context, listen: false);
    final value = _proxyUrlController.text.trim();
    setState(() => _proxyUrlSaving = true);
    final ok = await ModuleConfigService().saveProxyUrl(value);
    if (!mounted) return;
    setState(() => _proxyUrlSaving = false);
    showSnackbar(
      appConfigProvider: appConfigProvider,
      label: ok
          ? (isZh ? '订阅链接已保存并立即生效' : 'Proxy URL saved and applied')
          : (isZh ? '保存失败，请检查 Root 权限' : 'Save failed, check Root access'),
      color: ok ? Colors.green : Colors.red,
    );
  }

  @override
  Widget build(BuildContext context) {
    final serversProvider = Provider.of<ServersProvider>(context);
    final statusProvider = Provider.of<StatusProvider>(context);
    final appConfigProvider = Provider.of<AppConfigProvider>(context);
    final l10n = AppLocalizations.of(context)!;
    final isZh = Localizations.localeOf(context).languageCode.startsWith('zh');
    final allowlistCount = (_diag['allowlistCount'] as int?) ?? 0;

    return Scaffold(
      appBar: AppBar(
        centerTitle: false,
        title: Text(l10n.settings),
      ),
      body: ListView(
        children: [
          SectionLabel(label: isZh ? '模块与核心' : 'Module & Core'),
          CustomListTile(
            icon: Icons.health_and_safety_rounded,
            title: isZh ? '模块运行状态与自检' : 'Module Status & Logs',
            subtitle:
                _buildDiagSummary(appConfigProvider.moduleHttpAddress, isZh),
            onTap: () => _showLogsAndDiagModal(isZh),
            trailing: const Icon(Icons.chevron_right_rounded),
          ),
          CustomListTile(
            icon: Icons.apps_rounded,
            title: isZh ? '分应用开关（应用白名单）' : 'Per-App Bypass (Allowlist)',
            subtitle: isZh
                ? (allowlistCount > 0
                    ? '已放行 $allowlistCount 个应用不走去广告过滤'
                    : '指定部分应用直接放行、不经过去广告过滤')
                : (allowlistCount > 0
                    ? '$allowlistCount apps bypassed'
                    : 'Bypass ad filtering for selected apps'),
            onTap: _openAppAllowlist,
            trailing: const Icon(Icons.chevron_right_rounded),
          ),
          CustomListTile(
            icon: Icons.vpn_key_rounded,
            title: isZh
                ? '代理订阅链接 (PROXY_URL)'
                : 'Proxy Subscription (PROXY_URL)',
            subtitle: _proxyUrlLoading
                ? (isZh ? '正在读取配置…' : 'Loading…')
                : (_proxyUrlController.text.trim().isEmpty
                    ? (isZh
                        ? '未启用（独立 VPN 自动兼容）'
                        : 'Disabled (Standalone VPN auto-compatible)')
                    : (isZh
                        ? '已配置: ${_proxyUrlController.text.trim()}'
                        : 'Configured: ${_proxyUrlController.text.trim()}')),
            onTap: _proxyUrlSaving ? null : () => _showProxyUrlModal(isZh),
            trailing: _proxyUrlSaving
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.chevron_right_rounded),
          ),
          CustomListTile(
            icon: Icons.cleaning_services_rounded,
            title: isZh ? '清理广告与 SDK 缓存' : 'Clean Ad & SDK Caches',
            subtitle: _cleaningAdCache
                ? (isZh ? '正在清理…' : 'Cleaning…')
                : (isZh
                    ? '清理国内外应用开屏与广告 SDK 离线缓存'
                    : 'Purge app splash & ad SDK offline caches'),
            onTap: _cleaningAdCache ? null : () => _handleCleanAdCaches(isZh),
            trailing: _cleaningAdCache
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.chevron_right_rounded),
          ),
          CustomListTile(
            icon: Icons.restore_rounded,
            title: isZh ? '恢复默认规则' : 'Restore Default Rules',
            subtitle: _restoringRules
                ? (isZh ? '正在恢复…' : 'Restoring…')
                : (isZh
                    ? '智能补全或重置模块预置规则'
                    : 'Smart merge or reset factory rules'),
            onTap:
                _restoringRules ? null : () => _handleRestoreFactoryRules(isZh),
            trailing: _restoringRules
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.chevron_right_rounded),
          ),
          if (serversProvider.selectedServer != null &&
              statusProvider.serverStatus != null &&
              serversProvider.apiClient2 != null) ...[
            SectionLabel(label: isZh ? 'DNS 参数' : 'DNS Configuration'),
            CustomListTile(
              icon: Icons.dns_rounded,
              title: l10n.dnsSettings,
              subtitle: l10n.dnsSettingsDescription,
              trailing: const Icon(Icons.chevron_right_rounded),
              onTap: () => Navigator.of(context).push(
                MaterialPageRoute(builder: (_) => const DnsSettings()),
              ),
            ),
          ],
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 20, horizontal: 16),
            child: Center(
              child: Text(
                'AdGuard Home GoGoGo v${AppConfigProvider.appVersion}',
                style: TextStyle(
                  fontSize: 12,
                  color: Theme.of(context)
                      .colorScheme
                      .onSurfaceVariant
                      .withValues(alpha: 0.6),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _ProxyUrlEditDialog extends StatefulWidget {
  final String initialValue;
  final bool isZh;

  const _ProxyUrlEditDialog({
    required this.initialValue,
    required this.isZh,
  });

  @override
  State<_ProxyUrlEditDialog> createState() => _ProxyUrlEditDialogState();
}

class _ProxyUrlEditDialogState extends State<_ProxyUrlEditDialog> {
  late final TextEditingController _controller;

  @override
  void initState() {
    super.initState();
    _controller = TextEditingController(text: widget.initialValue);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final isZh = widget.isZh;
    return AlertDialog(
      title: Text(isZh
          ? '代理订阅链接 (PROXY_URL)'
          : 'Proxy Subscription (PROXY_URL)'),
      content: SizedBox(
        width: 480,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            TextField(
              controller: _controller,
              autofocus: true,
              decoration: InputDecoration(
                hintText: isZh
                    ? '填写代理订阅链接，留空则关闭模块内置代理'
                    : 'Enter subscription URL (leave blank to disable)',
                suffixIcon: IconButton(
                  icon: const Icon(Icons.clear_rounded),
                  tooltip: isZh ? '清空' : 'Clear',
                  onPressed: () => _controller.clear(),
                ),
              ),
            ),
            const SizedBox(height: 10),
            Text(
              isZh
                  ? '• 平时使用独立 VPN 客户端（Clash / FlClash / v2rayNG 等）时无需填写，模块会自动识别并兼容。\n'
                      '• 填写或清空保存后立即生效，无需重启手机。'
                  : '• Leave blank if you use a standalone VPN app (Clash / FlClash / v2rayNG); the module automatically coexists with it.\n'
                      '• Changes take effect immediately upon saving.',
              style: TextStyle(
                fontSize: 12,
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: Text(isZh ? '取消' : 'Cancel'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(_controller.text.trim()),
          child: Text(isZh ? '保存并应用' : 'Save & Apply'),
        ),
      ],
    );
  }
}
