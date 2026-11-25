// ignore_for_file: use_build_context_synchronously

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import 'package:adguard_home_manager/functions/format_time.dart';
import 'package:adguard_home_manager/functions/snackbar.dart';
import 'package:adguard_home_manager/models/filtering.dart';
import 'package:adguard_home_manager/widgets/module_diagnostics_sheet.dart';
import 'package:adguard_home_manager/widgets/troubleshooter_rule_panel.dart';
import 'package:adguard_home_manager/models/logs.dart';
import 'package:adguard_home_manager/providers/app_config_provider.dart';
import 'package:adguard_home_manager/providers/dns_provider.dart';
import 'package:adguard_home_manager/providers/filtering_provider.dart';
import 'package:adguard_home_manager/providers/servers_provider.dart';
import 'package:adguard_home_manager/providers/status_provider.dart';
import 'package:adguard_home_manager/screens/filters/my_manual_rules_screen.dart';
import 'package:adguard_home_manager/screens/settings/module/app_allowlist_modal.dart';
import 'package:adguard_home_manager/services/domain_input_parser.dart';
import 'package:adguard_home_manager/services/host_rule_diagnostics.dart';
import 'package:adguard_home_manager/services/manual_rule_provenance_service.dart';
import 'package:adguard_home_manager/services/module_config_service.dart';

/// 极简内嵌式模块快捷操作区（内嵌于首页顶部保护主卡片中）：
/// - 常态下展示国内/海外双模无缝切换器与一行 3 个高频操作按钮（误杀排错、分应用开关、网络刷新）；
/// - 仅当检测到核心未运行或 DNS/SNI 转发异常时，才在按钮上方显示一行异常修复提示。
class ModuleQuickActions extends StatefulWidget {
  const ModuleQuickActions({super.key});

  @override
  State<ModuleQuickActions> createState() => _ModuleQuickActionsState();
}

class _ModuleQuickActionsState extends State<ModuleQuickActions> {
  bool _loadingDiag = true;
  bool _flushing = false;
  bool _switchingMode = false;
  Map<String, dynamic> _diag = {
    'running': true,
    'natOk': true,
    'sniEnabled': true,
    'sniOk': true,
    'runMode': 'overseas',
  };

  @override
  void initState() {
    super.initState();
    _loadDiagnostics();
  }

  Future<void> _loadDiagnostics({bool forceRefresh = false}) async {
    final diag = await ModuleConfigService()
        .getModuleDiagnostics(forceRefresh: forceRefresh);
    if (!mounted) return;
    setState(() {
      _diag = diag;
      _loadingDiag = false;
    });
  }

  Future<void> _syncHttpAddressIfNeeded(
    ServersProvider serversProvider,
    AppConfigProvider appConfigProvider,
    ModuleConfigService service, {
    int? hintHttpPort,
  }) async {
    final currentAddr = appConfigProvider.moduleHttpAddress;
    if (hintHttpPort != null &&
        hintHttpPort > 0 &&
        currentAddr.isNotEmpty &&
        currentAddr.endsWith(':$hintHttpPort')) {
      return;
    }
    final addr = await service.readHttpAddress();
    if (addr != null &&
        addr.isNotEmpty &&
        addr != appConfigProvider.moduleHttpAddress) {
      appConfigProvider.setModuleHttpAddress(addr);
      await serversProvider.autoConnectModule(addr);
    }
  }

  Future<void> _handleSwitchMode(String targetMode) async {
    final currentMode = (_diag['runMode'] ?? 'overseas').toString();
    if (_switchingMode || targetMode == currentMode) return;
    HapticFeedback.mediumImpact();
    setState(() {
      _switchingMode = true;
      _diag['runMode'] = targetMode;
    });

    final serversProvider =
        Provider.of<ServersProvider>(context, listen: false);
    final statusProvider = Provider.of<StatusProvider>(context, listen: false);
    final dnsProvider = Provider.of<DnsProvider>(context, listen: false);
    final filteringProvider =
        Provider.of<FilteringProvider>(context, listen: false);
    final appConfigProvider =
        Provider.of<AppConfigProvider>(context, listen: false);
    final service = ModuleConfigService();

    final switchRes = await service.switchRunModeDetailed(targetMode);
    final refreshSw = Stopwatch()..start();
    await _syncHttpAddressIfNeeded(
      serversProvider,
      appConfigProvider,
      service,
      hintHttpPort: switchRes.httpPort,
    );
    await Future.wait([
      _loadDiagnostics(forceRefresh: true),
      statusProvider.getServerStatus(withLoadingIndicator: false),
      dnsProvider.fetchDnsData(showLoading: false),
      filteringProvider.fetchFilters(showLoading: false),
    ]);
    refreshSw.stop();

    if (!mounted) return;
    setState(() => _switchingMode = false);
    if (switchRes.opId != null) {
      unawaited(service.recordManagerModeSwitchTimings(
        opId: switchRes.opId!,
        managerScriptWaitMs: switchRes.managerScriptWaitMs,
        managerRefreshMs: refreshSw.elapsedMilliseconds,
        status: switchRes.succeeded ? 'ok' : 'error',
      ));
    }
    final modeLabel =
        targetMode == 'cn' ? '🇨🇳 国内模式 (CN)' : '🌐 海外模式 (Overseas)';
    if (switchRes.unconfirmed) {
      showSnackbar(
        appConfigProvider: appConfigProvider,
        label: '执行结果未确认，已同步当前实际状态',
        color: Colors.orange,
        actionLabel: '导出诊断包',
        onAction: () {
          if (mounted) showDiagnosticExportFlow(context, isZhOverride: true);
        },
      );
      return;
    }
    showSnackbar(
      appConfigProvider: appConfigProvider,
      label: switchRes.succeeded
          ? '已成功切换至 $modeLabel'
          : '模式切换失败（${switchRes.stage}），已保持原状态',
      color: switchRes.succeeded ? Colors.green : Colors.red,
      actionLabel: switchRes.succeeded ? null : '导出诊断包',
      onAction: switchRes.succeeded
          ? null
          : () {
              if (mounted) {
                showDiagnosticExportFlow(context, isZhOverride: true);
              }
            },
    );
  }

  Future<void> _handleQuickFlush() async {
    if (_flushing) return;
    HapticFeedback.mediumImpact();
    setState(() => _flushing = true);

    final serversProvider =
        Provider.of<ServersProvider>(context, listen: false);
    final statusProvider = Provider.of<StatusProvider>(context, listen: false);
    final appConfigProvider =
        Provider.of<AppConfigProvider>(context, listen: false);
    final service = ModuleConfigService();

    final repairRes = await service.reloadFirewallRulesDetailed();
    await _syncHttpAddressIfNeeded(serversProvider, appConfigProvider, service);

    bool sysDnsOk =
        repairRes.capabilityConfirmed && repairRes.systemDnsFlushed;
    if (repairRes.succeeded && !sysDnsOk) {
      sysDnsOk = await service.flushSystemDnsCache();
    }

    bool aghDnsOk = true;
    if (repairRes.succeeded && serversProvider.apiClient2 != null) {
      final cacheRes = await serversProvider.apiClient2!.resetDnsCache();
      aghDnsOk = cacheRes.successful;
    }

    await Future.delayed(const Duration(milliseconds: 250));
    await Future.wait([
      _loadDiagnostics(forceRefresh: true),
      statusProvider.getServerStatus(withLoadingIndicator: false),
    ]);

    if (!mounted) return;
    setState(() => _flushing = false);

    if (repairRes.unconfirmed) {
      showSnackbar(
        appConfigProvider: appConfigProvider,
        label: '执行结果未确认，已刷新当前实际状态',
        color: Colors.orange,
      );
      return;
    }

    final diagHealthy = _diag['running'] == true &&
        _diag['natOk'] == true &&
        (_diag['sniEnabled'] != true || _diag['sniOk'] == true);

    if (!repairRes.succeeded || !diagHealthy) {
      showSnackbar(
        appConfigProvider: appConfigProvider,
        label: '修复失败（${repairRes.stage}），请检查日志或 Root 权限',
        color: Colors.red,
      );
      return;
    }

    if (!sysDnsOk || !aghDnsOk) {
      showSnackbar(
        appConfigProvider: appConfigProvider,
        label: '转发规则已恢复，但部分 DNS 缓存刷新未完成',
        color: Colors.orange,
      );
      return;
    }

    showSnackbar(
      appConfigProvider: appConfigProvider,
      label: '已修复并刷新 DNS 缓存与转发规则',
      color: Colors.green,
    );
  }

  Future<void> _openAppAllowlist() async {
    HapticFeedback.lightImpact();
    await showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      barrierColor: Colors.black.withValues(alpha: 0.5),
      builder: (ctx) => const AppAllowlistModal(),
    );
    if (mounted) {
      _loadDiagnostics();
    }
  }

  Future<void> _openFalsePositiveAssistant() async {
    HapticFeedback.lightImpact();
    await showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      barrierColor: Colors.black.withValues(alpha: 0.5),
      builder: (ctx) => const _FalsePositiveAssistantModal(),
    );
  }

  String? _getAnomalyMessage(bool generalEnabled) {
    if (_loadingDiag || !generalEnabled) return null;
    final running = _diag['running'] == true;
    final natOk = _diag['natOk'] == true;
    final sniEnabled = _diag['sniEnabled'] == true;
    final sniOk = _diag['sniOk'] == true;
    if (!running) return '模块核心未运行';
    if (sniEnabled && !natOk && !sniOk) return 'DNS 与 SNI 转发未生效';
    if (!natOk) return 'DNS 转发规则未生效';
    if (sniEnabled && !sniOk) return 'SNI 过滤规则未生效';
    return null;
  }

  @override
  Widget build(BuildContext context) {
    final statusProvider = Provider.of<StatusProvider>(context);
    final generalEnabled = statusProvider.serverStatus?.generalEnabled ?? true;
    final anomalyMsg = _getAnomalyMessage(generalEnabled);

    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (anomalyMsg != null) ...[
          const SizedBox(height: 10),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
            decoration: BoxDecoration(
              color: Colors.orange.withValues(alpha: 0.14),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Row(
              children: [
                const Icon(
                  Icons.warning_amber_rounded,
                  size: 16,
                  color: Colors.orange,
                ),
                const SizedBox(width: 6),
                Expanded(
                  child: Text(
                    anomalyMsg,
                    style: const TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.w600,
                      color: Colors.orange,
                    ),
                  ),
                ),
                InkWell(
                  borderRadius: BorderRadius.circular(6),
                  onTap: _flushing ? null : _handleQuickFlush,
                  child: const Padding(
                    padding: EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    child: Text(
                      '一键修复',
                      style: TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.bold,
                        color: Colors.orange,
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
        const SizedBox(height: 12),
        _ModeSegmentedBar(
          currentMode: (_diag['runMode'] ?? 'overseas').toString(),
          switching: _switchingMode,
          onSelectMode: _handleSwitchMode,
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            Expanded(
              child: _QuickActionButton(
                icon: Icons.troubleshoot_rounded,
                label: '误杀排错',
                onTap: _openFalsePositiveAssistant,
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: _QuickActionButton(
                icon: Icons.apps_rounded,
                label: '分应用开关',
                onTap: _openAppAllowlist,
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: _QuickActionButton(
                icon: _flushing
                    ? Icons.hourglass_top_rounded
                    : Icons.bolt_rounded,
                label: _flushing ? '刷新中…' : '网络刷新',
                onTap: _flushing ? () {} : _handleQuickFlush,
              ),
            ),
          ],
        ),
      ],
    );
  }
}

class _ModeSegmentedBar extends StatelessWidget {
  final String currentMode;
  final bool switching;
  final ValueChanged<String> onSelectMode;

  const _ModeSegmentedBar({
    required this.currentMode,
    required this.switching,
    required this.onSelectMode,
  });

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final isOverseas = currentMode != 'cn';

    Widget buildTab({
      required String mode,
      required String label,
      required bool selected,
    }) {
      return Expanded(
        child: Material(
          color: selected
              ? colorScheme.primaryContainer.withValues(alpha: 0.9)
              : Colors.transparent,
          borderRadius: BorderRadius.circular(10),
          child: InkWell(
            borderRadius: BorderRadius.circular(10),
            onTap: switching ? null : () => onSelectMode(mode),
            child: Padding(
              padding: const EdgeInsets.symmetric(vertical: 7, horizontal: 8),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  if (switching && selected) ...[
                    SizedBox(
                      width: 12,
                      height: 12,
                      child: CircularProgressIndicator(
                        strokeWidth: 1.8,
                        color: colorScheme.onPrimaryContainer,
                      ),
                    ),
                    const SizedBox(width: 6),
                  ],
                  Flexible(
                    child: Text(
                      label,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(
                        fontSize: 12.5,
                        fontWeight:
                            selected ? FontWeight.w700 : FontWeight.w500,
                        color: selected
                            ? colorScheme.onPrimaryContainer
                            : colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      );
    }

    return Container(
      padding: const EdgeInsets.all(3),
      decoration: BoxDecoration(
        color: colorScheme.surfaceContainerHighest.withValues(alpha: 0.55),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        children: [
          buildTab(
            mode: 'overseas',
            label: '🌐 海外模式 (Overseas)',
            selected: isOverseas,
          ),
          const SizedBox(width: 4),
          buildTab(
            mode: 'cn',
            label: '🇨🇳 国内模式 (CN)',
            selected: !isOverseas,
          ),
        ],
      ),
    );
  }
}

class _QuickActionButton extends StatelessWidget {
  final IconData icon;
  final String label;
  final VoidCallback onTap;

  const _QuickActionButton({
    required this.icon,
    required this.label,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final bgColor = colorScheme.surfaceContainerHighest.withValues(alpha: 0.55);
    final fgColor = colorScheme.onSurfaceVariant;

    return Material(
      color: bgColor,
      borderRadius: BorderRadius.circular(12),
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 6),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(icon, size: 15, color: fgColor),
              const SizedBox(width: 5),
              Flexible(
                child: Text(
                  label,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    fontSize: 12.5,
                    fontWeight: FontWeight.w500,
                    color: fgColor,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _BlockedDomainSummary {
  final String domain;
  int count;
  DateTime latestTime;
  final String ruleText;
  final bool isSni;
  final bool isNewAfterCapture;
  final AggregatedLogGroup? group;

  _BlockedDomainSummary({
    required this.domain,
    required this.count,
    required this.latestTime,
    required this.ruleText,
    required this.isSni,
    this.isNewAfterCapture = false,
    this.group,
  });
}

class _DiagnosedDomainItem {
  final String domain;
  final bool blocked;
  final RuleCheckStatus status;
  final String reasonText;
  final String ruleText;
  final List<MatchedRuleInfo> matchedRules;

  const _DiagnosedDomainItem({
    required this.domain,
    required this.blocked,
    this.status = RuleCheckStatus.notBlocked,
    required this.reasonText,
    required this.ruleText,
    this.matchedRules = const [],
  });

  bool get isError =>
      status == RuleCheckStatus.failed || status == RuleCheckStatus.unsupported;
}

class _FalsePositiveAssistantModal extends StatefulWidget {
  const _FalsePositiveAssistantModal();

  @override
  State<_FalsePositiveAssistantModal> createState() =>
      _FalsePositiveAssistantModalState();
}

class _FalsePositiveAssistantModalState
    extends State<_FalsePositiveAssistantModal> with WidgetsBindingObserver {
  int _activeTab = 0; // 0: 最近拦截 & 查规则, 1: 网页排错, 2: 应用排错

  // Tab 0 状态
  bool _loading = true;
  String _searchQuery = '';
  final TextEditingController _searchController = TextEditingController();
  List<_BlockedDomainSummary> _blockedDomains = [];
  List<AggregatedLogGroup> _aggregatedHistory = [];
  bool _usingLegacyLogFallback = false;
  bool _searchingRules = false;
  List<Map<String, String>> _ruleMatches = [];
  Timer? _searchDebounce;
  late final RuleSearchCoordinator _ruleSearchCoordinator;

  // 实时规则检测 & 安全加白状态
  int _liveCheckGen = 0;
  bool _checkingLiveHost = false;
  String? _liveParseError;
  HostFamilyCheckReport? _liveCheckReport;
  String? _activeServerId;
  final ExceptionRuleCoordinator _exceptionCoordinator =
      ExceptionRuleCoordinator();
  final Map<String, ExceptionWriteOutcome> _exceptionOutcomes = {};
  bool _writingException = false;

  // Tab 1 (网页排错) 状态
  final TextEditingController _urlController = TextEditingController();
  bool _diagnosingWeb = false;
  String? _webDiagnoseHint;
  List<_DiagnosedDomainItem> _webDomains = [];

  // Tab 2 (应用排错) 状态
  bool _loadingApps = false;
  List<Map<String, dynamic>> _installedApps = [];
  Set<String> _allowlistedApps = {};
  String _appSearchQuery = '';
  final TextEditingController _appSearchController = TextEditingController();
  Map<String, dynamic>? _selectedApp;
  bool _capturingApp = false;
  DateTime? _captureStartTime;
  Set<String> _baselineBlockedDomains = {};
  List<_BlockedDomainSummary> _capturedAppDomains = [];
  bool _scanningAppLocal = false;
  List<_DiagnosedDomainItem> _scannedAppDomains = [];
  bool _togglingAllowlist = false;

  // 通用放行状态
  final Set<String> _unblockedDomains = {};
  final Set<String> _unblockingInProgress = {};
  bool _batchUnblocking = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    ManualRuleProvenanceService.instance.ensureLoaded();
    _ruleSearchCoordinator = RuleSearchCoordinator(
      executor: (keyword) => ModuleConfigService().searchFilterRules(keyword),
      onResult: (generation, keyword, matches, stillSearching) {
        if (!mounted ||
            generation != _ruleSearchCoordinator.requestGeneration) {
          return;
        }
        setState(() {
          _ruleMatches = matches;
          _searchingRules = stillSearching;
        });
      },
    );
    _fetchRecentBlocked();
    _searchController.addListener(_onSearchChanged);
    _appSearchController.addListener(() {
      if (!mounted) return;
      setState(() {
        _appSearchQuery = _appSearchController.text.trim().toLowerCase();
      });
    });
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final currentServerId =
        Provider.of<ServersProvider>(context).selectedServer?.id;
    if (_activeServerId != null && currentServerId != _activeServerId) {
      // 切换服务器时立即作废在途实时检测与旧列表结果，并刷新新服务器数据
      _liveCheckGen++;
      _activeServerId = currentServerId;
      _liveCheckReport = null;
      _liveParseError = null;
      _checkingLiveHost = false;
      _exceptionOutcomes.clear();
      _blockedDomains = [];
      _aggregatedHistory = [];
      _usingLegacyLogFallback = false;
      if (_searchQuery.isNotEmpty) {
        final q = _searchController.text;
        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (mounted) _triggerLiveCheckForInput(q);
        });
      }
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) _fetchRecentBlocked();
      });
    } else {
      _activeServerId ??= currentServerId;
    }
  }

  @override
  void dispose() {
    _liveCheckGen++;
    WidgetsBinding.instance.removeObserver(this);
    _searchDebounce?.cancel();
    _ruleSearchCoordinator.dispose();
    _searchController.dispose();
    _urlController.dispose();
    _appSearchController.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed &&
        _capturingApp &&
        _captureStartTime != null) {
      _finishAppCapture();
    }
  }

  (Map<int, String>, Map<int, String>) _resolveFilterNameMaps(
      Filtering? filtering) {
    if (filtering == null) return (const {}, const {});
    return (
      RuleBatchChecker.buildFilterNameMap(filtering.filters),
      RuleBatchChecker.buildFilterNameMap(filtering.whitelistFilters),
    );
  }

  void _onSearchChanged() {
    final raw = _searchController.text;
    final q = raw.trim().toLowerCase();
    if (q == _searchQuery) return;
    _searchDebounce?.cancel();
    _liveCheckGen++;

    if (q.length < 2) {
      _ruleSearchCoordinator.invalidatePending();
      setState(() {
        _searchQuery = q;
        _ruleMatches = [];
        _searchingRules = false;
        _checkingLiveHost = false;
        _liveParseError = null;
        _liveCheckReport = null;
      });
      return;
    }

    setState(() {
      _searchQuery = q;
      _searchingRules = true;
      _checkingLiveHost = true;
      _liveParseError = null;
      _liveCheckReport = null;
    });
    final gen = _liveCheckGen;
    _searchDebounce = Timer(const Duration(milliseconds: 300), () {
      if (!mounted || gen != _liveCheckGen) return;
      _triggerLiveCheckForInput(raw, forcedGen: gen);
    });
  }

  Future<void> _triggerLiveCheckForInput(String rawInput, {int? forcedGen}) async {
    final gen = forcedGen ?? ++_liveCheckGen;
    final parsed = DomainInputParser.parseSingleInput(rawInput);

    if (!parsed.ok) {
      // 若包含明显 URL/空白歧义/非法链接字符则直接给出解析错误；纯短关键词仍允许历史与规则文本搜索
      final looksLikeUrlOrAmbiguous = rawInput.contains('://') ||
          rawInput.contains('/') ||
          rawInput.contains(':') ||
          RegExp(r'\s').hasMatch(rawInput.trim()) ||
          rawInput.contains('.');
      _ruleSearchCoordinator.submitSearch(rawInput.trim().toLowerCase());
      if (!mounted || gen != _liveCheckGen) return;
      setState(() {
        _checkingLiveHost = false;
        _liveCheckReport = null;
        _liveParseError =
            looksLikeUrlOrAmbiguous ? (parsed.errorReason ?? '输入格式无效') : null;
      });
      return;
    }

    // 用规范化后的 host 触发本地规则辅助搜索（绝不把含追踪 token 的完整 URL 送去写日志或网络）
    _ruleSearchCoordinator.submitSearch(parsed.normalizedHost);

    final serversProvider =
        Provider.of<ServersProvider>(context, listen: false);
    final api = serversProvider.apiClient2;
    if (api == null) {
      if (!mounted || gen != _liveCheckGen) return;
      setState(() {
        _checkingLiveHost = false;
        _liveParseError = null;
        _liveCheckReport = HostFamilyCheckReport(
          parsedInput: parsed,
          originalA: HostCheckResult(
            host: parsed.normalizedHost,
            isOriginal: true,
            status: RuleCheckStatus.failed,
            rawReason: '',
            rules: const [],
            errorDetail: '未连接服务器',
          ),
          parentResults: const [],
        );
      });
      return;
    }

    final filteringProvider =
        Provider.of<FilteringProvider>(context, listen: false);
    var filtering = filteringProvider.filtering;
    if (filtering == null) {
      await filteringProvider.fetchFilters(showLoading: false);
      if (!mounted || gen != _liveCheckGen) return;
      filtering = filteringProvider.filtering;
    }
    final (filterNames, whitelistNames) = _resolveFilterNameMaps(filtering);

    final serverSnapshot = _activeServerId;
    final report = await RuleBatchChecker.checkDomainFamily(
      parsed: parsed,
      filterNames: filterNames,
      whitelistNames: whitelistNames,
      isCancelled: () =>
          !mounted || gen != _liveCheckGen || _activeServerId != serverSnapshot,
      checker: (host, qtype) => api.checkHostFiltered(host: host, qtype: qtype),
    );

    if (!mounted || gen != _liveCheckGen || _activeServerId != serverSnapshot) {
      return;
    }
    setState(() {
      _checkingLiveHost = false;
      _liveParseError = null;
      _liveCheckReport = report;
    });
  }

  Future<void> _fetchRecentBlocked() async {
    setState(() => _loading = true);
    final serversProvider =
        Provider.of<ServersProvider>(context, listen: false);
    final api = serversProvider.apiClient2;
    if (api == null) {
      if (mounted) setState(() => _loading = false);
      return;
    }
    final filteringProvider =
        Provider.of<FilteringProvider>(context, listen: false);
    if (filteringProvider.filtering == null) {
      await filteringProvider.fetchFilters(showLoading: false);
    }
    if (!mounted) return;
    final (filterNames, whitelistNames) =
        _resolveFilterNameMaps(filteringProvider.filtering);

    final summaryResp = await api.getBlockedSummary(limit: 256);
    if (!mounted) return;

    if (summaryResp.successful == true &&
        summaryResp.content is Map<String, dynamic>) {
      final parsedSummary = BlockedSummaryData.fromJson(
          summaryResp.content as Map<String, dynamic>);
      final groups = BlockedEventAggregator.fromBlockedSummary(
        parsedSummary,
        filterNames: filterNames,
        whitelistNames: whitelistNames,
      );
      final domains = _buildLegacyDomainListFromGroups(groups);
      setState(() {
        _usingLegacyLogFallback = false;
        _aggregatedHistory = groups;
        _blockedDomains = domains;
        _loading = false;
      });
      return;
    }

    // 兼容回退：旧版核心不支持 /control/querylog/blocked_summary 时回退到 /querylog?response_status=blocked
    final fallbackResp = await api.getLogs(
      count: 200,
      responseStatus: 'blocked',
    );
    if (!mounted) return;
    if (fallbackResp.successful == true && fallbackResp.content is LogsData) {
      final logs = (fallbackResp.content as LogsData).data;
      final groups = BlockedEventAggregator.aggregateRawLogs(
        logs,
        filterNames: filterNames,
        whitelistNames: whitelistNames,
      );
      final domains = _buildLegacyDomainListFromGroups(groups);
      setState(() {
        _usingLegacyLogFallback =
            summaryResp.statusCode == 404 || summaryResp.statusCode == 501 || !summaryResp.successful;
        _aggregatedHistory = groups;
        _blockedDomains = domains;
        _loading = false;
      });
    } else {
      setState(() => _loading = false);
    }
  }

  List<_BlockedDomainSummary> _buildLegacyDomainListFromGroups(
      List<AggregatedLogGroup> groups) {
    final map = <String, _BlockedDomainSummary>{};
    for (final g in groups) {
      final existing = map[g.domain];
      if (existing != null) {
        existing.count += g.count;
        if (g.time.isAfter(existing.latestTime)) {
          existing.latestTime = g.time;
        }
      } else {
        map[g.domain] = _BlockedDomainSummary(
          domain: g.domain,
          count: g.count,
          latestTime: g.time,
          ruleText: g.primaryRuleText,
          isSni: g.isSni,
          group: g,
        );
      }
    }
    return map.values.toList()
      ..sort((a, b) => b.latestTime.compareTo(a.latestTime));
  }

  Future<_DiagnosedDomainItem> _checkSingleDomain(String domain) async {
    final serversProvider =
        Provider.of<ServersProvider>(context, listen: false);
    final api = serversProvider.apiClient2;
    if (api == null) {
      return _DiagnosedDomainItem(
        domain: domain,
        blocked: false,
        status: RuleCheckStatus.failed,
        reasonText: '未连接服务器',
        ruleText: '',
      );
    }
    final filteringProvider =
        Provider.of<FilteringProvider>(context, listen: false);
    final (filterNames, whitelistNames) =
        _resolveFilterNameMaps(filteringProvider.filtering);
    try {
      final res = await api
          .checkHostFiltered(host: domain, qtype: 'A')
          .timeout(const Duration(seconds: 5));
      final parsed = HostCheckResult.fromApiResponse(
        host: domain,
        response: res,
        isOriginal: true,
        filterNames: filterNames,
        whitelistNames: whitelistNames,
      );
      return _DiagnosedDomainItem(
        domain: domain,
        blocked: parsed.isBlocked,
        status: parsed.status,
        reasonText: parsed.statusLabel,
        ruleText: parsed.rules.isNotEmpty
            ? '${parsed.rules.first.sourceName} · ${parsed.rules.first.text}'
            : '',
        matchedRules: parsed.rules,
      );
    } catch (e) {
      return _DiagnosedDomainItem(
        domain: domain,
        blocked: false,
        status: RuleCheckStatus.failed,
        reasonText: '查询失败（超时或异常）',
        ruleText: '',
      );
    }
  }

  Future<List<R>> _runBounded<T, R>(
    List<T> items,
    Future<R> Function(T) task, {
    int concurrency = 4,
  }) async {
    if (items.isEmpty) return <R>[];
    final results = List<R?>.filled(items.length, null);
    var nextIndex = 0;
    final workerCount = items.length < concurrency ? items.length : concurrency;

    Future<void> worker() async {
      while (nextIndex < items.length) {
        final idx = nextIndex++;
        results[idx] = await task(items[idx]);
      }
    }

    await Future.wait(List.generate(workerCount, (_) => worker()));
    return results.cast<R>();
  }

  Future<void> _diagnoseWebpage() async {
    final raw = _urlController.text.trim();
    if (raw.isEmpty || _diagnosingWeb) return;
    FocusScope.of(context).unfocus();
    HapticFeedback.lightImpact();

    setState(() {
      _diagnosingWeb = true;
      _webDiagnoseHint = '正在抓取网页源码并解析外链静态域名…';
      _webDomains = [];
    });

    final domains = await ModuleConfigService().extractWebpageDomains(raw);
    if (!mounted) return;
    if (domains.isEmpty) {
      setState(() {
        _diagnosingWeb = false;
        _webDiagnoseHint = '未能解析出有效域名，请检查输入的网址链接';
      });
      return;
    }

    setState(() {
      _webDiagnoseHint = '已提取 ${domains.length} 个关联域名，正在检测规则拦截状态…';
    });

    final results = await _runBounded(domains, _checkSingleDomain, concurrency: 4);
    if (!mounted) return;

    results.sort((a, b) {
      if (a.blocked != b.blocked) return a.blocked ? -1 : 1;
      return a.domain.compareTo(b.domain);
    });

    final blockedCount = results.where((e) => e.blocked).length;
    setState(() {
      _webDomains = results;
      _diagnosingWeb = false;
      _webDiagnoseHint = blockedCount > 0
          ? '共发现 ${results.length} 个网页关联域名，其中 $blockedCount 个被拦截（疑似导致网页异常的真凶）：'
          : '共检测 ${results.length} 个关联域名，均未被规则库拦截。若仍无法访问，可切换至「最近拦截」查看实时记录。';
    });
  }

  Future<void> _ensureAppsLoaded() async {
    if (_installedApps.isNotEmpty || _loadingApps) return;
    setState(() => _loadingApps = true);
    final service = ModuleConfigService();
    final results = await Future.wait([
      service.getInstalledApps(includeSystem: false),
      service.readAppAllowlist(),
    ]);
    if (!mounted) return;
    setState(() {
      _installedApps = results[0] as List<Map<String, dynamic>>;
      _allowlistedApps = (results[1] as List<String>).toSet();
      _loadingApps = false;
    });
  }

  Future<void> _startAppCapture(Map<String, dynamic> app) async {
    final pkg = (app['package'] ?? '').toString();
    if (pkg.isEmpty) return;
    HapticFeedback.mediumImpact();

    final baseline = _blockedDomains.map((e) => e.domain).toSet();
    final startTime = DateTime.now().subtract(const Duration(seconds: 2));

    setState(() {
      _capturingApp = true;
      _captureStartTime = startTime;
      _baselineBlockedDomains = baseline;
      _capturedAppDomains = [];
    });

    final serversProvider =
        Provider.of<ServersProvider>(context, listen: false);
    if (serversProvider.apiClient2 != null) {
      await serversProvider.apiClient2!.resetDnsCache();
    }

    await ModuleConfigService().launchAppForCapture(pkg, forceStop: true);
  }

  Future<void> _finishAppCapture() async {
    final startTime = _captureStartTime;
    if (startTime == null) return;
    setState(() {
      _capturingApp = false;
    });

    await _fetchRecentBlocked();
    if (!mounted) return;

    final List<_BlockedDomainSummary> newlyTriggered = [];
    for (final item in _blockedDomains) {
      if (item.latestTime.isAfter(startTime)) {
        final isNewDomain = !_baselineBlockedDomains.contains(item.domain);
        newlyTriggered.add(
          _BlockedDomainSummary(
            domain: item.domain,
            count: item.count,
            latestTime: item.latestTime,
            ruleText: item.ruleText,
            isSni: item.isSni,
            isNewAfterCapture: isNewDomain,
          ),
        );
      }
    }

    newlyTriggered.sort((a, b) {
      if (a.isNewAfterCapture != b.isNewAfterCapture) {
        return a.isNewAfterCapture ? -1 : 1;
      }
      return b.latestTime.compareTo(a.latestTime);
    });

    setState(() {
      _capturedAppDomains = newlyTriggered;
    });
  }

  Future<void> _scanSelectedAppDomains(Map<String, dynamic> app) async {
    final pkg = (app['package'] ?? '').toString();
    if (pkg.isEmpty || _scanningAppLocal) return;
    HapticFeedback.lightImpact();

    setState(() {
      _scanningAppLocal = true;
      _scannedAppDomains = [];
    });

    final domains = await ModuleConfigService().scanAppLocalDomains(pkg);
    if (!mounted) return;
    if (domains.isEmpty) {
      setState(() => _scanningAppLocal = false);
      return;
    }

    final checked = await _runBounded(domains, _checkSingleDomain, concurrency: 4);
    if (!mounted) return;

    checked.sort((a, b) {
      if (a.blocked != b.blocked) return a.blocked ? -1 : 1;
      return a.domain.compareTo(b.domain);
    });

    setState(() {
      _scannedAppDomains = checked;
      _scanningAppLocal = false;
    });
  }

  Future<void> _toggleSelectedAppAllowlist(Map<String, dynamic> app) async {
    final pkg = (app['package'] ?? '').toString();
    final name = (app['name'] ?? pkg).toString();
    if (pkg.isEmpty || _togglingAllowlist) return;
    HapticFeedback.mediumImpact();

    setState(() => _togglingAllowlist = true);
    final service = ModuleConfigService();
    final appConfigProvider =
        Provider.of<AppConfigProvider>(context, listen: false);
    final updated = Set<String>.from(_allowlistedApps);
    final adding = !updated.contains(pkg);
    if (adding) {
      updated.add(pkg);
    } else {
      updated.remove(pkg);
    }

    final reloadRes = await service.saveAppAllowlistDetailed(updated.toList());
    final ok = reloadRes.succeeded;
    bool dnsOk =
        reloadRes.capabilityConfirmed && reloadRes.systemDnsFlushed;
    if (ok && !dnsOk) {
      dnsOk = await service.flushSystemDnsCache();
    }

    if (!mounted) return;
    setState(() {
      _togglingAllowlist = false;
      if (ok) {
        _allowlistedApps = updated;
      }
    });

    showSnackbar(
      appConfigProvider: appConfigProvider,
      label: ok
          ? (dnsOk
              ? (adding ? '已将「$name」加入应用白名单并刷新网络' : '已将「$name」移出应用白名单')
              : (adding ? '已将「$name」加入应用白名单（DNS 缓存刷新未确认）' : '已将「$name」移出应用白名单（DNS 缓存刷新未确认）'))
          : '操作失败，请重试',
      color: ok ? (dnsOk ? Colors.green : Colors.orange) : Colors.red,
    );
  }

  String _formatRelativeTime(DateTime time) {
    final diff = DateTime.now().difference(time);
    if (diff.inSeconds < 60) return '${diff.inSeconds.clamp(1, 59)}秒前';
    if (diff.inMinutes < 60) return '${diff.inMinutes}分钟前';
    if (diff.inHours < 24) return '${diff.inHours}小时前';
    return '${time.month}/${time.day} ${time.hour.toString().padLeft(2, '0')}:${time.minute.toString().padLeft(2, '0')}';
  }

  Future<bool> _confirmRuleDialog({
    required String title,
    required String body,
    required String rule,
  }) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(title, style: const TextStyle(fontSize: 16)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(body, style: const TextStyle(fontSize: 13)),
            const SizedBox(height: 8),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: Theme.of(ctx).colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Text(
                rule,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('确认写入'),
          ),
        ],
      ),
    );
    return ok == true;
  }

  Future<void> _applyExceptionRule(
    String rule, {
    required bool confirmBroad,
    String? verifyHostOverride,
  }) async {
    if (_writingException) return;
    final verifyHost = verifyHostOverride ??
        _liveCheckReport?.parsedInput.normalizedHost ??
        '';
    if (verifyHost.isEmpty) return;

    if (confirmBroad) {
      final isImp = rule.endsWith(r'$important');
      final confirmed = await _confirmRuleDialog(
        title: isImp ? '确认添加优先级例外' : '确认宽范围放行',
        body: isImp
            ? '当前命中规则带 \$important 优先级。仅在明确知晓优先级影响时，才应添加如下 \$important 例外规则：'
            : '该例外规则会影响所属域名及全部下级子域名（例如可能同时放行同一追踪域名下的其他链接），是否确认写入？',
        rule: rule,
      );
      if (!confirmed || !mounted) return;
    }

    HapticFeedback.mediumImpact();
    setState(() => _writingException = true);

    final serversProvider =
        Provider.of<ServersProvider>(context, listen: false);
    final filteringProvider =
        Provider.of<FilteringProvider>(context, listen: false);
    final appConfigProvider =
        Provider.of<AppConfigProvider>(context, listen: false);
    final api = serversProvider.apiClient2;
    if (api == null) {
      if (mounted) setState(() => _writingException = false);
      return;
    }
    final (filterNames, whitelistNames) =
        _resolveFilterNameMaps(filteringProvider.filtering);

    final outcome = await _exceptionCoordinator.applyExceptionAndVerify(
      apiClient: api,
      verifyHost: verifyHost,
      exceptionRule: rule,
      flushSystemDnsCache: () => ModuleConfigService().flushSystemDnsCache(),
      filterNames: filterNames,
      whitelistNames: whitelistNames,
    );
    await filteringProvider.fetchFilters(showLoading: false);

    if (!mounted) return;
    setState(() {
      _writingException = false;
      _exceptionOutcomes[rule] = outcome;
      if (outcome.verifiedUnblocked) {
        _unblockedDomains.add(verifyHost);
      }
    });

    if (_liveCheckReport != null &&
        _liveCheckReport!.parsedInput.normalizedHost == verifyHost) {
      await _triggerLiveCheckForInput(verifyHost);
    }

    if (!mounted) return;
    showSnackbar(
      appConfigProvider: appConfigProvider,
      label: outcome.message,
      color: outcome.verifiedUnblocked &&
              !outcome.cacheFlushFailed &&
              !outcome.provenanceSaveFailed &&
              !outcome.provenanceInterrupted &&
              !outcome.provenanceLegacyUnconfirmed
          ? Colors.green
          : (outcome.writeSucceeded ? Colors.orange : Colors.red),
    );
  }

  Future<void> _undoExceptionRule(String addedRule) async {
    if (_writingException) return;
    final serversProvider =
        Provider.of<ServersProvider>(context, listen: false);
    final filteringProvider =
        Provider.of<FilteringProvider>(context, listen: false);
    final appConfigProvider =
        Provider.of<AppConfigProvider>(context, listen: false);
    final api = serversProvider.apiClient2;
    if (api == null) return;

    setState(() => _writingException = true);
    final token = _exceptionOutcomes[addedRule]?.undoToken;
    final res = await _exceptionCoordinator.undoAddedException(
      apiClient: api,
      addedRule: addedRule,
      undoToken: token,
      flushSystemDnsCache: () => ModuleConfigService().flushSystemDnsCache(),
    );
    await filteringProvider.fetchFilters(showLoading: false);

    if (!mounted) return;
    setState(() {
      _writingException = false;
      if (res.ok) {
        _exceptionOutcomes.remove(addedRule);
        if (_liveCheckReport != null) {
          _unblockedDomains.remove(_liveCheckReport!.parsedInput.normalizedHost);
        }
      }
    });
    if (_liveCheckReport != null) {
      await _triggerLiveCheckForInput(_liveCheckReport!.parsedInput.normalizedHost);
    }

    if (!mounted) return;
    showSnackbar(
      appConfigProvider: appConfigProvider,
      label: res.message,
      color: res.ok ? Colors.green : Colors.red,
    );
  }

  Future<void> _unblockDomain(
    String domain, {
    List<MatchedRuleInfo> matchedRules = const [],
  }) async {
    if (_unblockingInProgress.contains(domain) ||
        _unblockedDomains.contains(domain)) {
      return;
    }
    final suggestion = WhitelistPlanner.buildSuggestion(
      originalHost: domain,
      matchedRules: matchedRules,
    );
    if (!mounted) return;

    final selectedRule = await showDialog<({String rule, bool broad})>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('选择放行范围 · $domain', style: const TextStyle(fontSize: 15.5)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (suggestion.narrowRule != null) ...[
              Text('按钮 A · 放行此子域名: ${suggestion.narrowRule}',
                  style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 12.5)),
              const SizedBox(height: 2),
              Text(suggestion.narrowDescription,
                  style: const TextStyle(fontSize: 11.5)),
              const SizedBox(height: 10),
            ],
            if (suggestion.broadRule != null) ...[
              Text('按钮 B · 放行命中规则域名: ${suggestion.broadRule}',
                  style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 12.5)),
              const SizedBox(height: 2),
              Text(suggestion.broadDescription ?? '',
                  style: TextStyle(fontSize: 11.5, color: Colors.orange.shade900)),
            ] else if (suggestion.broadDisabledReason != null) ...[
              Text('宽范围放行已禁用: ${suggestion.broadDisabledReason}',
                  style: const TextStyle(fontSize: 11.5, color: Colors.grey)),
            ],
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('取消'),
          ),
          if (suggestion.narrowRule != null)
            FilledButton.tonal(
              onPressed: () =>
                  Navigator.pop(ctx, (rule: suggestion.narrowRule!, broad: false)),
              child: const Text('放行此子域名'),
            ),
          if (suggestion.broadRule != null)
            OutlinedButton(
              onPressed: () =>
                  Navigator.pop(ctx, (rule: suggestion.broadRule!, broad: true)),
              child: const Text('放行规则域名'),
            ),
        ],
      ),
    );
    if (selectedRule == null || !mounted) return;

    setState(() => _unblockingInProgress.add(domain));
    await _applyExceptionRule(
      selectedRule.rule,
      confirmBroad: selectedRule.broad,
      verifyHostOverride: domain,
    );
    if (!mounted) return;
    setState(() => _unblockingInProgress.remove(domain));
  }

  Future<void> _unblockAllDomains(List<String> domains) async {
    final pending =
        domains.where((d) => !_unblockedDomains.contains(d)).toList();
    if (pending.isEmpty || _batchUnblocking) return;
    final confirmed = await _confirmRuleDialog(
      title: '确认批量写入子域名例外',
      body: '将为以下 ${pending.length} 个被拦截域名分别写入 `@@||域名^` 例外（保留既有规则，不使用 \$important）并逐项核验：',
      rule: pending.map((d) => '@@||$d^').join('\n'),
    );
    if (!confirmed || !mounted) return;

    HapticFeedback.mediumImpact();
    setState(() => _batchUnblocking = true);

    final serversProvider =
        Provider.of<ServersProvider>(context, listen: false);
    final filteringProvider =
        Provider.of<FilteringProvider>(context, listen: false);
    final appConfigProvider =
        Provider.of<AppConfigProvider>(context, listen: false);
    final api = serversProvider.apiClient2;
    if (api == null) {
      setState(() => _batchUnblocking = false);
      return;
    }
    final (filterNames, whitelistNames) =
        _resolveFilterNameMaps(filteringProvider.filtering);

    int verifiedCount = 0;
    for (final d in pending) {
      final out = await _exceptionCoordinator.applyExceptionAndVerify(
        apiClient: api,
        verifyHost: d,
        exceptionRule: '@@||$d^',
        flushSystemDnsCache: () => ModuleConfigService().flushSystemDnsCache(),
        filterNames: filterNames,
        whitelistNames: whitelistNames,
      );
      if (out.verifiedUnblocked) {
        verifiedCount++;
        if (mounted) {
          setState(() => _unblockedDomains.add(d));
        }
      }
    }
    await filteringProvider.fetchFilters(showLoading: false);

    if (!mounted) return;
    setState(() => _batchUnblocking = false);
    showSnackbar(
      appConfigProvider: appConfigProvider,
      label: '已写入 $verifiedCount/${pending.length} 个子域名例外并核验生效',
      color: verifiedCount == pending.length ? Colors.green : Colors.orange,
    );
  }

  Widget _buildModeSelector(ColorScheme colorScheme) {
    const tabs = [
      (Icons.history_rounded, '最近拦截 & 查规则'),
      (Icons.language_rounded, '网页排错'),
      (Icons.phonelink_setup_rounded, '应用排错'),
    ];
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 2, 16, 8),
      child: Container(
        padding: const EdgeInsets.all(3),
        decoration: BoxDecoration(
          color: colorScheme.surfaceContainerHighest.withValues(alpha: 0.6),
          borderRadius: BorderRadius.circular(12),
        ),
        child: Row(
          children: List.generate(tabs.length, (i) {
            final selected = _activeTab == i;
            return Expanded(
              child: GestureDetector(
                onTap: () {
                  if (_activeTab == i) return;
                  HapticFeedback.selectionClick();
                  setState(() => _activeTab = i);
                  if (i == 2) {
                    _ensureAppsLoaded();
                  }
                },
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 180),
                  padding: const EdgeInsets.symmetric(vertical: 7),
                  decoration: BoxDecoration(
                    color: selected ? colorScheme.surface : Colors.transparent,
                    borderRadius: BorderRadius.circular(9),
                    boxShadow: selected
                        ? [
                            BoxShadow(
                              color: Colors.black.withValues(alpha: 0.06),
                              blurRadius: 4,
                              offset: const Offset(0, 1),
                            ),
                          ]
                        : null,
                  ),
                  child: Text(
                    tabs[i].$2,
                    textAlign: TextAlign.center,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      fontSize: 12,
                      fontWeight:
                          selected ? FontWeight.bold : FontWeight.w500,
                      color: selected
                          ? colorScheme.primary
                          : colorScheme.onSurfaceVariant,
                    ),
                  ),
                ),
              ),
            );
          }),
        ),
      ),
    );
  }

  Widget _buildRecentAndRuleSearchTab(ColorScheme colorScheme) {
    final normalizedHost =
        _liveCheckReport?.parsedInput.normalizedHost ?? '';
    final effectiveQuery =
        normalizedHost.isNotEmpty ? normalizedHost : _searchQuery;

    final filteredGroups = _aggregatedHistory.where((item) {
      if (effectiveQuery.isEmpty) return true;
      final dl = item.domain.toLowerCase();
      if (dl.contains(effectiveQuery)) return true;
      if (_searchQuery.isNotEmpty && dl.contains(_searchQuery)) return true;
      for (final r in item.matchedRules) {
        if (r.text.toLowerCase().contains(effectiveQuery) ||
            (_searchQuery.isNotEmpty &&
                r.text.toLowerCase().contains(_searchQuery))) {
          return true;
        }
      }
      return false;
    }).toList();

    final recentDomainSet =
        filteredGroups.map((e) => e.domain.toLowerCase()).toSet();
    final extraRuleMatches = _ruleMatches
        .where((m) => !recentDomainSet.contains((m['domain'] ?? '').toLowerCase()))
        .toList();
    final hasLiveCard =
        _liveParseError != null || _checkingLiveHost || _liveCheckReport != null;

    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
          child: TextField(
            controller: _searchController,
            onSubmitted: (val) => _triggerLiveCheckForInput(val),
            decoration: InputDecoration(
              isDense: true,
              prefixIcon: const Icon(Icons.search_rounded, size: 20),
              hintText: '输入链接或域名实时检规则（如 SendGrid 追踪 URL 或域名）…',
              suffixIcon: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (_searchController.text.isNotEmpty)
                    IconButton(
                      icon: const Icon(Icons.clear_rounded, size: 18),
                      onPressed: () => _searchController.clear(),
                    ),
                  IconButton(
                    tooltip: '粘贴链接/域名',
                    icon: const Icon(Icons.content_paste_rounded, size: 18),
                    onPressed: () async {
                      final data = await Clipboard.getData(Clipboard.kTextPlain);
                      final txt = data?.text?.trim() ?? '';
                      if (txt.isNotEmpty && mounted) {
                        _searchController.text = txt;
                        _triggerLiveCheckForInput(txt);
                      }
                    },
                  ),
                ],
              ),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(12),
              ),
              contentPadding: const EdgeInsets.symmetric(
                vertical: 9,
                horizontal: 12,
              ),
            ),
          ),
        ),
        if (hasLiveCard)
          LiveRuleDiagnosticCard(
            rawQuery: _searchController.text,
            parseError: _liveParseError,
            checking: _checkingLiveHost,
            report: _liveCheckReport,
            outcomesByRule: _exceptionOutcomes,
            writeBusy: _writingException,
            serverKey: ManualRuleProvenanceService.serverKeyForNullable(
              Provider.of<ServersProvider>(context, listen: false)
                  .selectedServer,
            ),
            onApplyException: (rule, {required confirmBroad}) =>
                _applyExceptionRule(rule, confirmBroad: confirmBroad),
            onUndoException: _undoExceptionRule,
            onOpenMyManualRules: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (_) => const MyManualRulesScreen(),
                ),
              );
            },
          ),
        const Divider(height: 1),
        Expanded(
          child: _loading
              ? const Center(child: CircularProgressIndicator())
              : (filteredGroups.isEmpty &&
                      extraRuleMatches.isEmpty &&
                      !_searchingRules)
                  ? Center(
                      child: Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 24),
                        child: Text(
                          effectiveQuery.isNotEmpty
                              ? '历史记录与本地规则文件未匹配 "$effectiveQuery"。\n提示：上方「实时规则检测」直接向核心查询当前规则命中状态，不受历史日志覆盖影响。'
                              : '最近暂无拦截历史事件',
                          textAlign: TextAlign.center,
                          style: TextStyle(
                            fontSize: 13,
                            color: colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ),
                    )
                  : ListView(
                      physics: const BouncingScrollPhysics(),
                      children: [
                        if (_usingLegacyLogFallback)
                          Padding(
                            padding: const EdgeInsets.fromLTRB(16, 8, 16, 2),
                            child: Text(
                              '提示：当前核心版本不支持近期阻断摘要接口，已兼容回退至近期日志，高频重试时较早记录可能被挤出。',
                              style: TextStyle(
                                fontSize: 11,
                                color: Colors.orange.shade900,
                              ),
                            ),
                          )
                        else if (filteredGroups.isNotEmpty)
                          Padding(
                            padding: const EdgeInsets.fromLTRB(16, 8, 16, 2),
                            child: Text(
                              '历史事件 · 来自核心有限内存摘要（最多保留 5 分钟 / 256 条聚合事件）',
                              style: TextStyle(
                                fontSize: 11,
                                color: colorScheme.onSurfaceVariant,
                              ),
                            ),
                          ),
                        if (filteredGroups.isNotEmpty) ...[
                          Padding(
                            padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
                            child: Text(
                              '历史事件 (${filteredGroups.length})',
                              style: TextStyle(
                                fontSize: 12,
                                fontWeight: FontWeight.bold,
                                color: colorScheme.primary,
                              ),
                            ),
                          ),
                          ...filteredGroups.map(
                            (group) => _buildAggregatedHistoryTile(
                              group,
                              colorScheme,
                            ),
                          ),
                        ],
                        if (_searchingRules)
                          const Padding(
                            padding: EdgeInsets.all(16),
                            child: Center(
                              child: SizedBox(
                                width: 20,
                                height: 20,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                ),
                              ),
                            ),
                          ),
                        if (extraRuleMatches.isNotEmpty) ...[
                          Padding(
                            padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
                            child: Text(
                              '本地规则文本补充匹配 (${extraRuleMatches.length})',
                              style: TextStyle(
                                fontSize: 12,
                                fontWeight: FontWeight.bold,
                                color: colorScheme.primary,
                              ),
                            ),
                          ),
                          ...extraRuleMatches.map((m) {
                            final domain = m['domain'] ?? '';
                            final rule = m['rule'] ?? '';
                            final filterName = m['filterName'] ?? '';
                            final isUnblocked =
                                _unblockedDomains.contains(domain);
                            final isBusy =
                                _unblockingInProgress.contains(domain);
                            return ListTile(
                              dense: true,
                              contentPadding: const EdgeInsets.symmetric(
                                horizontal: 16,
                                vertical: 2,
                              ),
                              title: Row(
                                children: [
                                  Container(
                                    padding: const EdgeInsets.symmetric(
                                      horizontal: 5,
                                      vertical: 1.5,
                                    ),
                                    decoration: BoxDecoration(
                                      color:
                                          Colors.orange.withValues(alpha: 0.14),
                                      borderRadius: BorderRadius.circular(5),
                                    ),
                                    child: const Text(
                                      '规则库',
                                      style: TextStyle(
                                        fontSize: 10,
                                        fontWeight: FontWeight.bold,
                                        color: Colors.orange,
                                      ),
                                    ),
                                  ),
                                  const SizedBox(width: 6),
                                  Expanded(
                                    child: Text(
                                      domain,
                                      maxLines: 1,
                                      overflow: TextOverflow.ellipsis,
                                      style: const TextStyle(
                                        fontSize: 14,
                                        fontWeight: FontWeight.w500,
                                      ),
                                    ),
                                  ),
                                ],
                              ),
                              subtitle: Text(
                                '$filterName · $rule',
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: TextStyle(
                                  fontSize: 11.5,
                                  color: colorScheme.onSurfaceVariant,
                                ),
                              ),
                              trailing: _buildUnblockButton(
                                domain,
                                isUnblocked,
                                isBusy,
                                matchedRules: rule.isNotEmpty
                                    ? [
                                        MatchedRuleInfo(
                                          text: rule,
                                          filterListId: 0,
                                          sourceName: filterName,
                                        ),
                                      ]
                                    : const [],
                              ),
                            );
                          }),
                        ],
                      ],
                    ),
        ),
      ],
    );
  }

  Widget _buildAggregatedHistoryTile(
    AggregatedLogGroup group,
    ColorScheme colorScheme,
  ) {
    final isUnblocked = _unblockedDomains.contains(group.domain);
    final isBusy = _unblockingInProgress.contains(group.domain);
    final protoLabel = group.isSni ? 'SNI' : 'DNS';
    final badgeColor = group.isSni ? Colors.purple : Colors.red;
    final hhmmss = convertTimestampLocalTimezone(group.time, 'HH:mm:ss');
    final ruleSummary = group.matchedRules.isNotEmpty
        ? group.matchedRules
            .map((r) => '[${r.sourceName}] ${r.text}')
            .join(' | ')
        : group.reason;

    return ListTile(
      dense: true,
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 2),
      onTap: () => showAggregatedGroupDetailDialog(
        context,
        group: group,
        onApplyException: (rule, {required confirmBroad}) =>
            _applyExceptionRule(
          rule,
          confirmBroad: confirmBroad,
          verifyHostOverride: group.domain,
        ),
      ),
      title: Row(
        children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1.5),
            decoration: BoxDecoration(
              color: badgeColor.withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(5),
            ),
            child: Text(
              protoLabel,
              style: TextStyle(
                fontSize: 10,
                fontWeight: FontWeight.bold,
                color: badgeColor,
              ),
            ),
          ),
          const SizedBox(width: 6),
          Expanded(
            child: Text(
              group.domain,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w500),
            ),
          ),
        ],
      ),
      subtitle: Text(
        '$hhmmss · $protoLabel · 重复 ${group.count} 次 · ${group.reason} · $ruleSummary',
        maxLines: 2,
        overflow: TextOverflow.ellipsis,
        style: TextStyle(fontSize: 11.5, color: colorScheme.onSurfaceVariant),
      ),
      trailing: _buildUnblockButton(
        group.domain,
        isUnblocked,
        isBusy,
        matchedRules: group.matchedRules,
      ),
    );
  }

  Widget _buildWebTroubleshootTab(ColorScheme colorScheme) {
    final blockedItems =
        _webDomains.where((e) => e.blocked && !_unblockedDomains.contains(e.domain)).toList();

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
          child: Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _urlController,
                  onSubmitted: (_) => _diagnoseWebpage(),
                  decoration: InputDecoration(
                    isDense: true,
                    prefixIcon: const Icon(Icons.link_rounded, size: 20),
                    hintText: '粘贴异常网页链接 (如 https://m997.lanzoue.com/…)',
                    suffixIcon: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        if (_urlController.text.isNotEmpty)
                          IconButton(
                            icon: const Icon(Icons.clear_rounded, size: 18),
                            onPressed: () => setState(() {
                              _urlController.clear();
                              _webDomains = [];
                              _webDiagnoseHint = null;
                            }),
                          ),
                        IconButton(
                          tooltip: '粘贴剪贴板链接',
                          icon: const Icon(
                            Icons.content_paste_rounded,
                            size: 18,
                          ),
                          onPressed: () async {
                            final data =
                                await Clipboard.getData(Clipboard.kTextPlain);
                            if (data?.text != null &&
                                data!.text!.trim().isNotEmpty) {
                              setState(() {
                                _urlController.text = data.text!.trim();
                              });
                              _diagnoseWebpage();
                            }
                          },
                        ),
                      ],
                    ),
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                    contentPadding: const EdgeInsets.symmetric(
                      vertical: 9,
                      horizontal: 12,
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              FilledButton(
                onPressed: _diagnosingWeb ? null : _diagnoseWebpage,
                style: FilledButton.styleFrom(
                  visualDensity: VisualDensity.compact,
                  padding: const EdgeInsets.symmetric(
                    horizontal: 14,
                    vertical: 10,
                  ),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
                child: _diagnosingWeb
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          color: Colors.white,
                        ),
                      )
                    : const Text('诊断'),
              ),
            ],
          ),
        ),
        if (_webDiagnoseHint != null)
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
            child: Text(
              _webDiagnoseHint!,
              style: TextStyle(
                fontSize: 12,
                color: colorScheme.onSurfaceVariant,
              ),
            ),
          ),
        if (blockedItems.length > 1)
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
            child: SizedBox(
              width: double.infinity,
              child: FilledButton.tonalIcon(
                onPressed: _batchUnblocking
                    ? null
                    : () => _unblockAllDomains(
                          blockedItems.map((e) => e.domain).toList(),
                        ),
                icon: const Icon(Icons.done_all_rounded, size: 18),
                label: Text(
                  _batchUnblocking
                      ? '正在放行…'
                      : '一键放行全部 ${blockedItems.length} 个被拦截依赖域名',
                ),
              ),
            ),
          ),
        const Divider(height: 1),
        Expanded(
          child: _diagnosingWeb
              ? const Center(child: CircularProgressIndicator())
              : _webDomains.isEmpty
                  ? Center(
                      child: Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 28),
                        child: Text(
                          '遇到网页打不开、按钮点击无反应（如蓝奏云外链 JS 被拦截）时：\n直接粘贴网址点击「诊断」，将自动抓取网页源码中引用的所有第三方静态资源/CDN 域名并检测哪一个被规则库拦截。',
                          textAlign: TextAlign.center,
                          style: TextStyle(
                            fontSize: 13,
                            height: 1.5,
                            color: colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ),
                    )
                  : ListView.separated(
                      physics: const BouncingScrollPhysics(),
                      itemCount: _webDomains.length,
                      separatorBuilder: (_, __) =>
                          const Divider(height: 1, indent: 16),
                      itemBuilder: (context, index) {
                        final item = _webDomains[index];
                        return _buildDiagnosedDomainTile(item, colorScheme);
                      },
                    ),
        ),
      ],
    );
  }

  Widget _buildAppTroubleshootTab(ColorScheme colorScheme) {
    if (_selectedApp == null) {
      final filteredApps = _installedApps.where((app) {
        if (_appSearchQuery.isEmpty) return true;
        final name = (app['name'] ?? '').toString().toLowerCase();
        final pkg = (app['package'] ?? '').toString().toLowerCase();
        return name.contains(_appSearchQuery) || pkg.contains(_appSearchQuery);
      }).toList();

      return Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
            child: TextField(
              controller: _appSearchController,
              decoration: InputDecoration(
                isDense: true,
                prefixIcon: const Icon(Icons.search_rounded, size: 20),
                hintText: '第一步：搜索并选择异常的应用名称或包名…',
                suffixIcon: _appSearchQuery.isNotEmpty
                    ? IconButton(
                        icon: const Icon(Icons.clear_rounded, size: 18),
                        onPressed: () => _appSearchController.clear(),
                      )
                    : null,
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                ),
                contentPadding: const EdgeInsets.symmetric(
                  vertical: 9,
                  horizontal: 12,
                ),
              ),
            ),
          ),
          const Divider(height: 1),
          Expanded(
            child: _loadingApps
                ? const Center(child: CircularProgressIndicator())
                : filteredApps.isEmpty
                    ? Center(
                        child: Text(
                          '未找到匹配应用',
                          style: TextStyle(
                            color: colorScheme.onSurfaceVariant,
                          ),
                        ),
                      )
                    : ListView.separated(
                        physics: const BouncingScrollPhysics(),
                        itemCount: filteredApps.length,
                        separatorBuilder: (_, __) =>
                            const Divider(height: 1, indent: 16),
                        itemBuilder: (context, index) {
                          final app = filteredApps[index];
                          final pkg = (app['package'] ?? '').toString();
                          final name = (app['name'] ?? pkg).toString();
                          final icon = app['icon'] as Uint8List?;
                          final isAllowlisted = _allowlistedApps.contains(pkg);

                          return ListTile(
                            dense: true,
                            leading: icon != null
                                ? ClipRRect(
                                    borderRadius: BorderRadius.circular(8),
                                    child: Image.memory(
                                      icon,
                                      width: 34,
                                      height: 34,
                                      fit: BoxFit.cover,
                                    ),
                                  )
                                : CircleAvatar(
                                    radius: 17,
                                    backgroundColor:
                                        colorScheme.primaryContainer,
                                    child: Icon(
                                      Icons.android_rounded,
                                      size: 18,
                                      color: colorScheme.onPrimaryContainer,
                                    ),
                                  ),
                            title: Row(
                              children: [
                                Flexible(
                                  child: Text(
                                    name,
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis,
                                    style: const TextStyle(
                                      fontSize: 14,
                                      fontWeight: FontWeight.w600,
                                    ),
                                  ),
                                ),
                                if (isAllowlisted) ...[
                                  const SizedBox(width: 6),
                                  Container(
                                    padding: const EdgeInsets.symmetric(
                                      horizontal: 5,
                                      vertical: 1,
                                    ),
                                    decoration: BoxDecoration(
                                      color:
                                          Colors.green.withValues(alpha: 0.14),
                                      borderRadius: BorderRadius.circular(4),
                                    ),
                                    child: const Text(
                                      '已在白名单',
                                      style: TextStyle(
                                        fontSize: 10,
                                        color: Colors.green,
                                        fontWeight: FontWeight.bold,
                                      ),
                                    ),
                                  ),
                                ],
                              ],
                            ),
                            subtitle: Text(
                              pkg,
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: TextStyle(
                                fontSize: 11.5,
                                color: colorScheme.onSurfaceVariant,
                              ),
                            ),
                            trailing: const Icon(
                              Icons.chevron_right_rounded,
                              size: 20,
                            ),
                            onTap: () {
                              HapticFeedback.selectionClick();
                              setState(() {
                                _selectedApp = app;
                                _capturedAppDomains = [];
                                _scannedAppDomains = [];
                              });
                              _scanSelectedAppDomains(app);
                            },
                          );
                        },
                      ),
          ),
        ],
      );
    }

    final app = _selectedApp!;
    final pkg = (app['package'] ?? '').toString();
    final name = (app['name'] ?? pkg).toString();
    final isAllowlisted = _allowlistedApps.contains(pkg);

    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 0, 12, 8),
          child: Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color:
                  colorScheme.surfaceContainerHighest.withValues(alpha: 0.45),
              borderRadius: BorderRadius.circular(14),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    InkWell(
                      borderRadius: BorderRadius.circular(8),
                      onTap: () => setState(() => _selectedApp = null),
                      child: const Padding(
                        padding: EdgeInsets.all(4),
                        child: Icon(Icons.arrow_back_rounded, size: 18),
                      ),
                    ),
                    const SizedBox(width: 6),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            name,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: const TextStyle(
                              fontSize: 14,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          Text(
                            pkg,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: TextStyle(
                              fontSize: 11,
                              color: colorScheme.onSurfaceVariant,
                            ),
                          ),
                        ],
                      ),
                    ),
                    TextButton(
                      onPressed: () => setState(() => _selectedApp = null),
                      style: TextButton.styleFrom(
                        visualDensity: VisualDensity.compact,
                      ),
                      child: const Text('更换应用', style: TextStyle(fontSize: 12)),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                Row(
                  children: [
                    Expanded(
                      child: FilledButton.icon(
                        onPressed: () => _startAppCapture(app),
                        icon: const Icon(Icons.play_arrow_rounded, size: 17),
                        label: const Text(
                          '清缓存并启动抓包',
                          style: TextStyle(fontSize: 12),
                        ),
                        style: FilledButton.styleFrom(
                          visualDensity: VisualDensity.compact,
                          padding: const EdgeInsets.symmetric(vertical: 8),
                        ),
                      ),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: FilledButton.tonalIcon(
                        onPressed: _togglingAllowlist
                            ? null
                            : () => _toggleSelectedAppAllowlist(app),
                        icon: Icon(
                          isAllowlisted
                              ? Icons.verified_user_rounded
                              : Icons.shield_outlined,
                          size: 16,
                        ),
                        label: Text(
                          isAllowlisted ? '已在全局白名单' : '加入全局白名单',
                          style: const TextStyle(fontSize: 12),
                        ),
                        style: FilledButton.styleFrom(
                          visualDensity: VisualDensity.compact,
                          padding: const EdgeInsets.symmetric(vertical: 8),
                        ),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
        const Divider(height: 1),
        Expanded(
          child: ListView(
            physics: const BouncingScrollPhysics(),
            children: [
              if (_capturedAppDomains.isNotEmpty) ...[
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 10, 16, 4),
                  child: Text(
                    '抓包复现期间触发的拦截域名 (${_capturedAppDomains.length})',
                    style: TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.bold,
                      color: colorScheme.primary,
                    ),
                  ),
                ),
                ..._capturedAppDomains.map(
                  (item) => _buildBlockedSummaryTile(item, colorScheme),
                ),
                const Divider(height: 12),
              ],
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 10, 16, 4),
                child: Row(
                  children: [
                    Expanded(
                      child: Text(
                        '应用本地配置/缓存域名扫描 (${_scannedAppDomains.length})',
                        style: TextStyle(
                          fontSize: 12,
                          fontWeight: FontWeight.bold,
                          color: colorScheme.primary,
                        ),
                      ),
                    ),
                    if (_scanningAppLocal)
                      const SizedBox(
                        width: 14,
                        height: 14,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    else
                      InkWell(
                        onTap: () => _scanSelectedAppDomains(app),
                        child: Text(
                          '重新扫描',
                          style: TextStyle(
                            fontSize: 12,
                            color: colorScheme.primary,
                          ),
                        ),
                      ),
                  ],
                ),
              ),
              if (!_scanningAppLocal && _scannedAppDomains.isEmpty)
                Padding(
                  padding: const EdgeInsets.all(20),
                  child: Text(
                    '未在该应用本地存储中扫描到明文域名。\n建议点击上方「清缓存并启动抓包」，在应用内操作复现问题后返回本页面，即可自动捕获刚刚被拦截的域名；或者直接点击「加入全局白名单」让该应用完全绕过拦截。',
                    style: TextStyle(
                      fontSize: 12.5,
                      height: 1.5,
                      color: colorScheme.onSurfaceVariant,
                    ),
                  ),
                )
              else
                ..._scannedAppDomains.map(
                  (item) => _buildDiagnosedDomainTile(item, colorScheme),
                ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildBlockedSummaryTile(
    _BlockedDomainSummary item,
    ColorScheme colorScheme,
  ) {
    final isUnblocked = _unblockedDomains.contains(item.domain);
    final isBusy = _unblockingInProgress.contains(item.domain);

    return ListTile(
      dense: true,
      contentPadding: const EdgeInsets.symmetric(
        horizontal: 16,
        vertical: 2,
      ),
      title: Row(
        children: [
          Container(
            padding: const EdgeInsets.symmetric(
              horizontal: 5,
              vertical: 1.5,
            ),
            decoration: BoxDecoration(
              color: (item.isSni ? Colors.purple : Colors.red)
                  .withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(5),
            ),
            child: Text(
              item.isSni ? 'SNI' : 'DNS',
              style: TextStyle(
                fontSize: 10,
                fontWeight: FontWeight.bold,
                color: item.isSni ? Colors.purple : Colors.red,
              ),
            ),
          ),
          if (item.isNewAfterCapture) ...[
            const SizedBox(width: 4),
            Container(
              padding: const EdgeInsets.symmetric(
                horizontal: 5,
                vertical: 1.5,
              ),
              decoration: BoxDecoration(
                color: Colors.deepOrange.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(5),
              ),
              child: const Text(
                '新触发',
                style: TextStyle(
                  fontSize: 10,
                  fontWeight: FontWeight.bold,
                  color: Colors.deepOrange,
                ),
              ),
            ),
          ],
          const SizedBox(width: 6),
          Expanded(
            child: Text(
              item.domain,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(
                fontSize: 14,
                fontWeight: FontWeight.w500,
              ),
            ),
          ),
        ],
      ),
      subtitle: Text(
        '${_formatRelativeTime(item.latestTime)} · ${item.count}次 · ${item.ruleText}',
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: TextStyle(
          fontSize: 11.5,
          color: colorScheme.onSurfaceVariant,
        ),
      ),
      trailing: _buildUnblockButton(
        item.domain,
        isUnblocked,
        isBusy,
        matchedRules: item.group?.matchedRules ?? const [],
      ),
    );
  }

  Widget _buildDiagnosedDomainTile(
    _DiagnosedDomainItem item,
    ColorScheme colorScheme,
  ) {
    final isUnblocked = _unblockedDomains.contains(item.domain);
    final isBusy = _unblockingInProgress.contains(item.domain);
    final effectiveBlocked = item.blocked && !isUnblocked;
    final badgeColor = item.isError
        ? Colors.orange.shade800
        : (effectiveBlocked ? Colors.red : Colors.green);
    final badgeText = item.isError
        ? '查询失败'
        : (effectiveBlocked ? '被拦截' : '正常');

    return ListTile(
      dense: true,
      contentPadding: const EdgeInsets.symmetric(
        horizontal: 16,
        vertical: 2,
      ),
      title: Row(
        children: [
          Container(
            padding: const EdgeInsets.symmetric(
              horizontal: 5,
              vertical: 1.5,
            ),
            decoration: BoxDecoration(
              color: badgeColor.withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(5),
            ),
            child: Text(
              badgeText,
              style: TextStyle(
                fontSize: 10,
                fontWeight: FontWeight.bold,
                color: badgeColor,
              ),
            ),
          ),
          const SizedBox(width: 6),
          Expanded(
            child: Text(
              item.domain,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                fontSize: 14,
                fontWeight:
                    effectiveBlocked ? FontWeight.bold : FontWeight.w500,
              ),
            ),
          ),
        ],
      ),
      subtitle: Text(
        item.ruleText.isNotEmpty
            ? '${item.reasonText} · ${item.ruleText}'
            : item.reasonText,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: TextStyle(
          fontSize: 11.5,
          color: item.isError
              ? Colors.orange.shade900
              : (effectiveBlocked ? Colors.red : colorScheme.onSurfaceVariant),
        ),
      ),
      trailing: (item.blocked || isUnblocked)
          ? _buildUnblockButton(
              item.domain,
              isUnblocked,
              isBusy,
              matchedRules: item.matchedRules,
            )
          : null,
    );
  }

  Widget _buildUnblockButton(
    String domain,
    bool isUnblocked,
    bool isBusy, {
    List<MatchedRuleInfo> matchedRules = const [],
  }) {
    return FilledButton.tonal(
      onPressed: isUnblocked || isBusy
          ? null
          : () => _unblockDomain(domain, matchedRules: matchedRules),
      style: FilledButton.styleFrom(
        visualDensity: VisualDensity.compact,
        padding: const EdgeInsets.symmetric(horizontal: 12),
      ),
      child: isBusy
          ? const SizedBox(
              width: 14,
              height: 14,
              child: CircularProgressIndicator(strokeWidth: 2),
            )
          : Text(
              isUnblocked ? '已放行' : '放行',
              style: const TextStyle(fontSize: 12),
            ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;

    return Container(
      height: MediaQuery.of(context).size.height * 0.85,
      decoration: BoxDecoration(
        color: colorScheme.surface,
        borderRadius: const BorderRadius.vertical(top: Radius.circular(24)),
      ),
      child: Column(
        children: [
          Center(
            child: Container(
              margin: const EdgeInsets.only(top: 10, bottom: 4),
              width: 36,
              height: 4,
              decoration: BoxDecoration(
                color: colorScheme.onSurfaceVariant.withValues(alpha: 0.4),
                borderRadius: BorderRadius.circular(2),
              ),
            ),
          ),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 2),
            child: Row(
              children: [
                IconButton(
                  icon: const Icon(Icons.close_rounded),
                  onPressed: () => Navigator.of(context).pop(),
                ),
                const SizedBox(width: 4),
                const Expanded(
                  child: Text(
                    '误杀排错中心',
                    style: TextStyle(
                      fontSize: 17,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
                IconButton(
                  icon: const Icon(Icons.refresh_rounded, size: 20),
                  tooltip: '刷新拦截记录',
                  onPressed: _fetchRecentBlocked,
                ),
              ],
            ),
          ),
          _buildModeSelector(colorScheme),
          Expanded(
            child: _activeTab == 0
                ? _buildRecentAndRuleSearchTab(colorScheme)
                : _activeTab == 1
                    ? _buildWebTroubleshootTab(colorScheme)
                    : _buildAppTroubleshootTab(colorScheme),
          ),
        ],
      ),
    );
  }
}
