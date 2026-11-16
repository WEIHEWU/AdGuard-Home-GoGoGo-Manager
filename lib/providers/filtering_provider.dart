import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';

import 'package:adguard_home_manager/constants/enums.dart';
import 'package:adguard_home_manager/models/filtering.dart';
import 'package:adguard_home_manager/models/server.dart';
import 'package:adguard_home_manager/providers/servers_provider.dart';
import 'package:adguard_home_manager/providers/status_provider.dart';
import 'package:adguard_home_manager/services/host_rule_diagnostics.dart';
import 'package:adguard_home_manager/services/manual_rule_provenance_service.dart';
import 'package:adguard_home_manager/services/module_config_service.dart';

enum FilteringListActions { edit, enable, disable }

class RuleMutationResult {
  final bool ok;
  final bool conflictDetected;
  final bool provenanceSaveFailed;
  final bool duplicateAmbiguous;
  final bool readbackFailed;
  final int addedCount;
  final int removedCount;
  final String? message;

  const RuleMutationResult({
    required this.ok,
    this.conflictDetected = false,
    this.provenanceSaveFailed = false,
    this.duplicateAmbiguous = false,
    this.readbackFailed = false,
    this.addedCount = 0,
    this.removedCount = 0,
    this.message,
  });
}

class FilteringProvider with ChangeNotifier {
  final ManualRuleProvenanceService _provenanceService;

  FilteringProvider({
    ManualRuleProvenanceService? provenanceService,
  }) : _provenanceService =
            provenanceService ?? ManualRuleProvenanceService.instance;

  StatusProvider? _statusProvider;
  ServersProvider? _serversProvider;

  void update(ServersProvider? servers, StatusProvider? status) {
    _serversProvider = servers;
    _statusProvider = status;
  }

  LoadStatus _loadStatus = LoadStatus.loading;
  Filtering? _filtering;
  Future<bool>? _inFlightFetch;

  LoadStatus get loadStatus {
    return _loadStatus;
  }

  Filtering? get filtering {
    return _filtering;
  }

  void setFilteringProtectionStatus(bool status, bool notify) {
    _statusProvider!.setFilteringEnabledStatus(status);
    _filtering!.enabled = status;
    if (notify == true) notifyListeners();
  }

  void setFiltersUpdateFrequency(int frequency) {
    if (_filtering != null) {
      _filtering!.interval = frequency;
      notifyListeners();
    }
  }

  Future<bool> fetchFilters({bool? showLoading}) async {
    if (_inFlightFetch != null) {
      return _inFlightFetch!;
    }
    if (showLoading == true && _filtering == null) {
      _loadStatus = LoadStatus.loading;
    }

    final future = _doFetchFilters();
    _inFlightFetch = future;
    try {
      return await future;
    } finally {
      _inFlightFetch = null;
    }
  }

  Future<void> _syncProvenanceWith(Server server, List<String> coreRules) async {
    await _provenanceService.syncWithCoreRules(
      serverKey: ServerRuleWriteQueue.serverKeyFor(server),
      coreRules: coreRules,
    );
  }

  Future<bool> _doFetchFilters() async {
    final api = _serversProvider?.apiClient2;
    if (api == null) {
      if (_filtering == null) {
        _loadStatus = LoadStatus.error;
        notifyListeners();
      }
      return false;
    }
    final result = await api.getFiltering();
    if (result.successful == true) {
      _filtering = result.content as Filtering;
      _loadStatus = LoadStatus.loaded;
      await _syncProvenanceWith(api.server, _filtering!.userRules);
      notifyListeners();
      return true;
    } else {
      if (_filtering == null) {
        _loadStatus = LoadStatus.error;
      }
      notifyListeners();
      return false;
    }
  }

  Future<Map<String, dynamic>> updateLists() async {
    final api = _serversProvider?.apiClient2;
    if (api == null) {
      notifyListeners();
      return {"success": false};
    }

    final prevRules = <int, int>{};
    final prevUpdated = <int, DateTime?>{};
    if (_filtering != null) {
      for (final f in [..._filtering!.filters, ..._filtering!.whitelistFilters]) {
        prevRules[f.id] = f.rulesCount;
        prevUpdated[f.id] = f.lastUpdated;
      }
    }

    final result = await api.updateLists();
    final result2 = await api.getFiltering();

    int changedListsCount = 0;
    if (result2.successful == true) {
      final latest = result2.content as Filtering;
      for (final f in [...latest.filters, ...latest.whitelistFilters]) {
        final oldRules = prevRules[f.id];
        final oldTime = prevUpdated[f.id];
        final rulesChanged = oldRules != null && oldRules != f.rulesCount;
        final timeAdvanced = f.lastUpdated != null &&
            (oldTime == null || f.lastUpdated!.isAfter(oldTime));
        if (rulesChanged) {
          changedListsCount++;
        } else if (!result.successful && timeAdvanced) {
          changedListsCount++;
        }
      }
      _filtering = latest;
      _loadStatus = LoadStatus.loaded;
    }

    if (_statusProvider != null) {
      unawaited(_statusProvider!.getServerStatus(withLoadingIndicator: false));
    }
    notifyListeners();

    if (result.successful == true) {
      final reported = (result.content is Map && result.content['updated'] is int)
          ? result.content['updated'] as int
          : 0;
      final effectiveUpdated =
          reported > 0 ? reported : (changedListsCount > 0 ? changedListsCount : 0);
      return {
        "success": true,
        "data": {"updated": effectiveUpdated},
      };
    }

    if (result2.successful == true && changedListsCount > 0) {
      return {
        "success": true,
        "data": {"updated": changedListsCount},
      };
    }

    return {"success": false};
  }

  Future<bool> enableDisableFiltering() async {
    final newValue = !_statusProvider!.serverStatus!.filteringEnabled;
    final result =
        await _serversProvider!.apiClient2!.updateFiltering(enable: newValue);
    if (result.successful == true) {
      setFilteringProtectionStatus(newValue, false);
      notifyListeners();
      return true;
    } else {
      notifyListeners();
      return false;
    }
  }

  Future<bool> changeUpdateFrequency(int value) async {
    final result = await _serversProvider!.apiClient2!
        .requestChangeUpdateFrequency(
            data: {"enabled": filtering!.enabled, "interval": value});
    if (result.successful == true) {
      setFiltersUpdateFrequency(value);
      return true;
    } else {
      notifyListeners();
      return false;
    }
  }

  void _flushDnsCaches() {
    if (_serversProvider?.apiClient2 != null) {
      unawaited(_serversProvider!.apiClient2!.resetDnsCache());
    }
    if (Platform.isAndroid) {
      unawaited(ModuleConfigService().flushSystemDnsCache());
    }
  }

  Future<RuleMutationResult> _mutateCustomRulesOnServer(
    List<String> Function(List<String> currentRules) transform, {
    String? explicitExpectedRevision,
    required String entryPoint,
    String? refuseDuplicateRemoveRule,
  }) async {
    final api = _serversProvider?.apiClient2;
    if (api == null) {
      return const RuleMutationResult(ok: false, message: '未连接服务器');
    }

    return ServerRuleWriteQueue.run(api.server, (session) async {
      // 轮到本服务器写队列时重新拉取最新规则与 revision，避免基于排队前快照盲写覆盖
      final beforeRes = await api.getFiltering();
      if (beforeRes.successful != true || beforeRes.content is! Filtering) {
        notifyListeners();
        return const RuleMutationResult(
          ok: false,
          message: '读取当前自定义规则失败，未修改任何规则',
        );
      }
      final latestFiltering = beforeRes.content as Filtering;
      final beforeRules = List<String>.from(latestFiltering.userRules);

      if (refuseDuplicateRemoveRule != null) {
        final target = refuseDuplicateRemoveRule.trim();
        final count = beforeRules.where((r) => r.trim() == target).length;
        if (count == 0) {
          await _syncProvenanceWith(api.server, beforeRules);
          _filtering = latestFiltering;
          notifyListeners();
          return const RuleMutationResult(
            ok: false,
            message: '该规则已不在 Core 自定义规则列表中，已同步本地状态',
          );
        }
        if (count > 1) {
          await _syncProvenanceWith(api.server, beforeRules);
          _filtering = latestFiltering;
          notifyListeners();
          return RuleMutationResult(
            ok: false,
            duplicateAmbiguous: true,
            message:
                '存在重复规则（Core 中共 $count 条相同文本），归属未确认，已拒绝按索引猜测删除；请前往批量规则编辑器确认具体行后再处理',
          );
        }
      }

      final expectedRev =
          explicitExpectedRevision ?? latestFiltering.userRulesRevision;
      final newRules = transform(List<String>.from(beforeRules));

      final result = await api.setCustomRules(
        rules: newRules,
        expectedRevision: expectedRev,
      );

      if (result.successful == true) {
        session.bumpLocalEpoch();
        // 优先回读最新状态与更新后的 revision，确保本地视图与服务端一致；
        // 只有回读成功确认内容，才把变更记入本地手动来源库。
        final afterRes = await api.getFiltering();
        if (afterRes.successful == true && afterRes.content is Filtering) {
          final confirmedFiltering = afterRes.content as Filtering;
          _filtering = confirmedFiltering;
          final afterRules = List<String>.from(confirmedFiltering.userRules);
          final diff = RuleListDiffResult.diff(beforeRules, afterRules);

          final saved = await _provenanceService.applyRuleListMutationDiff(
            serverKey: session.serverKey,
            rulesBefore: beforeRules,
            rulesAfter: afterRules,
            entryPoint: entryPoint,
            confirmedRevision: result.userRulesRevisionHeader ??
                confirmedFiltering.userRulesRevision,
          );
          _flushDnsCaches();
          notifyListeners();
          final addedTotal = diff.addedCounts.values.fold(0, (a, b) => a + b);
          final removedTotal =
              diff.removedCounts.values.fold(0, (a, b) => a + b);
          return RuleMutationResult(
            ok: true,
            provenanceSaveFailed: !saved,
            addedCount: addedTotal,
            removedCount: removedTotal,
            message: saved ? null : '规则已添加，但来源记录保存失败。',
          );
        } else {
          final filteringData = _filtering ?? latestFiltering;
          filteringData.userRules = newRules;
          _filtering = filteringData;
          _flushDnsCaches();
          notifyListeners();
          return const RuleMutationResult(
            ok: true,
            readbackFailed: true,
            message: '规则已提交，但回读确认 Core 状态失败，暂未写入已确认来源记录',
          );
        }
      } else {
        if (result.statusCode == 409) {
          final refreshed = await api.getFiltering();
          if (refreshed.successful == true && refreshed.content is Filtering) {
            _filtering = refreshed.content as Filtering;
            await _syncProvenanceWith(api.server, _filtering!.userRules);
          }
          notifyListeners();
          return const RuleMutationResult(
            ok: false,
            conflictDetected: true,
            message: '检测到其他客户端同时修改了自定义规则（版本冲突），已重新读取最新列表，请确认后重试',
          );
        }
        notifyListeners();
        return const RuleMutationResult(
          ok: false,
          message: '提交自定义规则失败，请重试',
        );
      }
    });
  }

  Future<RuleMutationResult> removeCustomRuleDetailed(
    String rule, {
    bool refuseDuplicateRemoval = true,
  }) {
    final target = rule.trim();
    return _mutateCustomRulesOnServer(
      (current) => current.where((r) => r.trim() != target).toList(),
      entryPoint: '手动移除规则',
      refuseDuplicateRemoveRule: refuseDuplicateRemoval ? target : null,
    );
  }

  Future<bool> removeCustomRule(String rule) async {
    final res = await removeCustomRuleDetailed(rule);
    return res.ok;
  }

  Future<bool> deleteList(
      {required String listUrl, required String type}) async {
    final result1 = await _serversProvider!.apiClient2!.deleteFilterList(data: {
      "url": listUrl,
      "whitelist": type == 'whitelist' ? true : false
    });

    if (result1.successful == true) {
      final result2 = await _serversProvider!.apiClient2!.getFiltering();

      if (result2.successful == true) {
        _filtering = result2.content as Filtering;
        notifyListeners();
        return true;
      } else {
        notifyListeners();
        return false;
      }
    } else {
      notifyListeners();
      return false;
    }
  }

  Future<bool> updateList(
      {required Filter list,
      required String type,
      required FilteringListActions action}) async {
    final result1 = await _serversProvider!.apiClient2!.updateFilterList(data: {
      "data": {
        "enabled": action == FilteringListActions.disable ||
                action == FilteringListActions.enable
            ? !list.enabled
            : list.enabled,
        "name": list.name,
        "url": list.url
      },
      "url": list.url,
      "whitelist": type == 'whitelist' ? true : false
    });

    if (result1.successful == true) {
      final result2 = await _serversProvider!.apiClient2!.getFiltering();

      if (result2.successful == true) {
        _filtering = result2.content as Filtering;
        notifyListeners();
        return true;
      } else {
        notifyListeners();
        return false;
      }
    } else {
      notifyListeners();
      return false;
    }
  }

  Future<RuleMutationResult> addCustomRuleDetailed(
    String rule, {
    String entryPoint = '自定义规则-单条添加',
  }) {
    final String trimmed = rule.trim();
    if (trimmed.isEmpty) {
      return Future.value(
        const RuleMutationResult(ok: false, message: '规则内容为空'),
      );
    }
    final Set<String> toRemove = {trimmed};
    final cls = RuleClassification.classify(trimmed);
    if (cls.action == ManualRuleAction.allow && cls.extractableHost != null) {
      final host = cls.extractableHost!;
      toRemove.addAll({
        '||$host^',
        '||$host^\$important',
        '@@||$host^',
        '@@||$host^\$important',
      });
    } else if (cls.action == ManualRuleAction.block &&
        cls.extractableHost != null) {
      final host = cls.extractableHost!;
      toRemove.addAll({
        '||$host^',
        '||$host^\$important',
        '@@||$host^',
        '@@||$host^\$important',
      });
    }
    return _mutateCustomRulesOnServer(
      (current) {
        final newRules =
            current.where((r) => !toRemove.contains(r.trim())).toList();
        newRules.add(trimmed);
        return newRules;
      },
      entryPoint: entryPoint,
    );
  }

  Future<bool> addCustomRule(String rule) async {
    final res = await addCustomRuleDetailed(rule);
    return res.ok;
  }

  Future<RuleMutationResult> setCustomRulesDetailed(
    List<String> rules, {
    String? expectedRevision,
    String entryPoint = '自定义规则-批量编辑',
  }) {
    final newRules = rules
        .map((r) => r.trim())
        .where((r) => r.isNotEmpty)
        .toList();
    return _mutateCustomRulesOnServer(
      (_) => newRules,
      explicitExpectedRevision: expectedRevision,
      entryPoint: entryPoint,
    );
  }

  Future<bool> setCustomRules(
    List<String> rules, {
    String? expectedRevision,
  }) async {
    final res = await setCustomRulesDetailed(
      rules,
      expectedRevision: expectedRevision,
    );
    return res.ok;
  }

  /// 主动认领当前 Core 中已存在但“来源未记录/来源未确认”的自定义规则（写入 source=claimed，createdAt=null）。
  Future<bool> claimExistingCustomRule(
    String rule, {
    String entryPoint = '自定义规则-主动认领',
    String? note,
  }) async {
    final api = _serversProvider?.apiClient2;
    final latest = _filtering;
    if (api == null || latest == null) return false;
    final ok = await _provenanceService.claimExistingRule(
      serverKey: ServerRuleWriteQueue.serverKeyFor(api.server),
      ruleText: rule,
      latestCoreRules: latest.userRules,
      entryPoint: entryPoint,
      confirmedRevision: latest.userRulesRevision,
      note: note,
    );
    if (ok) notifyListeners();
    return ok;
  }

  Future<Map<String, dynamic>> addList(
      {required String name, required String url, required String type}) async {
    final result1 = await _serversProvider!.apiClient2!.addFilteringList(data: {
      'name': name,
      'url': url,
      'whitelist': type == 'whitelist' ? true : false
    });

    if (result1.successful == true) {
      if (result1.content.toString().contains("OK")) {
        final result2 = await _serversProvider!.apiClient2!.getFiltering();
        final items = result1.content.toString().split(' ')[1];

        if (result2.successful == true) {
          _filtering = result2.content as Filtering;
          notifyListeners();
          return {'success': true, 'data': items};
        } else {
          notifyListeners();
          return {'success': false, 'error': null};
        }
      } else {
        notifyListeners();
        return {'success': false, 'error': null};
      }
    } else if (result1.successful == false &&
        result1.statusCode == 400 &&
        result1.content.toString().contains("data is HTML, not plain text")) {
      notifyListeners();
      return {'success': false, 'error': 'invalid_url'};
    } else if (result1.successful == false &&
        result1.statusCode == 400 &&
        result1.content.toString().contains('url already exists')) {
      notifyListeners();
      return {'success': false, 'error': 'url_exists'};
    } else {
      notifyListeners();
      return {'success': false, 'error': null};
    }
  }

  Future<List<ProcessedList>> deleteMultipleLists(
      {required List<Filter> blacklists,
      required List<Filter> whitelists}) async {
    Future<ProcessedList> deleteList({
      required Filter list,
      required bool isWhitelist,
    }) async {
      final result = await _serversProvider!.apiClient2!
          .deleteFilterList(data: {"url": list.url, "whitelist": isWhitelist});
      if (result.successful == true) {
        return ProcessedList(list: list, successful: true);
      } else {
        return ProcessedList(list: list, successful: false);
      }
    }

    final resultWhitelists = await Future.wait(
        whitelists.map((e) => deleteList(list: e, isWhitelist: true)));
    final resultBlacklists = await Future.wait(
        blacklists.map((e) => deleteList(list: e, isWhitelist: false)));

    await fetchFilters();

    return [
      ...resultWhitelists,
      ...resultBlacklists,
    ];
  }

  Future<List<ProcessedList>> enableDisableMultipleLists(
      {required List<Filter> blacklists,
      required List<Filter> whitelists}) async {
    Future<ProcessedList> enableDisableList({
      required Filter list,
      required bool isWhitelist,
    }) async {
      final result =
          await _serversProvider!.apiClient2!.updateFilterList(data: {
        "data": {"enabled": !list.enabled, "name": list.name, "url": list.url},
        "url": list.url,
        "whitelist": isWhitelist
      });
      if (result.successful == true) {
        return ProcessedList(list: list, successful: true);
      } else {
        return ProcessedList(list: list, successful: false);
      }
    }

    final resultWhitelists = await Future.wait(
        whitelists.map((e) => enableDisableList(list: e, isWhitelist: true)));
    final resultBlacklists = await Future.wait(
        blacklists.map((e) => enableDisableList(list: e, isWhitelist: false)));

    await fetchFilters();

    return [
      ...resultWhitelists,
      ...resultBlacklists,
    ];
  }
}
