import 'package:flutter/material.dart';
import 'package:adguard_home_manager/l10n/app_localizations.dart';


class RemoveCustomRule extends StatelessWidget {
  final void Function() onConfirm;
  final String? ruleText;
  final String? impactSummary;

  const RemoveCustomRule({
    super.key,
    required this.onConfirm,
    this.ruleText,
    this.impactSummary,
  });

  @override
  Widget build(BuildContext context) {
    final cleanRule = ruleText?.trim() ?? '';
    return AlertDialog(
      title: Column(
        children: [
          Icon(
            Icons.shield_rounded,
            size: 24,
            color: Theme.of(context).listTileTheme.iconColor
          ),
          const SizedBox(height: 16),
          Text(
            AppLocalizations.of(context)!.removeCustomRule,
            textAlign: TextAlign.center,
            style: TextStyle(
              color: Theme.of(context).colorScheme.onSurface
            ),
          )
        ],
      ),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            AppLocalizations.of(context)!.removeCustomRuleMessage,
            style: TextStyle(
              color: Theme.of(context).colorScheme.onSurface
            ),
          ),
          if (cleanRule.isNotEmpty) ...[
            const SizedBox(height: 12),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(8),
              ),
              child: SelectableText(
                cleanRule,
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 12.5,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
          ],
          if (impactSummary != null && impactSummary!.trim().isNotEmpty) ...[
            const SizedBox(height: 10),
            Text(
              '移除影响：${impactSummary!.trim()}',
              style: TextStyle(
                fontSize: 12.5,
                color: Theme.of(context).colorScheme.error,
              ),
            ),
          ],
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context), 
          child: Text(AppLocalizations.of(context)!.cancel)
        ),
        TextButton(
          onPressed: () {
            onConfirm();
            Navigator.pop(context);
          }, 
          child: Text(AppLocalizations.of(context)!.confirm)
        ),
      ],
    );
  }
}