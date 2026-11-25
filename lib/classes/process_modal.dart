import 'package:adguard_home_manager/config/globals.dart';
import 'package:flutter/material.dart';

import 'package:adguard_home_manager/widgets/process_dialog.dart';

class ProcessModal {
  BuildContext? _dialogContext;
  bool _closed = false;

  void open(String message) async {
    _closed = false;
    await Future.delayed(const Duration(seconds: 0), () {
      final navCtx = globalNavigatorKey.currentContext;
      if (_closed || navCtx == null || !navCtx.mounted) return;
      showDialog(
        context: navCtx,
        builder: (ctx) {
          _dialogContext = ctx;
          return ProcessDialog(
            message: message,
          );
        },
        barrierDismissible: false,
        useSafeArea: true,
      );
    });
  }

  void close() {
    _closed = true;
    final ctx = _dialogContext;
    _dialogContext = null;
    if (ctx != null && ctx.mounted) {
      Navigator.of(ctx).pop();
    }
  }
}