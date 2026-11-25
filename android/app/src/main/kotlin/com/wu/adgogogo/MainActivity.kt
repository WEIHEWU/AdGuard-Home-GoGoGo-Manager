package com.wu.adgogogo

import android.app.LocaleManager
import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ComponentName
import android.content.ContentValues
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.Drawable
import android.os.Build
import android.os.Environment
import android.os.LocaleList
import android.os.SystemClock
import android.provider.MediaStore
import android.service.quicksettings.TileService
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.ByteArrayOutputStream
import java.io.File

class MainActivity: FlutterActivity() {
    private val channelName = "com.wu.adgogogo/locale"
    private val localNetworkChannelName = "com.wu.adgogogo/local_network"
    private val installedAppsChannelName = "com.wu.adgogogo/installed_apps"
    private val diagnosticsChannelName = "com.wu.adgogogo/diagnostics"

    // String literal on purpose: the constant only exists in API 37 SDK and
    // the project compiles with 36.
    private val localNetworkPermission = "android.permission.ACCESS_LOCAL_NETWORK"
    private val localNetworkRequestCode = 0x4C4E
    private var localNetworkResult: MethodChannel.Result? = null

    @Volatile
    private var cachedInstalledApps: List<Map<String, Any?>>? = null
    @Volatile
    private var cachedInstalledAppsIncludeSystem: Boolean = false
    @Volatile
    private var cachedInstalledAppsTimestamp: Long = 0L
    @Volatile
    private var lastTileSyncElapsedMs: Long = 0L

    override fun onStart() {
        super.onStart()
        val now = SystemClock.elapsedRealtime()
        if (lastTileSyncElapsedMs == 0L || now - lastTileSyncElapsedMs >= 15_000L) {
            lastTileSyncElapsedMs = now
            TileService.requestListeningState(
                this,
                ComponentName(this, AdGuardTileService::class.java)
            )
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            channelName
        ).setMethodCallHandler { call, result ->
            when (call.method) {
                "getApplicationLocale" -> result.success(getApplicationLocale())
                "setApplicationLocale" -> {
                    setApplicationLocale(call.argument<String>("tag"))
                    result.success(null)
                }
                else -> result.notImplemented()
            }
        }

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            localNetworkChannelName
        ).setMethodCallHandler { call, result ->
            when (call.method) {
                "isGranted" -> result.success(isLocalNetworkGranted())
                "request" -> requestLocalNetworkPermission(result)
                else -> result.notImplemented()
            }
        }

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            installedAppsChannelName
        ).setMethodCallHandler { call, result ->
            when (call.method) {
                "getInstalledApps" -> {
                    val includeSystem = call.argument<Boolean>("includeSystem") ?: false
                    val forceRefresh = call.argument<Boolean>("forceRefresh") ?: false
                    val now = System.currentTimeMillis()
                    val cached = cachedInstalledApps
                    if (!forceRefresh &&
                        cached != null &&
                        cachedInstalledAppsIncludeSystem == includeSystem &&
                        now - cachedInstalledAppsTimestamp < 60_000L
                    ) {
                        result.success(cached)
                        return@setMethodCallHandler
                    }
                    Thread {
                        try {
                            val apps = queryInstalledApps(includeSystem)
                            cachedInstalledApps = apps
                            cachedInstalledAppsIncludeSystem = includeSystem
                            cachedInstalledAppsTimestamp = System.currentTimeMillis()
                            runOnUiThread { result.success(apps) }
                        } catch (t: Throwable) {
                            runOnUiThread {
                                result.error("QUERY_APPS_FAILED", t.message, null)
                            }
                        }
                    }.start()
                }
                else -> result.notImplemented()
            }
        }

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            diagnosticsChannelName
        ).setMethodCallHandler { call, result ->
            when (call.method) {
                "getAppFilesDir" -> {
                    if (!filesDir.exists()) {
                        filesDir.mkdirs()
                    }
                    result.success(filesDir.absolutePath)
                }
                "getCacheDiagDir" -> {
                    val dir = File(cacheDir, "diag_bundles")
                    if (!dir.exists()) {
                        dir.mkdirs()
                    }
                    result.success(dir.absolutePath)
                }
                "getCacheBackupDir" -> {
                    val dir = File(cacheDir, "manual_backups")
                    if (!dir.exists()) {
                        dir.mkdirs()
                    }
                    result.success(dir.absolutePath)
                }
                "shareBackupFile" -> {
                    val filePath = call.argument<String>("filePath")
                    val title = call.argument<String>("title") ?: "Share Manual Rule Provenance Backup"
                    if (filePath.isNullOrBlank()) {
                        result.error("INVALID_ARG", "Missing filePath", null)
                        return@setMethodCallHandler
                    }
                    val backupDir = File(cacheDir, "manual_backups").canonicalFile
                    val targetFile = File(filePath).canonicalFile
                    if (!targetFile.exists() || !targetFile.isFile ||
                        !targetFile.path.startsWith(backupDir.path + File.separator)
                    ) {
                        result.error("INVALID_PATH", "Backup file not found in cache backup dir", null)
                        return@setMethodCallHandler
                    }
                    try {
                        val authority = "${applicationContext.packageName}.fileprovider"
                        val contentUri = FileProvider.getUriForFile(this, authority, targetFile)
                        val sendIntent = Intent(Intent.ACTION_SEND).apply {
                            type = "application/json"
                            putExtra(Intent.EXTRA_STREAM, contentUri)
                            clipData = ClipData.newRawUri("manual_rule_backup", contentUri)
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }
                        val chooser = Intent.createChooser(sendIntent, title).apply {
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }
                        startActivity(chooser)
                        result.success(true)
                    } catch (_: ActivityNotFoundException) {
                        result.success(false)
                    } catch (t: Throwable) {
                        result.error("SHARE_FAILED", t.message, null)
                    }
                }
                "shareDiagBundle" -> {
                    val filePath = call.argument<String>("filePath")
                    val title = call.argument<String>("title") ?: "Share Diagnostic Bundle"
                    if (filePath.isNullOrBlank()) {
                        result.error("INVALID_ARG", "Missing filePath", null)
                        return@setMethodCallHandler
                    }
                    val cacheDiagDir = File(cacheDir, "diag_bundles").canonicalFile
                    val targetFile = File(filePath).canonicalFile
                    if (!targetFile.exists() || !targetFile.isFile ||
                        !targetFile.path.startsWith(cacheDiagDir.path + File.separator)
                    ) {
                        result.error("INVALID_PATH", "Bundle file not found in cache diag dir", null)
                        return@setMethodCallHandler
                    }
                    try {
                        val authority = "${applicationContext.packageName}.fileprovider"
                        val contentUri = FileProvider.getUriForFile(this, authority, targetFile)
                        val sendIntent = Intent(Intent.ACTION_SEND).apply {
                            type = "application/zip"
                            putExtra(Intent.EXTRA_STREAM, contentUri)
                            clipData = ClipData.newRawUri("diagnostics", contentUri)
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }
                        val chooser = Intent.createChooser(sendIntent, title).apply {
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }
                        startActivity(chooser)
                        result.success(true)
                    } catch (_: ActivityNotFoundException) {
                        result.success(false)
                    } catch (t: Throwable) {
                        result.error("SHARE_FAILED", t.message, null)
                    }
                }
                "saveDiagBundleToDownloads" -> {
                    val filePath = call.argument<String>("filePath")
                    val requestedName = call.argument<String>("fileName")
                    if (filePath.isNullOrBlank()) {
                        result.error("INVALID_ARG", "Missing filePath", null)
                        return@setMethodCallHandler
                    }
                    val cacheDiagDir = File(cacheDir, "diag_bundles").canonicalFile
                    val targetFile = File(filePath).canonicalFile
                    if (!targetFile.exists() || !targetFile.isFile ||
                        !targetFile.path.startsWith(cacheDiagDir.path + File.separator)
                    ) {
                        result.error("INVALID_PATH", "Bundle file not found in cache diag dir", null)
                        return@setMethodCallHandler
                    }
                    val rawBase = File(
                        if (!requestedName.isNullOrBlank()) requestedName else targetFile.name
                    ).name
                    val safeName = if (rawBase.isBlank() || rawBase == "." || rawBase == "..") {
                        targetFile.name
                    } else if (rawBase.endsWith(".zip", ignoreCase = true)) {
                        rawBase
                    } else {
                        "$rawBase.zip"
                    }
                    Thread {
                        try {
                            val savedInfo = saveZipToDownloadsOrFallback(targetFile, safeName)
                            runOnUiThread { result.success(savedInfo) }
                        } catch (t: Throwable) {
                            runOnUiThread {
                                result.error("SAVE_FAILED", t.message, null)
                            }
                        }
                    }.start()
                }
                else -> result.notImplemented()
            }
        }
    }

    private fun saveZipToDownloadsOrFallback(sourceFile: File, fileName: String): Map<String, Any?> {
        // Android 10+ (API 29+): 直接通过 MediaStore.Downloads 写入系统公共 Download 目录，无需额外存储权限
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val resolver = contentResolver
            val values = ContentValues().apply {
                put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
                put(MediaStore.MediaColumns.MIME_TYPE, "application/zip")
                put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                put(MediaStore.MediaColumns.IS_PENDING, 1)
            }
            var itemUri: android.net.Uri? = null
            try {
                itemUri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                if (itemUri != null) {
                    val out = resolver.openOutputStream(itemUri)
                        ?: throw IllegalStateException("openOutputStream returned null")
                    out.use { output ->
                        sourceFile.inputStream().use { input ->
                            input.copyTo(output)
                        }
                        output.flush()
                    }
                    val publishValues = ContentValues().apply {
                        put(MediaStore.MediaColumns.IS_PENDING, 0)
                    }
                    resolver.update(itemUri, publishValues, null, null)
                    var actualName = fileName
                    resolver.query(
                        itemUri,
                        arrayOf(MediaStore.MediaColumns.DISPLAY_NAME),
                        null,
                        null,
                        null
                    )?.use { cursor ->
                        if (cursor.moveToFirst()) {
                            val col = cursor.getColumnIndex(MediaStore.MediaColumns.DISPLAY_NAME)
                            if (col >= 0) {
                                val queried = cursor.getString(col)
                                if (!queried.isNullOrBlank()) {
                                    actualName = queried
                                }
                            }
                        }
                    }
                    return mapOf(
                        "saved" to true,
                        "displayPath" to "${Environment.DIRECTORY_DOWNLOADS}/$actualName",
                        "isPublicDownload" to true
                    )
                }
            } catch (_: Throwable) {
                if (itemUri != null) {
                    try {
                        resolver.delete(itemUri, null, null)
                    } catch (_: Throwable) {}
                }
            }
        } else {
            // Android 9 及以下：尝试写入公共 Downloads 目录，失败则降级至应用私有目录
            try {
                @Suppress("DEPRECATION")
                val publicDownloads = Environment.getExternalStoragePublicDirectory(
                    Environment.DIRECTORY_DOWNLOADS
                )
                if (publicDownloads != null && (publicDownloads.exists() || publicDownloads.mkdirs())) {
                    val destFile = File(publicDownloads, fileName)
                    sourceFile.inputStream().use { input ->
                        destFile.outputStream().use { output ->
                            input.copyTo(output)
                            output.flush()
                        }
                    }
                    return mapOf(
                        "saved" to true,
                        "displayPath" to "${Environment.DIRECTORY_DOWNLOADS}/${destFile.name}",
                        "isPublicDownload" to true
                    )
                }
            } catch (_: Throwable) {}
        }

        // 公共 Download 写入失败时的应用私有目录兜底
        val fallbackDir = getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS)
            ?: File(filesDir, "Download")
        if (!fallbackDir.exists()) {
            fallbackDir.mkdirs()
        }
        val fallbackFile = File(fallbackDir, fileName)
        sourceFile.inputStream().use { input ->
            fallbackFile.outputStream().use { output ->
                input.copyTo(output)
                output.flush()
            }
        }
        return mapOf(
            "saved" to true,
            "displayPath" to fallbackFile.absolutePath,
            "isPublicDownload" to false
        )
    }

    private fun queryInstalledApps(includeSystem: Boolean): List<Map<String, Any?>> {
        val pm = packageManager
        val installed = pm.getInstalledApplications(0)
        val selfPkg = applicationContext.packageName
        val list = ArrayList<Map<String, Any?>>(installed.size)
        for (app in installed) {
            val pkg = app.packageName ?: continue
            if (pkg == selfPkg) continue
            val isSystem = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0 &&
                (app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0
            if (isSystem && !includeSystem) continue

            val label = try {
                pm.getApplicationLabel(app)?.toString()?.trim().takeUnless { it.isNullOrEmpty() } ?: pkg
            } catch (_: Throwable) {
                pkg
            }
            val iconBytes = try {
                drawableToPngBytes(pm.getApplicationIcon(app), 72)
            } catch (_: Throwable) {
                null
            }
            list.add(
                mapOf(
                    "package" to pkg,
                    "name" to label,
                    "uid" to app.uid,
                    "isSystem" to isSystem,
                    "icon" to iconBytes
                )
            )
        }
        return list
    }

    private fun drawableToPngBytes(drawable: Drawable, sizePx: Int): ByteArray? {
        val bitmap = Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)
        drawable.setBounds(0, 0, sizePx, sizePx)
        drawable.draw(canvas)
        val stream = ByteArrayOutputStream()
        bitmap.compress(Bitmap.CompressFormat.PNG, 90, stream)
        bitmap.recycle()
        return stream.toByteArray()
    }

    /** Local Network Protection is only enforced on Android 16+, and the
        ACCESS_LOCAL_NETWORK runtime permission only exists on Android 17+ for
        apps targeting SDK 37. Below that, INTERNET implicitly covers the LAN. */
    private fun isLocalNetworkGranted(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.BAKLAVA) return true
        return ContextCompat.checkSelfPermission(this, localNetworkPermission) ==
            PackageManager.PERMISSION_GRANTED
    }

    private fun requestLocalNetworkPermission(result: MethodChannel.Result) {
        if (isLocalNetworkGranted()) {
            result.success(true)
            return
        }
        localNetworkResult?.success(false)
        localNetworkResult = result
        ActivityCompat.requestPermissions(
            this, arrayOf(localNetworkPermission), localNetworkRequestCode
        )
    }

    override fun onRequestPermissionsResult(
        requestCode: Int, permissions: Array<out String>, grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == localNetworkRequestCode) {
            localNetworkResult?.success(
                grantResults.isNotEmpty() &&
                    grantResults[0] == PackageManager.PERMISSION_GRANTED
            )
            localNetworkResult = null
        }
    }

    private fun getApplicationLocale(): String? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return null

        val localeManager = getSystemService(LocaleManager::class.java) ?: return null
        val locales = localeManager.applicationLocales
        if (locales.isEmpty) return null
        return locales.get(0)?.toLanguageTag()
    }

    private fun setApplicationLocale(tag: String?) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return

        val localeManager = getSystemService(LocaleManager::class.java) ?: return
        localeManager.applicationLocales = if (tag.isNullOrEmpty()) {
            LocaleList.getEmptyLocaleList()
        } else {
            LocaleList.forLanguageTags(tag)
        }
    }
}
