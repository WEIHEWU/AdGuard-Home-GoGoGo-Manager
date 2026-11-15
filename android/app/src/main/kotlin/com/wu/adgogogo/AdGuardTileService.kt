package com.wu.adgogogo

import android.content.Context
import android.content.SharedPreferences
import android.graphics.drawable.Icon
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Base64
import android.util.Log
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

object AdGuardModuleController {
    private const val YAML_PATH = "/data/adb/agh/bin/AdGuardHome.yaml"
    private const val USER = "root"
    private const val PASSWORD = "root"
    private const val TAG = "AdGuardModule"
    private const val SU_PROBE_TIMEOUT_MS = 3000L
    private const val SU_CMD_TIMEOUT_MS = 8000L

    private val probeLock = Any()
    @Volatile
    private var cachedSuBin: String? = null
    private var inFlightProbe: InFlightSuProbe? = null

    private class InFlightSuProbe {
        val latch = CountDownLatch(1)
        val resultRef = AtomicReference<String?>(null)
    }

    fun readPort(context: Context? = null, forceYaml: Boolean = false): Int? {
        if (!forceYaml) {
            val saved = readSavedAddress(context)
            if (saved != null) return saved
        }

        val output = runSu("cat $YAML_PATH") ?: return null
        val port = parsePort(output)
        if (port != null && context != null) {
            saveAddress(context, port)
        }
        return port
    }

    private fun saveAddress(context: Context, port: Int) {
        try {
            val prefs: SharedPreferences = context.getSharedPreferences(
                "FlutterSharedPreferences",
                Context.MODE_PRIVATE
            )
            prefs.edit().putString("flutter.moduleHttpAddress", "127.0.0.1:$port").apply()
        } catch (t: Throwable) {
            Log.w(TAG, "save address failed", t)
        }
    }

    fun parsePort(output: String): Int? {
        val lines = output.lines()
        var inHttp = false
        for (line in lines) {
            val trimmed = line.trim()
            if (trimmed.startsWith("http:")) {
                inHttp = true
                continue
            }
            if (inHttp) {
                if (trimmed.isNotEmpty() && !line.startsWith(" ")) {
                    inHttp = false
                }
                if (inHttp && trimmed.startsWith("address:")) {
                    val value = trimmed.removePrefix("address:").trim()
                        .removePrefix("\"").removeSuffix("\"")
                        .removePrefix("'").removeSuffix("'")
                    return value.substringAfterLast(":", "").toIntOrNull()
                }
            }
        }
        return null
    }

    private fun readSavedAddress(context: Context?): Int? {
        if (context == null) return null
        return try {
            val prefs: SharedPreferences = context.getSharedPreferences(
                "FlutterSharedPreferences",
                Context.MODE_PRIVATE
            )
            val saved = prefs.getString("flutter.moduleHttpAddress", null) ?: return null
            val normalized = if (saved.contains("://")) saved else "http://$saved"
            val port = Uri.parse(normalized).port
            if (port > 0) port else null
        } catch (t: Throwable) {
            Log.e(TAG, "read saved address failed", t)
            null
        }
    }

    fun getProtectionState(port: Int): Boolean? {
        val body = httpRequest(port, "/control/status", "GET") ?: return null
        return try {
            val json = JSONObject(body)
            when {
                json.has("protection_enabled") -> json.getBoolean("protection_enabled")
                json.has("general_enabled") -> json.getBoolean("general_enabled")
                else -> null
            }
        } catch (t: Throwable) {
            Log.e(TAG, "parse status failed", t)
            null
        }
    }

    fun setProtection(port: Int, enabled: Boolean): Boolean {
        val body = """{"enabled":$enabled,"duration":null}"""
        val ok = httpRequest(port, "/control/protection", "POST", body) != null
        if (ok) {
            httpRequest(port, "/control/cache_clear", "POST", "")
            runSu("ndc resolver flushenv >/dev/null 2>&1 || cmd netd resolver flushdefaultif >/dev/null 2>&1")
        }
        return ok
    }

    private val defaultSuCandidates = listOf(
        "su",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/debug_ramdisk/su",
    )

    private fun terminateAndReap(process: Process) {
        try {
            process.destroy()
        } catch (_: Throwable) {
        }
        try {
            if (!process.waitFor(200, TimeUnit.MILLISECONDS)) {
                process.destroyForcibly()
                process.waitFor(500, TimeUnit.MILLISECONDS)
            }
        } catch (_: Throwable) {
            try {
                process.destroyForcibly()
            } catch (_: Throwable) {
            }
        }
    }

    private fun runBoundedProcess(
        commandArgs: List<String>,
        timeoutMs: Long,
        maxCaptureChars: Int = 8192
    ): Pair<Int, String>? {
        val process = try {
            ProcessBuilder(commandArgs)
                .redirectErrorStream(true)
                .start()
        } catch (_: Throwable) {
            return null
        }

        val outputBuilder = StringBuilder()
        val readerThread = Thread {
            try {
                process.inputStream.bufferedReader().use { reader ->
                    val buf = CharArray(512)
                    var read: Int
                    while (reader.read(buf).also { read = it } != -1) {
                        if (outputBuilder.length < maxCaptureChars) {
                            val allow = (maxCaptureChars - outputBuilder.length).coerceAtMost(read)
                            outputBuilder.append(buf, 0, allow)
                        }
                    }
                }
            } catch (_: Throwable) {
            }
        }.apply {
            isDaemon = true
            start()
        }

        val finished = try {
            process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        } catch (_: Throwable) {
            false
        }

        if (!finished) {
            terminateAndReap(process)
            try {
                readerThread.join(100)
            } catch (_: Throwable) {
            }
            return null
        }

        try {
            readerThread.join(200)
        } catch (_: Throwable) {
        }
        val exitCode = try {
            process.exitValue()
        } catch (_: Throwable) {
            -1
        }
        return Pair(exitCode, outputBuilder.toString())
    }

    private fun resolveSuBin(forceRefresh: Boolean = false, excludeSu: String? = null): String? {
        while (true) {
            var existingProbe: InFlightSuProbe? = null
            var ownProbe: InFlightSuProbe? = null
            var initialCandidate: String? = null

            synchronized(probeLock) {
                val current = cachedSuBin
                if (!forceRefresh && current != null && current != excludeSu) {
                    return current
                }
                if (inFlightProbe != null) {
                    existingProbe = inFlightProbe
                } else {
                    if (forceRefresh) {
                        cachedSuBin = null
                    }
                    initialCandidate = current
                    ownProbe = InFlightSuProbe()
                    inFlightProbe = ownProbe
                }
            }

            if (existingProbe != null) {
                try {
                    existingProbe!!.latch.await(
                        SU_PROBE_TIMEOUT_MS * defaultSuCandidates.size + 1000L,
                        TimeUnit.MILLISECONDS
                    )
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return null
                }
                val res = existingProbe!!.resultRef.get()
                if (!forceRefresh && res != null && res != excludeSu) {
                    return res
                }
                if (forceRefresh && res != null && res != excludeSu) {
                    val snapshot = synchronized(probeLock) { cachedSuBin }
                    if (snapshot == res) {
                        return res
                    }
                }
                continue
            }

            val myProbe = ownProbe!!
            try {
                val candidates = if (initialCandidate != null) {
                    listOf(initialCandidate!!) + defaultSuCandidates.filter { it != initialCandidate }
                } else {
                    defaultSuCandidates
                }
                var found: String? = null
                for (su in candidates) {
                    if (su == excludeSu) continue
                    val probeRes = runBoundedProcess(
                        listOf(su, "-c", "id -u"),
                        SU_PROBE_TIMEOUT_MS,
                        maxCaptureChars = 256
                    )
                    if (probeRes != null &&
                        probeRes.first == 0 &&
                        probeRes.second.lineSequence().firstOrNull()?.trim() == "0"
                    ) {
                        found = su
                        break
                    }
                }
                myProbe.resultRef.set(found)
                synchronized(probeLock) {
                    cachedSuBin = found
                }
                return found
            } finally {
                myProbe.latch.countDown()
                synchronized(probeLock) {
                    if (inFlightProbe === myProbe) {
                        inFlightProbe = null
                    }
                }
            }
        }
    }

    private fun runSu(command: String): String? {
        var su = resolveSuBin() ?: return null
        var res = runBoundedProcess(listOf(su, "-c", command), SU_CMD_TIMEOUT_MS)
        if (res == null) {
            Log.w(TAG, "su($su) failed or timed out, re-probing")
            su = resolveSuBin(forceRefresh = true, excludeSu = su) ?: return null
            res = runBoundedProcess(listOf(su, "-c", command), SU_CMD_TIMEOUT_MS) ?: return null
        }
        return if (res.first == 0) {
            res.second
        } else {
            val detail = res.second.trim().take(200)
            Log.w(TAG, "su($su) exit=${res.first}${if (detail.isEmpty()) "" else " | $detail"}")
            null
        }
    }

    private fun httpRequest(port: Int, path: String, method: String, body: String? = null): String? {
        val connection = URL("http://127.0.0.1:$port$path").openConnection() as HttpURLConnection
        return try {
            connection.requestMethod = method
            connection.connectTimeout = 5000
            connection.readTimeout = 5000
            val credentials = Base64.encodeToString(
                "$USER:$PASSWORD".toByteArray(Charsets.UTF_8),
                Base64.NO_WRAP
            )
            connection.setRequestProperty("Authorization", "Basic $credentials")
            if (body != null) {
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            }
            val code = connection.responseCode
            if (code < 400) {
                connection.inputStream.bufferedReader().use { it.readText() }
            } else {
                val errorBody = connection.errorStream?.bufferedReader()?.use { it.readText() }?.take(200)
                Log.w(TAG, "http $method $path status=$code${if (errorBody.isNullOrEmpty()) "" else " | $errorBody"}")
                null
            }
        } catch (t: Throwable) {
            Log.e(TAG, "http $method $path failed", t)
            null
        } finally {
            connection.disconnect()
        }
    }
}

class AdGuardTileService : TileService() {
    private val mainHandler = Handler(Looper.getMainLooper())
    @Volatile
    private var listening = false
    private val listenGeneration = AtomicInteger(0)
    private val toggleInFlight = AtomicBoolean(false)
    @Volatile
    private var pendingRetryRunnable: Runnable? = null

    override fun onTileAdded() {
        super.onTileAdded()
        TileService.requestListeningState(
            this,
            android.content.ComponentName(this, AdGuardTileService::class.java)
        )
        updateTileDirect(Tile.STATE_INACTIVE)
    }

    override fun onClick() {
        super.onClick()
        if (qsTile == null) return
        if (!toggleInFlight.compareAndSet(false, true)) {
            Log.i("AdGuardTile", "onClick ignored: toggle already in flight")
            return
        }

        Thread {
            try {
                var port = AdGuardModuleController.readPort(this)
                if (port == null) {
                    updateTileDirect(Tile.STATE_INACTIVE)
                    openManager()
                    return@Thread
                }
                var current = AdGuardModuleController.getProtectionState(port)
                if (current == null) {
                    val freshPort = AdGuardModuleController.readPort(this, forceYaml = true)
                    if (freshPort != null && freshPort != port) {
                        port = freshPort
                        current = AdGuardModuleController.getProtectionState(port)
                    }
                }
                if (current == null) {
                    Log.w("AdGuardTile", "toggle aborted: unable to read current state on port=$port")
                    updateTileDirect(Tile.STATE_INACTIVE)
                    openManager()
                    return@Thread
                }

                val target = !current
                val setOk = AdGuardModuleController.setProtection(port, target)
                val confirmedState = if (setOk) {
                    AdGuardModuleController.getProtectionState(port)
                } else {
                    null
                }

                if (setOk && confirmedState == target) {
                    Log.i("AdGuardTile", "toggle confirmed: port=$port state=$confirmedState")
                    updateTileDirect(if (confirmedState) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE)
                } else {
                    Log.w(
                        "AdGuardTile",
                        "toggle failed or unconfirmed: port=$port target=$target setOk=$setOk confirmed=$confirmedState"
                    )
                    val fallbackTileState = when (confirmedState) {
                        true -> Tile.STATE_ACTIVE
                        false -> Tile.STATE_INACTIVE
                        null -> Tile.STATE_INACTIVE
                    }
                    updateTileDirect(fallbackTileState)
                    openManager()
                }
            } catch (t: Throwable) {
                Log.e("AdGuardTile", "toggle failed", t)
                updateTileDirect(Tile.STATE_INACTIVE)
                openManager()
            } finally {
                toggleInFlight.set(false)
            }
        }.start()
    }

    override fun onStartListening() {
        super.onStartListening()
        listening = true
        cancelPendingRetry()
        val gen = listenGeneration.incrementAndGet()
        refreshTile(0, gen)
    }

    override fun onStopListening() {
        listening = false
        listenGeneration.incrementAndGet()
        cancelPendingRetry()
        super.onStopListening()
    }

    private fun cancelPendingRetry() {
        val r = pendingRetryRunnable
        if (r != null) {
            mainHandler.removeCallbacks(r)
            pendingRetryRunnable = null
        }
    }

    private fun isGenerationActive(generation: Int): Boolean {
        return listening && listenGeneration.get() == generation
    }

    private fun refreshTile(attempt: Int, generation: Int) {
        if (!isGenerationActive(generation)) return
        Thread {
            try {
                var port = AdGuardModuleController.readPort(this)
                if (!isGenerationActive(generation)) return@Thread
                if (port == null) {
                    Log.w("AdGuardTile", "listening: no port (su/yaml failed), attempt=$attempt")
                    updateTileForGeneration(Tile.STATE_INACTIVE, generation)
                    scheduleRetry(attempt, generation)
                    return@Thread
                }
                var enabled = AdGuardModuleController.getProtectionState(port)
                if (!isGenerationActive(generation)) return@Thread
                if (enabled == null) {
                    val freshPort = AdGuardModuleController.readPort(this, forceYaml = true)
                    if (!isGenerationActive(generation)) return@Thread
                    if (freshPort != null && freshPort != port) {
                        port = freshPort
                        enabled = AdGuardModuleController.getProtectionState(port)
                        if (!isGenerationActive(generation)) return@Thread
                    }
                }
                val state = when (enabled) {
                    true -> Tile.STATE_ACTIVE
                    false -> Tile.STATE_INACTIVE
                    null -> Tile.STATE_INACTIVE
                }
                Log.i("AdGuardTile", "listening: port=$port enabled=$enabled state=$state")
                updateTileForGeneration(state, generation)
                if (enabled == null) scheduleRetry(attempt, generation)
            } catch (t: Throwable) {
                Log.e("AdGuardTile", "refresh failed", t)
                if (isGenerationActive(generation)) {
                    updateTileForGeneration(Tile.STATE_INACTIVE, generation)
                    scheduleRetry(attempt, generation)
                }
            }
        }.start()
    }

    private fun scheduleRetry(attempt: Int, generation: Int) {
        if (attempt >= 5 || !isGenerationActive(generation)) return
        cancelPendingRetry()
        val runnable = Runnable {
            pendingRetryRunnable = null
            if (isGenerationActive(generation)) {
                refreshTile(attempt + 1, generation)
            }
        }
        pendingRetryRunnable = runnable
        mainHandler.postDelayed(runnable, 3000)
    }

    private fun openManager() {
        mainHandler.post {
            try {
                val intent = android.content.Intent(this, MainActivity::class.java).apply {
                    addFlags(
                        android.content.Intent.FLAG_ACTIVITY_NEW_TASK or
                            android.content.Intent.FLAG_ACTIVITY_CLEAR_TOP
                    )
                }
                startActivityAndCollapse(intent)
            } catch (t: Throwable) {
                Log.e("AdGuardTile", "open manager failed", t)
            }
        }
    }

    private fun updateTileForGeneration(state: Int, generation: Int) {
        if (!isGenerationActive(generation)) return
        mainHandler.post {
            try {
                if (!isGenerationActive(generation)) return@post
                val tile = qsTile ?: return@post
                tile.state = state
                tile.label = getString(R.string.tile_label)
                tile.icon = Icon.createWithResource(this, R.drawable.ic_tile_adguard)
                tile.updateTile()
            } catch (t: Throwable) {
                Log.e("AdGuardTile", "update tile failed", t)
            }
        }
    }

    private fun updateTileDirect(state: Int) {
        mainHandler.post {
            try {
                val tile = qsTile ?: return@post
                tile.state = state
                tile.label = getString(R.string.tile_label)
                tile.icon = Icon.createWithResource(this, R.drawable.ic_tile_adguard)
                tile.updateTile()
            } catch (t: Throwable) {
                Log.e("AdGuardTile", "update tile failed", t)
            }
        }
    }
}
