package com.panxcz.injector

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.PixelFormat
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.view.*
import android.widget.*
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

class FloatingService : Service() {

    private lateinit var windowManager: WindowManager
    private val handler = Handler(Looper.getMainLooper())
    private var floatingView: View? = null
    private var isShowingDialog = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        windowManager = getSystemService(WINDOW_SERVICE) as WindowManager
        startForegroundIfNeeded()
        createFloatingIcon()
    }

    private fun startForegroundIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel("panxcz_overlay", "Panxcz Overlay", NotificationManager.IMPORTANCE_LOW)
            channel.description = "Floating overlay service"
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(channel)
        }
        val notification = Notification.Builder(this, "panxcz_overlay")
            .setSmallIcon(android.R.drawable.ic_menu_info_details)
            .setContentTitle("Panxcz Injector")
            .setContentText("Floating overlay active")
            .build()
        startForeground(1, notification)
    }

    @SuppressLint("ClickableViewAccessibility")
    private fun createFloatingIcon() {
        floatingView = LayoutInflater.from(this).inflate(R.layout.floating_icon, null)

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
            else WindowManager.LayoutParams.TYPE_PHONE,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
            PixelFormat.TRANSLUCENT
        ).apply { gravity = Gravity.TOP or Gravity.START; x = 0; y = 300 }

        var ix = 0; var iy = 0; var tx = 0f; var ty = 0f
        floatingView?.setOnTouchListener { _, e ->
            when (e.action) {
                MotionEvent.ACTION_DOWN -> { ix = params.x; iy = params.y; tx = e.rawX; ty = e.rawY; true }
                MotionEvent.ACTION_MOVE -> { params.x = ix + (e.rawX - tx).toInt(); params.y = iy + (e.rawY - ty).toInt(); windowManager.updateViewLayout(floatingView, params); true }
                MotionEvent.ACTION_UP -> {
                    if (Math.abs(e.rawX - tx) < 10 && Math.abs(e.rawY - ty) < 10) showProcessList()
                    true
                }
                else -> false
            }
        }
        windowManager.addView(floatingView, params)
    }

    /**
     * Batch scan: ONE su shell gets all PIDs + cmdlines.
     * Matches cmdline against installed packages from PackageManager.
     */
    private fun showProcessList() {
        if (isShowingDialog) return
        isShowingDialog = true
        Thread {
            val procs = mutableListOf<Pair<Int, String>>()

            // Get all installed packages
            val installedPkgs = mutableSetOf<String>()
            try {
                val pm = packageManager
                val apps = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getInstalledApplications(PackageManager.GET_META_DATA)
                } else {
                    @Suppress("DEPRECATION") pm.getInstalledApplications(0)
                }
                for (app in apps) {
                    if (app.packageName.isNotEmpty()) installedPkgs.add(app.packageName)
                }
            } catch (_: Exception) {}

            // Single su batch scan — use $$ to escape Kotlin $ interpolation in shell vars
            try {
                val shellScript = """
                    for pid_dir in /proc/[0-9]*; do
                        p=$(basename "$$pid_dir")
                        cmd=$(cat "$$pid_dir/cmdline" 2>/dev/null | tr '\0' ' ' | head -c 200)
                        if [ -n "$$cmd" ]; then
                            echo "$$p|$$cmd"
                        fi
                    done
                """.trimIndent()

                val proc = Runtime.getRuntime().exec(arrayOf("su", "-c", shellScript))
                val reader = BufferedReader(InputStreamReader(proc.inputStream))
                reader.useLines { lines ->
                    for (line in lines) {
                        val trimmed = line.trim()
                        if (trimmed.isEmpty()) continue
                        val pipeIdx = trimmed.indexOf('|')
                        if (pipeIdx < 0) continue
                        val pidStr = trimmed.substring(0, pipeIdx)
                        val cmdline = trimmed.substring(pipeIdx + 1).trim()
                        val pid = pidStr.toIntOrNull() ?: continue
                        if (pid <= 0 || pid == android.os.Process.myPid()) continue

                        var pkgName = ""
                        for (pkg in installedPkgs) {
                            if (cmdline.contains(pkg)) { pkgName = pkg; break }
                        }
                        if (pkgName.isEmpty()) {
                            if (cmdline.startsWith("/system/") || cmdline.startsWith("[")) continue
                            pkgName = cmdline.substring(0, minOf(cmdline.length, 60))
                        }
                        procs.add(pid to pkgName)
                    }
                }
                proc.waitFor()
            } catch (_: Exception) {
                // Fallback without root
                File("/proc").listFiles()?.forEach { dir ->
                    val n = dir.name; if (!n.all { it.isDigit() }) return@forEach
                    val pid = n.toIntOrNull() ?: return@forEach; if (pid <= 0 || pid == android.os.Process.myPid()) return@forEach
                    val cmd = try { File("/proc/$pid/cmdline").readText().trim('\u0000') } catch (_: Exception) { return@forEach }
                    if (cmd.isEmpty()) return@forEach
                    var pkgName = ""
                    for (pkg in installedPkgs) {
                        if (cmd.contains(pkg)) { pkgName = pkg; break }
                    }
                    if (pkgName.isEmpty()) {
                        if (cmd.startsWith("/system/") || cmd.startsWith("[")) return@forEach
                        pkgName = cmd.substring(0, minOf(cmd.length, 60))
                    }
                    procs.add(pid to pkgName)
                }
            }

            procs.sortWith(compareBy<Pair<Int, String>> {
                if (it.second.contains('.')) 0 else 1
            }.thenBy { it.second })

            handler.post {
                if (procs.isEmpty()) {
                    isShowingDialog = false
                    Toast.makeText(this, "No game processes found", Toast.LENGTH_SHORT).show()
                    return@post
                }
                val items = procs.map { "PID ${it.first} — ${it.second}" }.toTypedArray()
                val builder = android.app.AlertDialog.Builder(this, R.style.ElainaDialog)
                    .setTitle("Select Game")
                    .setItems(items) { _, w -> injectProcess(procs[w].first, procs[w].second) }
                    .setNegativeButton("Cancel") { _, _ -> isShowingDialog = false }
                    .setOnDismissListener { isShowingDialog = false }
                builder.create().show()
            }
        }.start()
    }

    private fun injectProcess(pid: Int, pkg: String) {
        Toast.makeText(this, "Injecting into $pkg...", Toast.LENGTH_SHORT).show()
        Thread {
            try {
                val libAsset = try { assets.open("libTool.so") } catch (_: Exception) { null }
                if (libAsset != null) {
                    val f = File("/data/local/tmp/libTool.so"); f.outputStream().use { o -> libAsset.use { it.copyTo(o) } }
                    Runtime.getRuntime().exec(arrayOf("su", "-c", "chmod 777 /data/local/tmp/libTool.so")).waitFor()
                }
                val proc = Runtime.getRuntime().exec(arrayOf("su", "-c", "/data/local/tmp/panxcz_injector $pid /data/local/tmp/libTool.so"))
                val out = proc.inputStream.bufferedReader().readText(); proc.waitFor()
                handler.post {
                    Toast.makeText(this, if (proc.exitValue() == 0) "Injected! Open $pkg for overlay" else "Failed: $out", Toast.LENGTH_LONG).show()
                }
            } catch (e: Exception) { handler.post { Toast.makeText(this, "Error: ${e.message}", Toast.LENGTH_LONG).show() } }
        }.start()
    }

    override fun onDestroy() { super.onDestroy(); floatingView?.let { windowManager.removeView(it) } }
}
