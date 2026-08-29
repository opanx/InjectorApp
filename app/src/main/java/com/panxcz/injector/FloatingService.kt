package com.panxcz.injector

import android.annotation.SuppressLint
import android.app.Service
import android.content.Intent
import android.graphics.PixelFormat
import android.os.Build
import android.os.IBinder
import android.view.*
import android.widget.*
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

class FloatingService : Service() {

    private lateinit var windowManager: WindowManager
    private var floatingView: View? = null
    private var processDialog: AlertDialog? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        windowManager = getSystemService(WINDOW_SERVICE) as WindowManager
        createFloatingIcon()
    }

    @SuppressLint("ClickableViewAccessibility")
    private fun createFloatingIcon() {
        val inflater = LayoutInflater.from(this)
        floatingView = inflater.inflate(R.layout.floating_icon, null)

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
            else
                WindowManager.LayoutParams.TYPE_PHONE,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.START
            x = 0
            y = 300
        }

        var initialX = 0
        var initialY = 0
        var initialTouchX = 0f
        var initialTouchY = 0f

        floatingView?.setOnTouchListener { _, event ->
            when (event.action) {
                MotionEvent.ACTION_DOWN -> {
                    initialX = params.x
                    initialY = params.y
                    initialTouchX = event.rawX
                    initialTouchY = event.rawY
                    true
                }
                MotionEvent.ACTION_MOVE -> {
                    params.x = initialX + (event.rawX - initialTouchX).toInt()
                    params.y = initialY + (event.rawY - initialTouchY).toInt()
                    windowManager.updateViewLayout(floatingView, params)
                    true
                }
                MotionEvent.ACTION_UP -> {
                    if (Math.abs(event.rawX - initialTouchX) < 10 &&
                        Math.abs(event.rawY - initialTouchY) < 10) {
                        showProcessList()
                    }
                    true
                }
                else -> false
            }
        }

        windowManager.addView(floatingView, params)
    }

    @SuppressLint("WrongConstant")
    private fun showProcessList() {
        Thread {
            val procs = mutableListOf<Pair<Int, String>>()
            File("/proc").listFiles()?.forEach { dir ->
                val name = dir.name
                if (name.all { it.isDigit() }) {
                    val pid = name.toIntOrNull() ?: return@forEach
                    if (pid <= 0) return@forEach
                    val cmdline = try {
                        File("/proc/$pid/cmdline").readText().trim('\u0000')
                    } catch (_: Exception) { return@forEach }
                    if (cmdline.isEmpty()) return@forEach
                    val pkg = getPackageName(pid)
                    if (pkg.isNotEmpty()) procs.add(pid to pkg)
                }
            }
            procs.sortBy { it.second }

            runOnUiThread {
                val items = procs.map { "PID ${it.first} - ${it.second}" }.toTypedArray()
                processDialog = AlertDialog.Builder(this, R.style.ElainaDialog)
                    .setTitle("Select Game Process")
                    .setItems(items) { _, which ->
                        val (pid, pkg) = procs[which]
                        injectProcess(pid, pkg)
                    }
                    .setNegativeButton("Cancel", null)
                    .create()
                processDialog?.show()
            }
        }.start()
    }

    private fun getPackageName(pid: Int): String {
        return try {
            val p = Runtime.getRuntime().exec(arrayOf("su", "-c", "cat /proc/$pid/maps"))
            val reader = BufferedReader(InputStreamReader(p.inputStream))
            var pkg = ""
            reader.useLines { lines ->
                for (line in lines) {
                    val idx = line.indexOf("/data/app/")
                    if (idx >= 0) {
                        val rest = line.substring(idx + 10)
                        val dash = rest.lastIndexOf('-')
                        if (dash > 0) pkg = rest.substring(0, dash)
                        return@useLines
                    }
                }
            }
            p.waitFor()
            pkg
        } catch (_: Exception) { "" }
    }

    private fun injectProcess(pid: Int, pkg: String) {
        Toast.makeText(this, "Injecting into $pkg (PID $pid)...", Toast.LENGTH_SHORT).show()
        Thread {
            try {
                // First copy libTool.so to /data/local/tmp/
                val libAsset = try { assets.open("libTool.so") } catch (_: Exception) { null }
                if (libAsset != null) {
                    val outFile = File("/data/local/tmp/libTool.so")
                    outFile.outputStream().use { out -> libAsset.use { it.copyTo(out) } }
                    Runtime.getRuntime().exec(arrayOf("su", "-c", "chmod 777 /data/local/tmp/libTool.so")).waitFor()
                }

                // Run injector
                val proc = Runtime.getRuntime().exec(
                    arrayOf("su", "-c", "/data/local/tmp/panxcz_injector $pid /data/local/tmp/libTool.so"))
                val output = proc.inputStream.bufferedReader().readText()
                proc.waitFor()

                runOnUiThread {
                    if (proc.exitValue() == 0) {
                        Toast.makeText(this, "Injected! ImGui overlay should appear in $pkg", Toast.LENGTH_LONG).show()
                    } else {
                        Toast.makeText(this, "Injection failed: $output", Toast.LENGTH_LONG).show()
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    Toast.makeText(this, "Error: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }.start()
    }

    override fun onDestroy() {
        super.onDestroy()
        floatingView?.let { windowManager.removeView(it) }
    }
}
