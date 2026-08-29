package com.panxcz.injector

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.PixelFormat
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.view.*
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import java.io.BufferedReader
import java.io.File
import java.io.FileOutputStream
import java.io.InputStreamReader

class MainActivity : AppCompatActivity() {

    private lateinit var processList: ListView
    private lateinit var statusText: TextView
    private lateinit var injectBtn: Button
    private lateinit var refreshBtn: Button
    private lateinit var floatingBtn: Button
    private lateinit var menuBtn: Button

    private data class ProcessInfo(val pid: Int, val packageName: String, val cmdline: String)
    private var processes = mutableListOf<ProcessInfo>()
    private var selectedPid = -1
    private var soPath = "/data/local/tmp/libTool.so"
    private var injectorPath = "/data/local/tmp/panxcz_injector"

    // Elaina theme colors
    companion object {
        const val ELAINA_PURPLE = "#FF9B59B6"
        const val ELAINA_PINK = "#FFC39BD3"
        const val ELAINA_DARK = "#FF1A1A2E"
        const val ELAINA_DEEP = "#FF16213E"
        const val ELAINA_ACCENT = "#FFE8DAEF"
        const val ELAINA_MAGIC = "#FFBB8FCE"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        processList = findViewById(R.id.processList)
        statusText = findViewById(R.id.statusText)
        injectBtn = findViewById(R.id.injectBtn)
        refreshBtn = findViewById(R.id.refreshBtn)
        floatingBtn = findViewById(R.id.floatingBtn)
        menuBtn = findViewById(R.id.menuBtn)

        setupElainaTheme()
        extractBinaries()
        requestOverlayPermission()

        statusText.text = "Welcome to Panxcz Injector! Tap Refresh to scan processes."

        refreshBtn.setOnClickListener { refreshProcesses() }
        injectBtn.setOnClickListener {
            if (selectedPid <= 0) {
                statusText.text = "Select a process first!"
                return@setOnClickListener
            }
            injectToProcess(selectedPid)
        }
        floatingBtn.setOnClickListener {
            startFloatingService()
        }
        menuBtn.setOnClickListener {
            showToolMenu()
        }

        processList.setOnItemClickListener { _, _, position, _ ->
            selectedPid = processes[position].pid
            statusText.text = "Selected: PID $selectedPid (${processes[position].packageName})"
            injectBtn.isEnabled = true
        }

        refreshProcesses()
    }

    private fun setupElainaTheme() {
        // Set status bar color
        window.statusBarColor = android.graphics.Color.parseColor(ELAINA_DEEP)
        window.navigationBarColor = android.graphics.Color.parseColor(ELAINA_DEEP)

        // Style buttons with gradient
        listOf(injectBtn, refreshBtn, floatingBtn, menuBtn).forEach { btn ->
            val bg = GradientDrawable().apply {
                shape = GradientDrawable.RECTANGLE
                cornerRadius = 24f
                setColor(android.graphics.Color.parseColor(ELAINA_PURPLE))
            }
            btn.background = bg
        }
    }

    private fun extractBinaries() {
        Thread {
            try {
                // Extract injector binary from native build
                val injectorFile = File(injectorPath)
                if (!injectorFile.exists()) {
                    // Try to copy from assets
                    try {
                        assets.open("injector").use { input ->
                            FileOutputStream(injectorFile).use { output ->
                                input.copyTo(output)
                            }
                        }
                    } catch (_: Exception) {}
                }

                // Copy libTool.so from assets
                val libFile = File(soPath)
                try {
                    assets.open("libTool.so").use { input ->
                        FileOutputStream(libFile).use { output ->
                            input.copyTo(output)
                        }
                    }
                } catch (_: Exception) {}

                // Set permissions
                Runtime.getRuntime().exec(arrayOf("su", "-c", "chmod 777 $injectorPath $soPath")).waitFor()

                runOnUiThread {
                    statusText.text = "Binaries ready. Tap Refresh to scan processes."
                }
            } catch (e: Exception) {
                runOnUiThread {
                    statusText.text = "Error: ${e.message}"
                }
            }
        }.start()
    }

    private fun requestOverlayPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (!Settings.canDrawOverlays(this)) {
                val intent = Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                    Uri.parse("package:$packageName"))
                startActivity(intent)
            }
        }
    }

    private fun refreshProcesses() {
        statusText.text = "Scanning processes..."
        Thread {
            try {
                val procs = mutableListOf<ProcessInfo>()
                val procDir = File("/proc")
                procDir.listFiles()?.forEach { dir ->
                    val name = dir.name
                    if (name.all { it.isDigit() }) {
                        val pid = name.toIntOrNull() ?: return@forEach
                        if (pid <= 0) return@forEach
                        val cmdline = try {
                            File("/proc/$pid/cmdline").readText().trim('\u0000')
                        } catch (_: Exception) { return@forEach }
                        if (cmdline.isEmpty()) return@forEach
                        val pkg = getPackageName(pid)
                        if (pkg.isNotEmpty()) {
                            procs.add(ProcessInfo(pid, pkg, cmdline))
                        }
                    }
                }
                runOnUiThread {
                    processes.clear()
                    procs.sortBy { it.packageName }
                    processes.addAll(procs)
                    val adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1,
                        procs.map { "PID ${it.pid} - ${it.packageName}" })
                    processList.adapter = adapter
                    statusText.text = "Found ${procs.size} app processes. Select one to inject."
                    injectBtn.isEnabled = false
                    selectedPid = -1
                }
            } catch (e: Exception) {
                runOnUiThread { statusText.text = "Error: ${e.message}" }
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

    private fun injectToProcess(pid: Int) {
        statusText.text = "Injecting into PID $pid..."
        injectBtn.isEnabled = false
        Thread {
            try {
                val process = Runtime.getRuntime().exec(
                    arrayOf("su", "-c", "$injectorPath $pid $soPath"))
                val output = process.inputStream.bufferedReader().readText()
                val errors = process.errorStream.bufferedReader().readText()
                process.waitFor()
                runOnUiThread {
                    statusText.text = if (process.exitValue() == 0) {
                        "Injection successful!\n$output"
                    } else {
                        "Failed:\n$errors\n$output"
                    }
                    injectBtn.isEnabled = true
                }
            } catch (e: Exception) {
                runOnUiThread {
                    statusText.text = "Error: ${e.message}"
                    injectBtn.isEnabled = true
                }
            }
        }.start()
    }

    private fun startFloatingService() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !Settings.canDrawOverlays(this)) {
            statusText.text = "Overlay permission required!"
            requestOverlayPermission()
            return
        }
        statusText.text = "Floating overlay activated!"
        // Show floating icon
        val wm = getSystemService(WINDOW_SERVICE) as WindowManager
        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
            else
                WindowManager.LayoutParams.TYPE_PHONE,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
            PixelFormat.TRANSLUCENT
        )
        params.gravity = Gravity.TOP or Gravity.START
        params.x = 0
        params.y = 200

        val floatingView = layoutInflater.inflate(R.layout.floating_icon, null)
        val icon = floatingView.findViewById<ImageView>(R.id.floatingIcon)

        var offsetX = 0
        var offsetY = 0
        var initialX = 0
        var initialY = 0
        var initialTouchX = 0f
        var initialTouchY = 0f

        floatingView.setOnTouchListener { _, event ->
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
                    wm.updateViewLayout(floatingView, params)
                    true
                }
                MotionEvent.ACTION_UP -> {
                    val dx = Math.abs(event.rawX - initialTouchX)
                    val dy = Math.abs(event.rawY - initialTouchY)
                    if (dx < 10 && dy < 10) {
                        showToolMenu()
                    }
                    true
                }
                else -> false
            }
        }

        try {
            wm.addView(floatingView, params)
            statusText.text = "Floating icon active! Tap to open tools."
        } catch (e: Exception) {
            statusText.text = "Failed to add floating icon: ${e.message}"
        }
    }

    private fun showToolMenu() {
        val dialog = android.app.AlertDialog.Builder(this, R.style.ElainaDialog)
            .setTitle("Panxcz Tool Menu")
            .setItems(arrayOf(
                "IL2CPP Dumper",
                "String Explorer",
                "Method Tracer",
                "Memory Patcher",
                "Frida Scripts",
                "Class Viewer",
                "Settings",
                "About"
            )) { _, which ->
                when (which) {
                    0 -> statusText.text = "IL2CPP Dumper - Use injector to load libTool.so into game"
                    1 -> statusText.text = "String Explorer - Available in ImGui overlay"
                    2 -> statusText.text = "Method Tracer - Available in ImGui overlay"
                    3 -> statusText.text = "Memory Patcher - Available in ImGui overlay"
                    4 -> statusText.text = "Frida Scripts - Available in ImGui overlay"
                    5 -> statusText.text = "Class Viewer - Available in ImGui overlay"
                    6 -> statusText.text = "Settings - Available in ImGui overlay"
                    7 -> statusText.text = "Panxcz Injector v1.0\nBy Panxcz & Freebuff\nElaina Theme"
                }
            }
            .create()
        dialog.show()
    }

    override fun onDestroy() {
        super.onDestroy()
        // Cleanup floating view if needed
    }
}
