package com.panxcz.injector

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
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
    private lateinit var overlayBtn: Button

    private data class ProcessInfo(val pid: Int, val packageName: String)
    private var processes = mutableListOf<ProcessInfo>()
    private var selectedPid = -1
    private var soPath = "/data/local/tmp/libTool.so"
    private var injectorPath = "/data/local/tmp/panxcz_injector"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        processList = findViewById(R.id.processList)
        statusText = findViewById(R.id.statusText)
        injectBtn = findViewById(R.id.injectBtn)
        refreshBtn = findViewById(R.id.refreshBtn)
        overlayBtn = findViewById(R.id.overlayBtn)

        applyTheme()
        extractBinaries()
        checkPermissions()

        refreshBtn.setOnClickListener { refreshProcesses() }
        injectBtn.setOnClickListener {
            if (selectedPid <= 0) { statusText.text = "Select a process first!"; return@setOnClickListener }
            injectToProcess(selectedPid)
        }
        overlayBtn.setOnClickListener { startOverlay() }

        processList.setOnItemClickListener { _, _, position, _ ->
            selectedPid = processes[position].pid
            statusText.text = "Selected: PID $selectedPid (${processes[position].packageName})"
            injectBtn.isEnabled = true
        }

        refreshProcesses()
    }

    private fun applyTheme() {
        window.statusBarColor = android.graphics.Color.parseColor("#FF1A1A2E")
        window.navigationBarColor = android.graphics.Color.parseColor("#FF1A1A2E")
        listOf(injectBtn, refreshBtn, overlayBtn).forEach { btn ->
            btn.background = GradientDrawable().apply {
                shape = GradientDrawable.RECTANGLE
                cornerRadius = 24f
                setColor(android.graphics.Color.parseColor("#FF9B59B6"))
            }
        }
    }

    private fun checkPermissions() {
        // Root check
        Thread {
            try {
                val p = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
                val output = p.inputStream.bufferedReader().readText()
                p.waitFor()
                runOnUiThread {
                    if (p.exitValue() == 0 && output.contains("uid=0")) {
                        statusText.text = "Root OK. Extracting binaries..."
                    } else {
                        statusText.text = "ROOT REQUIRED! Install Magisk/KSU first."
                    }
                }
            } catch (_: Exception) {
                runOnUiThread { statusText.text = "ROOT REQUIRED! Install Magisk/KSU first." }
            }
        }.start()

        // Overlay permission
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !Settings.canDrawOverlays(this)) {
            startActivity(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:$packageName")))
        }
    }

    private fun extractBinaries() {
        Thread {
            var msgs = mutableListOf<String>()
            try {
                // 1) Extract injector from assets (built by CMake as executable)
                try {
                    assets.open("injector").use { input ->
                        FileOutputStream(File(injectorPath)).use { output -> input.copyTo(output) }
                    }
                    msgs.add("injector: OK")
                } catch (_: Exception) {
                    msgs.add("injector: not in assets")
                }

                // 2) Copy libTool.so from assets
                try {
                    assets.open("libTool.so").use { input ->
                        FileOutputStream(File(soPath)).use { output -> input.copyTo(output) }
                    }
                    msgs.add("libTool.so: OK")
                } catch (_: Exception) {
                    msgs.add("libTool.so: not in assets")
                }

                // 3) chmod via su
                try {
                    Runtime.getRuntime().exec(arrayOf("su", "-c", "chmod 777 $injectorPath $soPath")).waitFor()
                } catch (_: Exception) {}

                val inj = File(injectorPath)
                val injOk = inj.exists() && inj.length() > 0
                runOnUiThread {
                    statusText.text = if (injOk) "Binaries ready (${msgs.joinToString()}). Tap Refresh."
                    else "Warning: ${msgs.joinToString()}. Injector not found."
                }
            } catch (e: Exception) {
                runOnUiThread { statusText.text = "Extract error: ${e.message}" }
            }
        }.start()
    }

    private fun refreshProcesses() {
        statusText.text = "Scanning processes..."
        Thread {
            val procs = mutableListOf<ProcessInfo>()
            File("/proc").listFiles()?.forEach { dir ->
                val name = dir.name
                if (name.all { it.isDigit() }) {
                    val pid = name.toIntOrNull() ?: return@forEach
                    if (pid <= 0) return@forEach
                    val cmdline = try { File("/proc/$pid/cmdline").readText().trim('\u0000') } catch (_: Exception) { return@forEach }
                    if (cmdline.isEmpty()) return@forEach
                    val pkg = getPackageName(pid)
                    if (pkg.isNotEmpty()) procs.add(ProcessInfo(pid, pkg))
                }
            }
            runOnUiThread {
                processes.clear()
                procs.sortBy { it.packageName }
                processes.addAll(procs)
                processList.adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1,
                    procs.map { "PID ${it.pid} - ${it.packageName}" })
                statusText.text = "Found ${procs.size} apps. Select one to inject."
                injectBtn.isEnabled = false
                selectedPid = -1
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
                val proc = Runtime.getRuntime().exec(
                    arrayOf("su", "-c", "$injectorPath $pid $soPath"))
                val output = proc.inputStream.bufferedReader().readText()
                val errors = proc.errorStream.bufferedReader().readText()
                proc.waitFor()
                runOnUiThread {
                    statusText.text = if (proc.exitValue() == 0) {
                        "Injection successful!\n$output"
                    } else { "Failed:\n$errors\n$output" }
                    injectBtn.isEnabled = true
                }
            } catch (e: Exception) {
                runOnUiThread { statusText.text = "Error: ${e.message}"; injectBtn.isEnabled = true }
            }
        }.start()
    }

    private fun startOverlay() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !Settings.canDrawOverlays(this)) {
            statusText.text = "Overlay permission required!"
            startActivity(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:$packageName")))
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(Intent(this, FloatingService::class.java))
        } else {
            startService(Intent(this, FloatingService::class.java))
        }
        statusText.text = "Floating icon active! Open a game, tap the icon to inject."
    }
}
