package com.panxcz.injector

import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
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

    private data class ProcessInfo(val pid: Int, val packageName: String, val cmdline: String)
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
        Thread {
            try {
                val p = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
                val output = p.inputStream.bufferedReader().readText()
                p.waitFor()
                runOnUiThread {
                    statusText.text = if (p.exitValue() == 0 && output.contains("uid=0")) {
                        "Root OK. Extracting binaries..."
                    } else {
                        "ROOT REQUIRED! Install Magisk/KSU first."
                    }
                }
            } catch (_: Exception) {
                runOnUiThread { statusText.text = "ROOT REQUIRED! Install Magisk/KSU first." }
            }
        }.start()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !Settings.canDrawOverlays(this)) {
            startActivity(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:$packageName")))
        }
    }

    private fun extractBinaries() {
        Thread {
            var msgs = mutableListOf<String>()
            try {
                try {
                    assets.open("injector").use { input ->
                        FileOutputStream(File(injectorPath)).use { output -> input.copyTo(output) }
                    }
                    msgs.add("injector: OK")
                } catch (_: Exception) { msgs.add("injector: not in assets") }

                try {
                    assets.open("libTool.so").use { input ->
                        FileOutputStream(File(soPath)).use { output -> input.copyTo(output) }
                    }
                    msgs.add("libTool.so: OK")
                } catch (_: Exception) { msgs.add("libTool.so: not in assets") }

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

    /**
     * Build shell script avoiding Kotlin $ interpolation.
     * Uses a temporary file to pass the script to su.
     */
    private fun buildScanScript(): String {
        val DOLLAR = '$'
        val script = StringBuilder()
        script.appendLine("#!/system/bin/sh")
        script.appendLine("for d in /proc/[0-9]*; do")
        script.appendLine("    p=$(basename ${DOLLAR}d)")
        script.appendLine("    cmd=$(cat ${DOLLAR}d/cmdline 2>/dev/null | tr '\\0' ' ' | head -c 200)")
        script.appendLine("    if [ -n ${DOLLAR}cmd ]; then")
        script.appendLine("        echo ${DOLLAR}p${DOLLAR}cmd")
        script.appendLine("    fi")
        script.appendLine("done")

        val scriptFile = File(cacheDir, "scan.sh")
        scriptFile.writeText(script.toString())
        return scriptFile.absolutePath
    }

    private fun refreshProcesses() {
        statusText.text = "Scanning processes..."
        Thread {
            val procs = mutableListOf<ProcessInfo>()

            // Step 1: Get all installed app packages from PackageManager
            val installedPkgs = mutableSetOf<String>()
            try {
                val pm = packageManager
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
                    for (app in apps) {
                        if (app.packageName.isNotEmpty()) installedPkgs.add(app.packageName)
                    }
                } else {
                    @Suppress("DEPRECATION")
                    val apps = pm.getInstalledApplications(0)
                    for (app in apps) {
                        if (app.packageName.isNotEmpty()) installedPkgs.add(app.packageName)
                    }
                }
            } catch (_: Exception) {}

            // Step 2: Use a shell script file to avoid Kotlin $ escaping issues
            try {
                val scriptPath = buildScanScript()
                val proc = Runtime.getRuntime().exec(arrayOf("su", "-c", "sh $scriptPath"))
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
                            if (cmdline.contains(pkg)) {
                                pkgName = pkg
                                break
                            }
                        }
                        if (pkgName.isEmpty()) {
                            if (cmdline.startsWith("/system/") || cmdline.startsWith("[")) continue
                            pkgName = cmdline.substring(0, minOf(cmdline.length, 60))
                        }
                        procs.add(ProcessInfo(pid, pkgName, cmdline))
                    }
                }
                proc.waitFor()
                File(scriptPath).delete()
            } catch (e: Exception) {
                // Fallback: scan /proc without root
                File("/proc").listFiles()?.forEach { dir ->
                    val name = dir.name
                    if (!name.all { it.isDigit() }) return@forEach
                    val pid = name.toIntOrNull() ?: return@forEach
                    if (pid <= 0 || pid == android.os.Process.myPid()) return@forEach
                    val cmdline = try {
                        File("/proc/$pid/cmdline").readText().trim('\u0000')
                    } catch (_: Exception) { return@forEach }
                    if (cmdline.isEmpty()) return@forEach

                    var pkgName = ""
                    for (pkg in installedPkgs) {
                        if (cmdline.contains(pkg)) { pkgName = pkg; break }
                    }
                    if (pkgName.isEmpty()) {
                        if (cmdline.startsWith("/system/") || cmdline.startsWith("[")) return@forEach
                        pkgName = cmdline.substring(0, minOf(cmdline.length, 60))
                    }
                    procs.add(ProcessInfo(pid, pkgName, cmdline))
                }
            }

            runOnUiThread {
                processes.clear()
                procs.sortWith(compareBy<ProcessInfo> {
                    if (it.packageName.contains('.')) 0 else 1
                }.thenBy { it.packageName })
                processes.addAll(procs)
                processList.adapter = ArrayAdapter(
                    this,
                    android.R.layout.simple_list_item_1,
                    procs.map { "PID ${it.pid} — ${it.packageName}" }
                )
                statusText.text = "Found ${procs.size} processes. Select one to inject."
                injectBtn.isEnabled = false
                selectedPid = -1
            }
        }.start()
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
