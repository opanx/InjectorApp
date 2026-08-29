package com.panxcz.injector

import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

class MainActivity : AppCompatActivity() {

    private lateinit var processList: ListView
    private lateinit var statusText: TextView
    private lateinit var injectBtn: Button
    private lateinit var refreshBtn: Button

    private data class ProcessInfo(val pid: Int, val packageName: String, val cmdline: String)
    private var processes = mutableListOf<ProcessInfo>()
    private var selectedPid = -1
    private var soPath = "/data/local/tmp/libTool.so"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        processList = findViewById(R.id.processList)
        statusText = findViewById(R.id.statusText)
        injectBtn = findViewById(R.id.injectBtn)
        refreshBtn = findViewById(R.id.refreshBtn)

        // Copy binaries from assets
        copyAsset("injector", "/data/local/tmp/panxcz_injector")
        copyAsset("libTool.so", "/data/local/tmp/libTool.so")

        statusText.text = "Ready. Tap Refresh to list processes."

        refreshBtn.setOnClickListener { refreshProcesses() }

        injectBtn.setOnClickListener {
            if (selectedPid <= 0) {
                statusText.text = "Select a process first!"
                return@setOnClickListener
            }
            injectToProcess(selectedPid)
        }

        processList.setOnItemClickListener { _, _, position, _ ->
            selectedPid = processes[position].pid
            statusText.text = "Selected: PID $selectedPid (${processes[position].packageName})"
            injectBtn.isEnabled = true
        }

        refreshProcesses()
    }

    private fun copyAsset(name: String, targetPath: String) {
        try {
            val target = File(targetPath)
            assets.open(name).use { input ->
                target.outputStream().use { output -> input.copyTo(output) }
            }
            Runtime.getRuntime().exec(arrayOf("su", "-c", "chmod 777 $targetPath")).waitFor()
        } catch (_: Exception) {}
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
                    statusText.text = "Found ${procs.size} app processes."
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
                    arrayOf("su", "-c", "/data/local/tmp/panxcz_injector $pid $so_path"))
                val output = process.inputStream.bufferedReader().readText()
                val errors = process.errorStream.bufferedReader().readText()
                process.waitFor()
                runOnUiThread {
                    statusText.text = if (process.exitValue() == 0) {
                        "✅ Injection successful!\n$output"
                    } else {
                        "❌ Failed:\n$errors\n$output"
                    }
                    injectBtn.isEnabled = true
                }
            } catch (e: Exception) {
                runOnUiThread {
                    statusText.text = "❌ Error: ${e.message}"
                    injectBtn.isEnabled = true
                }
            }
        }.start()
    }
}
