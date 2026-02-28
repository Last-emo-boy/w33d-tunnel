package com.w33d.tunnel

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import mobile.Mobile
import mobile.MobileClient
import org.json.JSONObject
import java.util.Timer
import java.util.TimerTask

class MainActivity : AppCompatActivity() {
    private var client: MobileClient? = null
    private var timer: Timer? = null
    private val VPN_REQUEST_CODE = 0x0F

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val etSubUrl = findViewById<EditText>(R.id.etSubUrl)
        val btnStart = findViewById<Button>(R.id.btnStart)
        val btnStop = findViewById<Button>(R.id.btnStop)
        val tvStats = findViewById<TextView>(R.id.tvStats)

        // Set Default Log Level
        Mobile.setLogLevel(0) // Debug

        btnStart.setOnClickListener {
            val subUrl = etSubUrl.text.toString()
            if (subUrl.isEmpty()) return@setOnClickListener

            // 1. Start VPN Permission Check
            val intent = VpnService.prepare(this)
            if (intent != null) {
                startActivityForResult(intent, VPN_REQUEST_CODE)
            } else {
                onActivityResult(VPN_REQUEST_CODE, RESULT_OK, null)
            }
            
            // 2. Start Go Client (SOCKS5)
            startGoClient(subUrl, btnStart, btnStop, tvStats)
        }

        btnStop.setOnClickListener {
            // Stop VPN
            val intent = Intent(this, TunnelService::class.java)
            intent.action = "STOP"
            startService(intent)

            client?.stop()
            TunnelInstance.client = null
            client = null // Reset
            btnStart.isEnabled = true
            btnStop.isEnabled = false
            stopStatsUpdater()
            tvStats.text = "Stopped"
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            val intent = Intent(this, TunnelService::class.java)
            startService(intent)
        }
    }

    private fun startGoClient(subUrl: String, btnStart: Button, btnStop: Button, tvStats: TextView) {
        if (TunnelInstance.client == null) {
            TunnelInstance.client = Mobile.newMobileClient()
        }
        client = TunnelInstance.client

        // Construct JSON Config
        val json = JSONObject()
        json.put("SubURL", subUrl)
        json.put("SocksAddr", "127.0.0.1:1080")

        try {
            client?.start(json.toString())
            btnStart.isEnabled = false
            btnStop.isEnabled = true
            startStatsUpdater(tvStats)
        } catch (e: Exception) {
            Log.e("W33D", "Start failed", e)
            tvStats.text = "Error: ${e.message}"
        }
    }

    private fun startStatsUpdater(tv: TextView) {
        timer = Timer()
        timer?.scheduleAtFixedRate(object : TimerTask() {
            override fun run() {
                val statsJson = client?.stats ?: return
                runOnUiThread {
                    try {
                        val obj = JSONObject(statsJson)
                        val tx = obj.getLong("bytes_tx")
                        val rx = obj.getLong("bytes_rx")
                        tv.text = "TX: ${formatBytes(tx)} | RX: ${formatBytes(rx)}"
                    } catch (e: Exception) {
                        // Ignore parse error
                    }
                }
            }
        }, 1000, 1000)
    }

    private fun stopStatsUpdater() {
        timer?.cancel()
        timer = null
    }

    private fun formatBytes(bytes: Long): String {
        if (bytes < 1024) return "$bytes B"
        val exp = (Math.log(bytes.toDouble()) / Math.log(1024.0)).toInt()
        val pre = "KMGTPE"[exp - 1]
        return String.format("%.1f %sB", bytes / Math.pow(1024.0, exp.toDouble()), pre)
    }
}
