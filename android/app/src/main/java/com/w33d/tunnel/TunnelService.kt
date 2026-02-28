package com.w33d.tunnel

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import mobile.Mobile
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer

class TunnelService : VpnService() {

    private var mInterface: ParcelFileDescriptor? = null
    private var mThread: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action == "STOP") {
            stopVpn()
            return START_NOT_STICKY
        }

        if (mThread != null) {
            mThread?.interrupt()
        }

        mThread = Thread {
            runVpn()
        }
        mThread?.start()
        
        return START_STICKY
    }

    private fun runVpn() {
        try {
            if (mInterface != null) {
                mInterface?.close()
                mInterface = null
            }

            // 1. Configure VPN Interface
            val builder = Builder()
            builder.setMtu(1500)
            builder.addAddress("10.1.10.1", 24)
            builder.addRoute("0.0.0.0", 0)
            builder.setSession("w33d-tunnel")
            
            // Exclude our own app traffic to avoid loop (if we were using system network, 
            // but w33d-tunnel uses specific socket binding which might bypass VPN, 
            // but addDisallowedApplication is safer if we knew our package name strictly)
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Log.e("VPN", "Failed to exclude self", e)
            }

            mInterface = builder.establish()

            if (mInterface == null) {
                Log.e("VPN", "Failed to establish VPN")
                return
            }

            val fd = mInterface!!.fd
            Log.i("VPN", "VPN Interface established. FD: $fd")

            // 2. Pass FD to Go
            // We need access to the singleton client instance or similar.
            // For now, let's assume MainActivity sets a static reference or we use a static method.
            // A better way is to pass it via Intent or Binder, but Mobile package is global?
            // Actually MobileClient is an instance.
            
            // Let's rely on MainActivity to pass the client instance to us? No, Service runs independently.
            // Let's use a Singleton helper in Kotlin.
            
            TunnelInstance.client?.startTun(fd)
            
            // Keep thread alive
            while (!Thread.interrupted()) {
                Thread.sleep(1000)
            }

        } catch (e: Exception) {
            Log.e("VPN", "VPN Error", e)
        } finally {
            stopVpn()
        }
    }

    private fun stopVpn() {
        try {
            mInterface?.close()
            mInterface = null
        } catch (e: Exception) {
            // ignore
        }
        stopSelf()
    }

    override fun onDestroy() {
        if (mThread != null) {
            mThread?.interrupt()
        }
        stopVpn()
        super.onDestroy()
    }
}
