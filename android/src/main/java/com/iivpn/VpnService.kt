package com.iivpn

import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream

class VpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null

    companion object {
        init {
            System.loadLibrary("rust")
        }

        external fun startTor(): Int
        external fun startVpn()
        external fun modifySni(packet: ByteArray, newSni: String): ByteArray
        external fun initLogging()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        initLogging()
        // Start Tor if not already running (check via JNI)
        val torResult = startTor()
        Log.i("IIVPN", "Tor start result: $torResult")

        if (vpnInterface == null) {
            startVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        val builder = Builder()
        builder.setSession("II VPN")
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .setBlocking(true)
            .setMtu(1500)

        vpnInterface = builder.establish() ?: return

        // Call Rust to start VPN processing
        startVpn()
    }

    override fun onDestroy() {
        vpnInterface?.close()
        super.onDestroy()
    }
}
