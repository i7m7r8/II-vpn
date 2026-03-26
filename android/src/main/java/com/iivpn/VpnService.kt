package com.iivpn

import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream

class VpnService : android.net.VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null

    companion object {
        init {
            System.loadLibrary("rust")
        }

        external fun startTor(): Int
        external fun isTorRunning(): Boolean
        external fun setSniRule(domain: String, replacement: String)
        external fun removeSniRule(domain: String)
        external fun setSniRulesPath(path: String)
        external fun getSniRulesJson(): String
        external fun modifySni(packet: ByteArray): ByteArray
        external fun startVpn()
        external fun initLogging()
        external fun getVersion(): String
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        initLogging()
        // Set storage path for SNI rules
        val filesDir = applicationContext.filesDir.absolutePath
        setSniRulesPath("$filesDir/sni_rules.json")

        // Start Tor if not already running
        if (!isTorRunning()) {
            startTor()
        }

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

        // Start VPN thread that will call the Rust startVpn function
        // In a real implementation, we'd pass the fd to Rust.
        // For now, we'll just call the placeholder.
        startVpn()
    }

    override fun onDestroy() {
        vpnInterface?.close()
        super.onDestroy()
    }
}
