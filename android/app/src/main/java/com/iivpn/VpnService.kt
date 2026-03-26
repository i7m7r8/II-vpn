package com.iivpn

import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel

class VpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (vpnInterface == null) {
            startVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        // Load the Rust library
        System.loadLibrary("rust")

        // Build VPN interface
        val builder = Builder()
        builder.setSession("II VPN")
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .setBlocking(true)
            .setMtu(1500)

        vpnInterface = builder.establish() ?: return

        // Start forwarding thread
        Thread {
            forwardPackets()
        }.start()
    }

    private fun forwardPackets() {
        val input = FileInputStream(vpnInterface!!.fileDescriptor)
        val output = FileOutputStream(vpnInterface!!.fileDescriptor)
        val buffer = ByteBuffer.allocate(1500)

        while (true) {
            buffer.clear()
            val length = input.channel.read(buffer)
            if (length <= 0) continue

            buffer.flip()
            val packet = ByteArray(length)
            buffer.get(packet)

            // Simple SNI modification: check if it's TLS (port 443) and contains a ClientHello
            // For simplicity, we'll assume we detect TLS and call modifySni
            // This is a placeholder; you'd need to properly parse IP/TCP headers.
            // For now, we'll just forward unchanged.
            output.channel.write(ByteBuffer.wrap(packet))
        }
    }

    override fun onDestroy() {
        vpnInterface?.close()
        super.onDestroy()
    }

    external fun modifySni(packet: ByteArray, newSni: String): ByteArray
}
