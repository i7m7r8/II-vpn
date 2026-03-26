package com.iivpn

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val startVpnButton: Button = findViewById(R.id.start_vpn)
        startVpnButton.setOnClickListener {
            val intent = Intent(this, VpnService::class.java)
            startService(intent)
        }
    }
}
