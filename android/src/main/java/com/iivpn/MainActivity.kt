package com.iivpn

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.filled.Shield
import com.iivpn.ui.theme.IIVPNTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            IIVPNTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    VPNControlScreen(
                        onStartVpn = {
                            val intent = Intent(this, VpnService::class.java)
                            startService(intent)
                        },
                        onStopVpn = {
                            val intent = Intent(this, VpnService::class.java)
                            stopService(intent)
                        },
                        onStartTor = {
                            // Call JNI to start Tor
                            VpnService.startTor()
                        }
                    )
                }
            }
        }
    }
}

@Composable
fun VPNControlScreen(
    onStartVpn: () -> Unit,
    onStopVpn: () -> Unit,
    onStartTor: () -> Unit
) {
    var isVpnRunning by remember { mutableStateOf(false) }
    var isTorRunning by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            imageVector = Icons.Default.VpnKey,
            contentDescription = "VPN",
            modifier = Modifier.size(80.dp),
            tint = MaterialTheme.colorScheme.primary
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = "II VPN",
            style = MaterialTheme.typography.headlineLarge,
            color = MaterialTheme.colorScheme.primary
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Tor + SNI Protection",
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
        )
        Spacer(modifier = Modifier.height(32.dp))

        // Tor status and button
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(4.dp)
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Shield,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Tor Status:")
                    Spacer(modifier = Modifier.width(8.dp))
                    Surface(
                        color = if (isTorRunning) Color.Green else Color.Red,
                        shape = MaterialTheme.shapes.small
                    ) {
                        Text(
                            text = if (isTorRunning) "ACTIVE" else "INACTIVE",
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                            fontSize = 12.sp,
                            color = Color.White
                        )
                    }
                }
                Spacer(modifier = Modifier.height(16.dp))
                Button(
                    onClick = {
                        onStartTor()
                        isTorRunning = true
                    },
                    enabled = !isTorRunning,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Start Tor")
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        // VPN status and buttons
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(4.dp)
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text("VPN Status:")
                Spacer(modifier = Modifier.height(4.dp))
                Surface(
                    color = if (isVpnRunning) Color.Green else Color.Red,
                    shape = MaterialTheme.shapes.small
                ) {
                    Text(
                        text = if (isVpnRunning) "CONNECTED" else "DISCONNECTED",
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp),
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White
                    )
                }
                Spacer(modifier = Modifier.height(16.dp))
                Button(
                    onClick = {
                        onStartVpn()
                        isVpnRunning = true
                    },
                    enabled = isTorRunning,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Start VPN")
                }
                Spacer(modifier = Modifier.height(8.dp))
                Button(
                    onClick = {
                        onStopVpn()
                        isVpnRunning = false
                    },
                    enabled = isVpnRunning,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error
                    )
                ) {
                    Text("Stop VPN")
                }
            }
        }
    }
}
