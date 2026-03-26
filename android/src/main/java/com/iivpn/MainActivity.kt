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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
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
                    VPNControlScreen()
                }
            }
        }
    }
}

@Composable
fun VPNControlScreen() {
    var isTorRunning by remember { mutableStateOf(false) }
    var isVpnRunning by remember { mutableStateOf(false) }
    var sniRules by remember { mutableStateOf(mapOf<String, String>()) }

    LaunchedEffect(Unit) {
        VpnService.initLogging()
        // Optionally load existing rules
        val json = VpnService.getSniRulesJson()
        // Parse JSON (simplified – you'd use a JSON library)
        // For brevity, we'll just print
        android.util.Log.d("IIVPN", "Rules JSON: $json")
    }

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
        Spacer(modifier = Modifier.height(24.dp))
        Text(
            text = "II VPN",
            fontSize = 32.sp,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.primary
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Tor + SNI Protection",
            fontSize = 16.sp,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
        )
        Spacer(modifier = Modifier.height(48.dp))

        // Tor status and button
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(4.dp)
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text("Tor Status:", fontWeight = FontWeight.Medium)
                Spacer(modifier = Modifier.height(4.dp))
                Surface(
                    color = if (isTorRunning) Color.Green else Color.Red,
                    shape = MaterialTheme.shapes.small
                ) {
                    Text(
                        text = if (isTorRunning) "ACTIVE" else "INACTIVE",
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp),
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White
                    )
                }
                Spacer(modifier = Modifier.height(16.dp))
                Button(
                    onClick = {
                        val result = VpnService.startTor()
                        if (result == 0) {
                            isTorRunning = true
                        }
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
                        VpnService.startVpn()
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
                        // Implement stop later
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

        Spacer(modifier = Modifier.height(24.dp))

        // SNI rules management (placeholder)
        Text(
            text = "SNI Rules: ${sniRules.size} rules",
            fontSize = 14.sp,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
        )
    }
}
