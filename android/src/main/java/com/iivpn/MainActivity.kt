package com.iivpn

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.iivpn.ui.theme.IIVPNTheme
import kotlinx.coroutines.launch
import org.json.JSONObject

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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VPNControlScreen() {
    var isTorRunning by remember { mutableStateOf(false) }
    var isVpnRunning by remember { mutableStateOf(false) }
    var sniRules by remember { mutableStateOf(mapOf<String, String>()) }
    var showAddRuleDialog by remember { mutableStateOf(false) }
    var editingRule by remember { mutableStateOf<Pair<String, String>?>(null) }

    val scope = rememberCoroutineScope()

    // Load rules on start
    LaunchedEffect(Unit) {
        VpnService.initLogging()
        refreshRules()
    }

    fun refreshRules() {
        val json = VpnService.getSniRulesJson()
        val obj = JSONObject(json)
        val newRules = mutableMapOf<String, String>()
        obj.keys().forEach { key ->
            newRules[key] = obj.getString(key)
        }
        sniRules = newRules
    }

    fun addRule(domain: String, replacement: String) {
        VpnService.setSniRule(domain, replacement)
        refreshRules()
    }

    fun removeRule(domain: String) {
        VpnService.removeSniRule(domain)
        refreshRules()
    }

    Scaffold(
        floatingActionButton = {
            FloatingActionButton(
                onClick = { showAddRuleDialog = true },
                containerColor = MaterialTheme.colorScheme.primary
            ) {
                Icon(Icons.Default.Add, contentDescription = "Add SNI rule")
            }
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Header
            Icon(
                imageVector = Icons.Default.VpnKey,
                contentDescription = "VPN",
                modifier = Modifier.size(80.dp),
                tint = MaterialTheme.colorScheme.primary
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "II VPN",
                fontSize = 28.sp,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )
            Text(
                text = "Tor + SNI Protection",
                fontSize = 14.sp,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
            )
            Spacer(modifier = Modifier.height(24.dp))

            // Tor status card
            Card(
                modifier = Modifier.fillMaxWidth(),
                elevation = CardDefaults.cardElevation(4.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("Tor Status", fontWeight = FontWeight.Medium)
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
                    Spacer(modifier = Modifier.height(12.dp))
                    Button(
                        onClick = {
                            val result = VpnService.startTor()
                            if (result == 0) isTorRunning = true
                        },
                        enabled = !isTorRunning,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Start Tor")
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // VPN status card
            Card(
                modifier = Modifier.fillMaxWidth(),
                elevation = CardDefaults.cardElevation(4.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("VPN Status", fontWeight = FontWeight.Medium)
                        Surface(
                            color = if (isVpnRunning) Color.Green else Color.Red,
                            shape = MaterialTheme.shapes.small
                        ) {
                            Text(
                                text = if (isVpnRunning) "CONNECTED" else "DISCONNECTED",
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                                fontSize = 12.sp,
                                color = Color.White
                            )
                        }
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                    Button(
                        onClick = {
                            VpnService.startVpn()
                            isVpnRunning = true
                        },
                        enabled = isTorRunning && !isVpnRunning,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Start VPN")
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(
                        onClick = {
                            // TODO: implement stop VPN
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

            // SNI Rules list
            Text(
                text = "SNI Rules",
                fontSize = 18.sp,
                fontWeight = FontWeight.Medium,
                modifier = Modifier.align(Alignment.Start)
            )
            Spacer(modifier = Modifier.height(8.dp))

            if (sniRules.isEmpty()) {
                Text(
                    text = "No rules. Tap + to add.",
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f),
                    modifier = Modifier.padding(16.dp)
                )
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(sniRules.toList()) { (domain, replacement) ->
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            elevation = CardDefaults.cardElevation(2.dp)
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(12.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column {
                                    Text(domain, fontWeight = FontWeight.Medium)
                                    Text("→ $replacement", fontSize = 12.sp, color = Color.Gray)
                                }
                                IconButton(onClick = { removeRule(domain) }) {
                                    Icon(Icons.Default.Delete, contentDescription = "Delete")
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Add/Edit Rule Dialog
    if (showAddRuleDialog || editingRule != null) {
        val isEdit = editingRule != null
        var domain by remember { mutableStateOf(editingRule?.first ?: "") }
        var replacement by remember { mutableStateOf(editingRule?.second ?: "") }

        Dialog(onDismissRequest = {
            showAddRuleDialog = false
            editingRule = null
        }) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                elevation = CardDefaults.cardElevation(8.dp)
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        text = if (isEdit) "Edit Rule" else "Add Rule",
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    OutlinedTextField(
                        value = domain,
                        onValueChange = { domain = it },
                        label = { Text("Domain") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = replacement,
                        onValueChange = { replacement = it },
                        label = { Text("Replacement SNI") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End
                    ) {
                        TextButton(onClick = {
                            showAddRuleDialog = false
                            editingRule = null
                        }) {
                            Text("Cancel")
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Button(
                            onClick = {
                                if (domain.isNotBlank() && replacement.isNotBlank()) {
                                    addRule(domain, replacement)
                                    showAddRuleDialog = false
                                    editingRule = null
                                }
                            },
                            enabled = domain.isNotBlank() && replacement.isNotBlank()
                        ) {
                            Text(if (isEdit) "Update" else "Add")
                        }
                    }
                }
            }
        }
    }
}
