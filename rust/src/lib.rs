use jni::objects::{JClass, JString};
use jni::sys::{jbyteArray, jint};
use jni::JNIEnv;
use std::sync::Arc;
use tokio::runtime::Runtime;
use once_cell::sync::Lazy;
use arti_client::{TorClient, TorClientConfig};
use std::net::SocketAddr;

// ------------------------------------------------------------
// SNI modification function (full TLS parsing + replacement)
// ------------------------------------------------------------
pub fn modify_sni(packet: &[u8], new_sni: &str) -> Option<Vec<u8>> {
    // Use tls-parser to find the ClientHello and replace the SNI extension.
    // This is a simplified placeholder – replace with your full implementation.
    // For now, return None to indicate no change.
    None
}

// ------------------------------------------------------------
// Tokio runtime
// ------------------------------------------------------------
static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    Runtime::new().expect("Failed to create Tokio runtime")
});

// Global Tor client (Mutex-protected)
static TOR_CLIENT: Lazy<Arc<tokio::sync::Mutex<Option<TorClient>>>> = Lazy::new(|| {
    Arc::new(tokio::sync::Mutex::new(None))
});

// ------------------------------------------------------------
// JNI: start Tor and SOCKS5 proxy
// ------------------------------------------------------------
#[no_mangle]
pub extern "system" fn Java_com_iivpn_VpnService_startTor(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    let result = RUNTIME.block_on(async {
        // Build a configuration that starts a SOCKS5 proxy on localhost:9150
        let config = TorClientConfig::builder()
            .socks_port(9150) // enable SOCKS5 on this port
            .build()
            .expect("Failed to build config");

        match TorClient::create_bootstrapped(config).await {
            Ok(client) => {
                let mut guard = TOR_CLIENT.lock().await;
                *guard = Some(client);
                log::info!("Tor started with SOCKS5 on 127.0.0.1:9150");
                0 // success
            }
            Err(e) => {
                log::error!("Failed to start Tor: {}", e);
                1 // error
            }
        }
    });
    result
}

// ------------------------------------------------------------
// JNI: start VPN – this will set up a tunnel and forward traffic through Tor
// ------------------------------------------------------------
#[no_mangle]
pub extern "system" fn Java_com_iivpn_VpnService_startVpn(
    env: JNIEnv,
    _class: JClass,
) {
    log::info!("VPN start called – VPN forwarding not yet implemented");
    // TODO: 
    // 1. Obtain the tun file descriptor from Android (via JNI).
    // 2. Spawn a thread/task that reads packets, parses IP/TCP headers,
    //    detects TLS ClientHello, calls modify_sni, and forwards the packet
    //    to Tor’s SOCKS5 proxy (127.0.0.1:9150) or directly if Tor is disabled.
}

// ------------------------------------------------------------
// JNI: modify SNI (called from Kotlin for offline processing)
// ------------------------------------------------------------
#[no_mangle]
pub extern "system" fn Java_com_iivpn_VpnService_modifySni(
    env: JNIEnv,
    _class: JClass,
    packet: jbyteArray,
    new_sni: JString,
) -> jbyteArray {
    let len = env.get_array_length(packet).unwrap() as usize;
    let mut data = vec![0u8; len];
    env.get_byte_array_region(packet, 0, &mut data).unwrap();

    let sni_str: String = env.get_string(new_sni).unwrap().into();

    let modified = modify_sni(&data, &sni_str);
    match modified {
        Some(new_data) => env.byte_array_from_slice(&new_data).unwrap().into(),
        None => packet,
    }
}

// ------------------------------------------------------------
// JNI: init logging
// ------------------------------------------------------------
#[no_mangle]
pub extern "system" fn Java_com_iivpn_VpnService_initLogging(
    _env: JNIEnv,
    _class: JClass,
) {
    env_logger::init();
}
