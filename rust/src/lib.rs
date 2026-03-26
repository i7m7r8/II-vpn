use jni::objects::{JClass, JString};
use jni::sys::{jbyteArray, jint};
use jni::JNIEnv;
use std::sync::Arc;
use tokio::runtime::Runtime;
use once_cell::sync::Lazy;
use arti_client::{TorClient, TorClientConfig};
use std::net::SocketAddr;

// ------------------------------------------------------------
// SNI modification (placeholder – you can reuse your earlier code)
// ------------------------------------------------------------
pub fn modify_sni(packet: &[u8], new_sni: &str) -> Option<Vec<u8>> {
    // TODO: Implement TLS ClientHello parsing and SNI replacement.
    // For now, return None (no modification).
    None
}

// ------------------------------------------------------------
// Tokio runtime for async Tor operations
// ------------------------------------------------------------
static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    Runtime::new().expect("Failed to create Tokio runtime")
});

// Global Tor client (initially None)
static TOR_CLIENT: Lazy<Arc<tokio::sync::Mutex<Option<TorClient>>>> = Lazy::new(|| {
    Arc::new(tokio::sync::Mutex::new(None))
});

// ------------------------------------------------------------
// JNI function to start Tor
// ------------------------------------------------------------
#[no_mangle]
pub extern "system" fn Java_com_iivpn_VpnService_startTor(
    env: JNIEnv,
    _class: JClass,
) -> jint {
    let result = RUNTIME.block_on(async {
        let config = TorClientConfig::default();
        match TorClient::create_bootstrapped(config).await {
            Ok(client) => {
                let mut guard = TOR_CLIENT.lock().await;
                *guard = Some(client);
                log::info!("Tor started successfully");
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
// JNI function to start VPN (placeholder)
// ------------------------------------------------------------
#[no_mangle]
pub extern "system" fn Java_com_iivpn_VpnService_startVpn(
    _env: JNIEnv,
    _class: JClass,
) {
    log::info!("VPN start called – implementation pending");
    // TODO: Read from tun, parse packets, forward through Tor SOCKS5 proxy.
}

// ------------------------------------------------------------
// JNI function to modify SNI (called from Kotlin)
// ------------------------------------------------------------
#[no_mangle]
pub extern "system" fn Java_com_iivpn_VpnService_modifySni(
    env: JNIEnv,
    _class: JClass,
    packet: jbyteArray,
    new_sni: JString,
) -> jbyteArray {
    // Convert Java byte array to Vec<u8>
    let len = env.get_array_length(packet).unwrap() as usize;
    let mut data = vec![0u8; len];
    env.get_byte_array_region(packet, 0, &mut data).unwrap();

    let sni_str: String = env.get_string(new_sni).unwrap().into();

    let modified = modify_sni(&data, &sni_str);
    match modified {
        Some(new_data) => env.byte_array_from_slice(&new_data).unwrap().into(),
        None => packet, // return original if no modification
    }
}

// ------------------------------------------------------------
// JNI function to initialise logging (optional)
// ------------------------------------------------------------
#[no_mangle]
pub extern "system" fn Java_com_iivpn_VpnService_initLogging(
    _env: JNIEnv,
    _class: JClass,
) {
    env_logger::init();
}
