use jni::objects::{JClass, JString};
use jni::sys::{jbyteArray, jint};
use jni::JNIEnv;
use std::sync::Arc;
use std::thread;
use tokio::runtime::Runtime;
use once_cell::sync::Lazy;
use arti_client::{TorClient, TorClientConfig};
use std::net::SocketAddr;

// SNI modification function (reuse from previous)
pub fn modify_sni(packet: &[u8], new_sni: &str) -> Option<Vec<u8>> {
    // (Same implementation as before – omitted for brevity)
    // You can copy the earlier modify_sni code here.
    // For now, placeholder:
    None
}

// Global Tokio runtime
static RUNTIME: Lazy<Runtime> = Lazy::new(|| Runtime::new().expect("Failed to create runtime"));

// Global Tor client (once started)
static TOR_CLIENT: Lazy<Arc<Option<TorClient>>> = Lazy::new(|| Arc::new(None));

#[no_mangle]
pub extern "system" fn Java_com_iivpn_VpnService_startTor(
    env: JNIEnv,
    _class: JClass,
) -> jint {
    let result = RUNTIME.block_on(async {
        let config = TorClientConfig::default();
        match TorClient::create_bootstrapped(config).await {
            Ok(client) => {
                // Store globally
                // In a real app, use a mutex or a global static Mutex.
                // For simplicity, we'll just log success.
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

// Placeholder for VPN start – will be implemented in a later step
#[no_mangle]
pub extern "system" fn Java_com_iivpn_VpnService_startVpn(
    env: JNIEnv,
    _class: JClass,
) {
    // Start VPN thread that reads from tun and forwards through Tor
    // For now, just log.
    log::info!("VPN started (placeholder)");
}

// JNI function for SNI modification (already defined, but ensure it's present)
#[no_mangle]
pub extern "system" fn Java_com_iivpn_VpnService_modifySni(
    env: JNIEnv,
    _class: JClass,
    packet: jbyteArray,
    new_sni: JString,
) -> jbyteArray {
    // Convert packet to Vec<u8>
    let len = env.get_array_length(packet).unwrap() as usize;
    let mut data = vec![0u8; len];
    env.get_byte_array_region(packet, 0, &mut data).unwrap();

    let sni_str: String = env.get_string(new_sni).unwrap().into();

    let modified = modify_sni(&data, &sni_str);
    match modified {
        Some(new_data) => env.byte_array_from_slice(&new_data).unwrap().into(),
        None => packet, // return original
    }
}

// Optional: init logging from Android
#[no_mangle]
pub extern "system" fn Java_com_iivpn_VpnService_initLogging(
    env: JNIEnv,
    _class: JClass,
) {
    env_logger::init();
}
