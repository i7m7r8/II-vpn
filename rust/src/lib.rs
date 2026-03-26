//! II VPN – Rust core with SNI spoofing, Tor integration, and VPN tunnel.
//! This library is compiled into a shared object (.so) for Android.
//! All JNI functions are exposed for Kotlin/Java.

// ============================================================
//  Imports & Modules
// ============================================================

use bytes::BytesMut;
use jni::objects::{JClass, JString, JObject, JByteArray};
use jni::sys::{jbyteArray, jint, jboolean, JNI_TRUE, JNI_FALSE};
use jni::JNIEnv;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::path::PathBuf;
use std::fs;
use std::io::{self, Write, Read};
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::Mutex as TokioMutex;
use tokio::net::TcpStream;
use futures::TryFutureExt;
use thiserror::Error;

// SNI parsing
use tls_parser::handshake::extensions::TlsExtension;
use tls_parser::handshake::*;
use tls_parser::record::TLSMessage;
use tls_parser::{parse_tls_plaintext};
use tls_parser::types::U24;

// Tor
use arti_client::{TorClient, TorClientConfig};
use arti_client::config::BoolOrAuto;

// For VPN packet parsing (future use)
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;

// For serialising SNI rules
use serde::{Serialize, Deserialize};

// ============================================================
//  Constants & Configuration
// ============================================================

/// Default SOCKS5 port for Tor (as defined by Arti)
const TOR_SOCKS_PORT: u16 = 9150;

/// VPN tunnel IP address
const VPN_TUN_ADDR: &str = "10.0.0.2";
const VPN_TUN_MASK: i32 = 32;

/// Maximum packet size (MTU)
const MTU: usize = 1500;

// ============================================================
//  Error Types
// ============================================================

#[derive(Error, Debug)]
pub enum IIVpnError {
    #[error("JNI error: {0}")]
    Jni(String),
    #[error("Tor error: {0}")]
    Tor(String),
    #[error("SNI parsing error: {0}")]
    Sni(String),
    #[error("VPN error: {0}")]
    Vpn(String),
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Serde error: {0}")]
    Serde(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, IIVpnError>;

// ============================================================
//  SNI Rules Management
// ============================================================

/// In-memory SNI rule map: domain -> replacement
static SNI_RULES: Lazy<RwLock<HashMap<String, String>>> = Lazy::new(|| RwLock::new(HashMap::new()));

/// Persistent storage path (Android data directory, set via JNI)
static SNI_RULES_PATH: Lazy<Mutex<Option<PathBuf>>> = Lazy::new(|| Mutex::new(None));

/// Set the path for persistent storage (called from Kotlin)
pub fn set_sni_rules_path(path: PathBuf) {
    let mut guard = SNI_RULES_PATH.lock().unwrap();
    *guard = Some(path);
    // Try to load existing rules
    if let Some(p) = guard.as_ref() {
        load_rules_from_file(p).ok();
    }
}

/// Load rules from JSON file
fn load_rules_from_file(path: &PathBuf) -> Result<()> {
    let content = fs::read_to_string(path)?;
    let rules: HashMap<String, String> = serde_json::from_str(&content)?;
    let mut guard = SNI_RULES.write().unwrap();
    *guard = rules;
    log::info!("Loaded {} SNI rules from {}", guard.len(), path.display());
    Ok(())
}

/// Save rules to JSON file
fn save_rules_to_file() -> Result<()> {
    let guard = SNI_RULES_PATH.lock().unwrap();
    if let Some(path) = guard.as_ref() {
        let rules = SNI_RULES.read().unwrap();
        let json = serde_json::to_string_pretty(&*rules)?;
        fs::write(path, json)?;
        log::info!("Saved {} SNI rules to {}", rules.len(), path.display());
    }
    Ok(())
}

/// Add or update an SNI rule
pub fn set_sni_rule(domain: &str, replacement: &str) -> Result<()> {
    let mut rules = SNI_RULES.write().unwrap();
    rules.insert(domain.to_string(), replacement.to_string());
    log::info!("SNI rule added: {} -> {}", domain, replacement);
    drop(rules);
    save_rules_to_file()?;
    Ok(())
}

/// Remove an SNI rule
pub fn remove_sni_rule(domain: &str) -> Result<()> {
    let mut rules = SNI_RULES.write().unwrap();
    if rules.remove(domain).is_some() {
        log::info!("SNI rule removed: {}", domain);
        drop(rules);
        save_rules_to_file()?;
    }
    Ok(())
}

/// Get replacement for a domain
fn get_sni_replacement(domain: &str) -> Option<String> {
    let rules = SNI_RULES.read().unwrap();
    rules.get(domain).cloned()
}

// ============================================================
//  SNI Modification Core
// ============================================================

/// Extract SNI from TLS ClientHello
fn extract_sni_from_client_hello(handshake_body: &[u8]) -> Option<String> {
    let (_, client_hello) = parse_tls_handshake_clienthello(handshake_body).ok()?;
    for ext in client_hello.extensions {
        if ext.typ == 0x00 {
            if let Ok((_, sni)) = parse_tls_sni(ext.data) {
                return Some(sni);
            }
        }
    }
    None
}

/// Parse SNI from extension data (simple)
fn parse_tls_sni(data: &[u8]) -> Result<(&[u8], String), ()> {
    if data.len() < 3 || data[0] != 0x00 {
        return Err(());
    }
    let len = u16::from_be_bytes([data[1], data[2]]) as usize;
    if data.len() < 3 + len {
        return Err(());
    }
    let sni = std::str::from_utf8(&data[3..3 + len]).map_err(|_| ())?;
    Ok((&data[3 + len..], sni.to_string()))
}

/// Build SNI extension bytes
fn build_sni_extension(sni: &str) -> TlsExtension {
    let server_name = sni.as_bytes();
    let mut ext_data = Vec::new();
    ext_data.push(0x00);
    ext_data.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
    ext_data.extend_from_slice(server_name);
    TlsExtension {
        typ: 0x00,
        data: ext_data,
    }
}

/// Rebuild ClientHello after modifying SNI
fn rebuild_client_hello(
    version: u16,
    random: &[u8; 32],
    session_id: &[u8],
    cipher_suites: &[u16],
    compression_methods: &[u8],
    extensions: &[TlsExtension],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&version.to_be_bytes());
    body.extend_from_slice(random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&(cipher_suites.len() as u16 * 2).to_be_bytes());
    for cs in cipher_suites {
        body.extend_from_slice(&cs.to_be_bytes());
    }
    body.push(compression_methods.len() as u8);
    body.extend_from_slice(compression_methods);

    let mut ext_bytes = Vec::new();
    for ext in extensions {
        ext_bytes.extend_from_slice(&ext.typ.to_be_bytes());
        ext_bytes.extend_from_slice(&(ext.data.len() as u16).to_be_bytes());
        ext_bytes.extend_from_slice(&ext.data);
    }
    body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_bytes);

    body
}

/// Build a TLS handshake record (plaintext)
fn build_handshake_record(msg_type: HandshakeType, body: &[u8]) -> Vec<u8> {
    let mut record = Vec::new();
    record.push(0x16); // handshake record type
    record.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    record.push(msg_type as u8);
    record.extend_from_slice(&(body.len() as u24).to_be_bytes());
    record.extend_from_slice(body);
    record
}

/// Modify SNI in a raw TLS packet according to rules.
/// Returns the modified packet, or None if no modification needed.
pub fn modify_sni(packet: &[u8]) -> Option<Vec<u8>> {
    let (rem, tls_plaintext) = parse_tls_plaintext(packet).ok()?;
    let mut output = BytesMut::new();

    match tls_plaintext.msg {
        TLSMessage::Handshake(handshake) => {
            if handshake.handshake_type == HandshakeType::ClientHello {
                let (_, client_hello) = parse_tls_handshake_clienthello(handshake.body).ok()?;

                // Find original SNI
                let mut original_sni = None;
                for ext in client_hello.extensions {
                    if ext.typ == 0x00 {
                        if let Ok((_, sni)) = parse_tls_sni(ext.data) {
                            original_sni = Some(sni);
                            break;
                        }
                    }
                }

                let new_sni = if let Some(sni) = original_sni {
                    get_sni_replacement(&sni).unwrap_or(sni)
                } else {
                    // No SNI, nothing to replace
                    return None;
                };

                // Build new extensions with replaced SNI
                let mut new_extensions = Vec::new();
                for ext in client_hello.extensions {
                    if ext.typ == 0x00 {
                        new_extensions.push(build_sni_extension(&new_sni));
                    } else {
                        new_extensions.push(ext);
                    }
                }

                let new_client_hello = rebuild_client_hello(
                    client_hello.client_version,
                    client_hello.random,
                    client_hello.session_id,
                    client_hello.cipher_suites,
                    client_hello.compression_methods,
                    &new_extensions,
                );

                let record = build_handshake_record(HandshakeType::ClientHello, &new_client_hello);
                output.extend_from_slice(&record);
            } else {
                let record = build_handshake_record(handshake.handshake_type, handshake.body);
                output.extend_from_slice(&record);
            }
        }
        TLSMessage::ChangeCipherSpec(body) => {
            output.extend_from_slice(&[0x14]);
            output.extend_from_slice(&(body.len() as u16).to_be_bytes());
            output.extend_from_slice(body);
        }
        TLSMessage::Alert(body) => {
            output.extend_from_slice(&[0x15]);
            output.extend_from_slice(&(body.len() as u16).to_be_bytes());
            output.extend_from_slice(body);
        }
        TLSMessage::ApplicationData(body) => {
            output.extend_from_slice(&[0x17]);
            output.extend_from_slice(&(body.len() as u16).to_be_bytes());
            output.extend_from_slice(body);
        }
        _ => {}
    }

    Some(output.to_vec())
}

// ============================================================
//  Tor Integration
// ============================================================

/// Tor client instance (global, wrapped in Arc<TokioMutex> for async access)
static TOR_CLIENT: Lazy<Arc<TokioMutex<Option<TorClient<tokio::runtime::Runtime>>>>> =
    Lazy::new(|| Arc::new(TokioMutex::new(None)));

/// Tokio runtime for async operations
static RUNTIME: Lazy<Runtime> = Lazy::new(|| Runtime::new().expect("Failed to create Tokio runtime"));

/// Start Tor with default configuration
async fn start_tor_internal() -> Result<()> {
    let config = TorClientConfig::builder()
        .socks_port(TOR_SOCKS_PORT) // Enable SOCKS5 proxy
        .build()
        .map_err(|e| IIVpnError::Tor(e.to_string()))?;
    let client = TorClient::create_bootstrapped(config)
        .await
        .map_err(|e| IIVpnError::Tor(e.to_string()))?;
    let mut guard = TOR_CLIENT.lock().await;
    *guard = Some(client);
    log::info!("Tor started with SOCKS5 on 127.0.0.1:{}", TOR_SOCKS_PORT);
    Ok(())
}

/// Stop Tor (drop client)
async fn stop_tor_internal() {
    let mut guard = TOR_CLIENT.lock().await;
    *guard = None;
    log::info!("Tor stopped");
}

/// JNI entry point: start Tor
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_startTor(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    match RUNTIME.block_on(start_tor_internal()) {
        Ok(_) => 0,
        Err(e) => {
            log::error!("Failed to start Tor: {}", e);
            1
        }
    }
}

/// JNI entry point: stop Tor (optional)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_stopTor(
    _env: JNIEnv,
    _class: JClass,
) {
    RUNTIME.block_on(stop_tor_internal());
}

// ============================================================
//  VPN Tunnel (Placeholder – to be implemented)
// ============================================================

/// Global flag to stop VPN loop
static VPN_RUNNING: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

/// Start VPN: reads from tun file descriptor, processes packets, forwards to Tor.
/// The tun fd is passed from Android via JNI.
pub async fn start_vpn_internal(tun_fd: i32) -> Result<()> {
    use std::os::unix::io::FromRawFd;
    let mut tun_file = unsafe { std::fs::File::from_raw_fd(tun_fd) };
    let mut buffer = [0u8; MTU];
    let mut running = VPN_RUNNING.lock().unwrap();
    *running = true;
    drop(running);

    log::info!("VPN thread started, reading from fd {}", tun_fd);

    while *VPN_RUNNING.lock().unwrap() {
        match tun_file.read(&mut buffer) {
            Ok(n) if n > 0 => {
                let packet = &buffer[..n];
                // For now, just echo back (placeholder)
                tun_file.write_all(packet)?;
            }
            Ok(_) => continue,
            Err(e) => {
                log::error!("Error reading from tun: {}", e);
                break;
            }
        }
    }
    log::info!("VPN thread exiting");
    Ok(())
}

/// Stop VPN (set flag)
pub fn stop_vpn() {
    let mut running = VPN_RUNNING.lock().unwrap();
    *running = false;
    log::info!("VPN stop requested");
}

/// JNI entry point: start VPN
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_startVpn(
    _env: JNIEnv,
    _class: JClass,
) {
    log::info!("VPN start called – implementation pending");
    // In production, you would receive the tun fd from Kotlin and call start_vpn_internal.
}

// ============================================================
//  JNI Functions for SNI Rules
// ============================================================

/// Convert a jbyteArray to a JByteArray safely
fn jbytearray_to_jbytearray<'a>(env: &JNIEnv<'a>, arr: jbyteArray) -> JByteArray<'a> {
    // JByteArray is a JObject; we can create it via JObject::from and then cast.
    // The safe way is to use JObject::from(arr as jobject) and then into JByteArray.
    JByteArray::from(JObject::from(arr as jni::sys::jobject))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_setSniRule(
    mut env: JNIEnv,
    _class: JClass,
    domain: JString,
    replacement: JString,
) {
    let domain_str: String = env.get_string(&domain).unwrap().into();
    let repl_str: String = env.get_string(&replacement).unwrap().into();
    if let Err(e) = set_sni_rule(&domain_str, &repl_str) {
        log::error!("Failed to set SNI rule: {}", e);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_removeSniRule(
    mut env: JNIEnv,
    _class: JClass,
    domain: JString,
) {
    let domain_str: String = env.get_string(&domain).unwrap().into();
    if let Err(e) = remove_sni_rule(&domain_str) {
        log::error!("Failed to remove SNI rule: {}", e);
    }
}

/// Set the persistent storage path for SNI rules (called from Kotlin)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_setSniRulesPath(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
) {
    let path_str: String = env.get_string(&path).unwrap().into();
    set_sni_rules_path(PathBuf::from(path_str));
}

/// JNI for modifying a packet (testing)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_modifySni(
    mut env: JNIEnv,
    _class: JClass,
    packet: jbyteArray,
) -> jbyteArray {
    // Convert raw pointer to JByteArray
    let jba = jbytearray_to_jbytearray(&env, packet);

    // Get length
    let len = match env.get_array_length(&jba) {
        Ok(l) => l as usize,
        Err(_) => return packet,
    };

    // Read packet data into Vec<u8>
    let mut data = vec![0u8; len];
    let data_i8: &mut [i8] = unsafe {
        std::slice::from_raw_parts_mut(data.as_mut_ptr() as *mut i8, len)
    };
    if env.get_byte_array_region(&jba, 0, data_i8).is_err() {
        return packet;
    }

    let modified = modify_sni(&data);
    match modified {
        Some(new_data) => {
            // Create new byte array
            let new_array = match env.new_byte_array(new_data.len() as jint) {
                Ok(arr) => arr,
                Err(_) => return packet,
            };
            let new_data_i8: &[i8] = unsafe {
                std::slice::from_raw_parts(new_data.as_ptr() as *const i8, new_data.len())
            };
            if env.set_byte_array_region(new_array, 0, new_data_i8).is_err() {
                return packet;
            }
            // Return raw pointer
            new_array
        }
        None => packet,
    }
}

// ============================================================
//  Logging Configuration
// ============================================================

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_initLogging(
    _env: JNIEnv,
    _class: JClass,
) {
    env_logger::init();
    log::info!("II VPN Rust core initialized");
}

// ============================================================
//  Additional Features
// ============================================================

/// Get current SNI rules as JSON string (for UI display)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_getSniRulesJson(
    mut env: JNIEnv,
    _class: JClass,
) -> JString {
    let rules = SNI_RULES.read().unwrap();
    let json = serde_json::to_string(&*rules).unwrap_or_else(|_| "{}".to_string());
    env.new_string(json).unwrap()
}

/// Check if Tor is running
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_isTorRunning(
    mut _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    let running = RUNTIME.block_on(async {
        let guard = TOR_CLIENT.lock().await;
        guard.is_some()
    });
    if running { JNI_TRUE } else { JNI_FALSE }
}

/// Get version string
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_getVersion(
    mut env: JNIEnv,
    _class: JClass,
) -> JString {
    let version = format!("{}.{}.{}", env!("CARGO_PKG_VERSION_MAJOR"), env!("CARGO_PKG_VERSION_MINOR"), env!("CARGO_PKG_VERSION_PATCH"));
    env.new_string(version).unwrap()
}

// ============================================================
//  End of Library
// ============================================================
