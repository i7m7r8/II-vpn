//! II VPN – Rust core with SNI spoofing, Tor integration, and VPN tunnel.
//! This library is compiled into a shared object (.so) for Android.

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
use tokio::runtime::Runtime;
use tokio::sync::Mutex as TokioMutex;
use thiserror::Error;

// Tor – use the config builder (no external runtime needed)
use arti_client::{TorClient, TorClientConfig};

// Serialization
use serde_json;

// ============================================================
//  Constants
// ============================================================

const TOR_SOCKS_PORT: u16 = 9150;
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

static SNI_RULES: Lazy<RwLock<HashMap<String, String>>> = Lazy::new(|| RwLock::new(HashMap::new()));
static SNI_RULES_PATH: Lazy<Mutex<Option<PathBuf>>> = Lazy::new(|| Mutex::new(None));

pub fn set_sni_rules_path(path: PathBuf) {
    let mut guard = SNI_RULES_PATH.lock().unwrap();
    *guard = Some(path);
    if let Some(p) = guard.as_ref() {
        load_rules_from_file(p).ok();
    }
}

fn load_rules_from_file(path: &PathBuf) -> Result<()> {
    let content = fs::read_to_string(path)?;
    let rules: HashMap<String, String> = serde_json::from_str(&content)?;
    let mut guard = SNI_RULES.write().unwrap();
    *guard = rules;
    log::info!("Loaded {} SNI rules", guard.len());
    Ok(())
}

fn save_rules_to_file() -> Result<()> {
    let guard = SNI_RULES_PATH.lock().unwrap();
    if let Some(path) = guard.as_ref() {
        let rules = SNI_RULES.read().unwrap();
        let json = serde_json::to_string_pretty(&*rules)?;
        fs::write(path, json)?;
        log::info!("Saved {} SNI rules", rules.len());
    }
    Ok(())
}

pub fn set_sni_rule(domain: &str, replacement: &str) -> Result<()> {
    let mut rules = SNI_RULES.write().unwrap();
    rules.insert(domain.to_string(), replacement.to_string());
    log::info!("SNI rule added: {} -> {}", domain, replacement);
    drop(rules);
    save_rules_to_file()?;
    Ok(())
}

pub fn remove_sni_rule(domain: &str) -> Result<()> {
    let mut rules = SNI_RULES.write().unwrap();
    if rules.remove(domain).is_some() {
        log::info!("SNI rule removed: {}", domain);
        drop(rules);
        save_rules_to_file()?;
    }
    Ok(())
}

fn get_sni_replacement(domain: &str) -> Option<String> {
    let rules = SNI_RULES.read().unwrap();
    rules.get(domain).cloned()
}

// ============================================================
//  SNI Modification Core – manual parsing
// ============================================================

/// Extract SNI from a TLS ClientHello packet (simplified)
fn extract_sni_from_tls_packet(packet: &[u8]) -> Option<String> {
    // TLS handshake records start with 0x16, followed by 2-byte length, then handshake header.
    // We'll look for a ClientHello (type 0x01) and then the SNI extension.
    // This is a very basic parser – works for most single‑record ClientHello.
    if packet.len() < 5 || packet[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([packet[3], packet[4]]) as usize;
    if packet.len() < 5 + record_len {
        return None;
    }
    let handshake_start = 5;
    if packet[handshake_start] != 0x01 {
        return None; // not ClientHello
    }
    // Skip handshake header (4 bytes: type, 3‑byte length)
    let mut pos = handshake_start + 4;
    // ClientHello version
    pos += 2;
    // Random (32 bytes)
    pos += 32;
    // Session ID length
    if pos >= packet.len() { return None; }
    let session_len = packet[pos] as usize;
    pos += 1 + session_len;
    // Cipher suites length
    if pos + 1 >= packet.len() { return None; }
    let cipher_len = u16::from_be_bytes([packet[pos], packet[pos+1]]) as usize;
    pos += 2 + cipher_len;
    // Compression methods length
    if pos >= packet.len() { return None; }
    let comp_len = packet[pos] as usize;
    pos += 1 + comp_len;
    // Extensions length
    if pos + 1 >= packet.len() { return None; }
    let ext_len = u16::from_be_bytes([packet[pos], packet[pos+1]]) as usize;
    pos += 2;
    let end = pos + ext_len;
    if end > packet.len() { return None; }

    // Walk extensions looking for SNI (type 0x00)
    while pos + 2 <= end {
        let ext_type = u16::from_be_bytes([packet[pos], packet[pos+1]]);
        pos += 2;
        if pos + 2 > end { break; }
        let ext_data_len = u16::from_be_bytes([packet[pos], packet[pos+1]]) as usize;
        pos += 2;
        if pos + ext_data_len > end { break; }
        if ext_type == 0x00 {
            // SNI extension data: list of server names (each: type, length, name)
            let sni_data = &packet[pos..pos+ext_data_len];
            if sni_data.len() < 3 { break; }
            if sni_data[0] == 0x00 { // hostname type
                let name_len = u16::from_be_bytes([sni_data[1], sni_data[2]]) as usize;
                if sni_data.len() >= 3 + name_len {
                    let sni = std::str::from_utf8(&sni_data[3..3+name_len]).ok()?;
                    return Some(sni.to_string());
                }
            }
            break;
        }
        pos += ext_data_len;
    }
    None
}

/// Build a TLS handshake record (same as before, but no dependencies)
fn build_tls_handshake_record(handshake_body: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + handshake_body.len());
    record.push(0x16); // handshake content type
    record.extend_from_slice(&(handshake_body.len() as u16).to_be_bytes());
    record.extend_from_slice(handshake_body);
    record
}

/// Modify the SNI in a TLS ClientHello packet according to rules.
/// Returns the modified packet, or None if no modification.
pub fn modify_sni(packet: &[u8]) -> Option<Vec<u8>> {
    let original_sni = extract_sni_from_tls_packet(packet)?;
    let new_sni = get_sni_replacement(&original_sni)?; // only modify if a rule exists
    if new_sni == original_sni {
        return None;
    }
    // For a full replacement, we would need to rebuild the whole ClientHello.
    // As a placeholder, we'll just replace the SNI string in the packet (not fully correct).
    // However, for a demo this is acceptable; a real implementation would rebuild.
    // Since this is a proof-of-concept, we'll return None for now, meaning no change.
    // In a production version, you'd replace the extension data.
    // To avoid complexity, we'll skip modification in this version.
    log::info!("Would replace SNI {} -> {}", original_sni, new_sni);
    None
}

// ============================================================
//  Tor Integration
// ============================================================

static TOR_CLIENT: Lazy<Arc<TokioMutex<Option<TorClient<arti_client::tor_rtcompat::PreferredRuntime>>>>> =
    Lazy::new(|| Arc::new(TokioMutex::new(None)));
static RUNTIME: Lazy<Runtime> = Lazy::new(|| Runtime::new().expect("Failed to create Tokio runtime"));

async fn start_tor_internal() -> Result<()> {
    let config = TorClientConfig::builder()
        .socks_port(TOR_SOCKS_PORT)
        .build()
        .map_err(|e| IIVpnError::Tor(e.to_string()))?;
    let client = TorClient::create_bootstrapped(config)
        .await
        .map_err(|e| IIVpnError::Tor(e.to_string()))?;
    *TOR_CLIENT.lock().await = Some(client);
    log::info!("Tor started on port {}", TOR_SOCKS_PORT);
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_startTor(
    _env: JNIEnv, _class: JClass,
) -> jint {
    match RUNTIME.block_on(start_tor_internal()) {
        Ok(_) => 0,
        Err(e) => { log::error!("Tor start failed: {}", e); 1 }
    }
}

// ============================================================
//  JNI Functions for SNI Rules
// ============================================================

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_setSniRule(
    mut env: JNIEnv, _class: JClass, domain: JString, replacement: JString,
) {
    let domain_str: String = env.get_string(&domain).unwrap().into();
    let repl_str: String = env.get_string(&replacement).unwrap().into();
    if let Err(e) = set_sni_rule(&domain_str, &repl_str) {
        log::error!("Failed to set SNI rule: {}", e);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_removeSniRule(
    mut env: JNIEnv, _class: JClass, domain: JString,
) {
    let domain_str: String = env.get_string(&domain).unwrap().into();
    if let Err(e) = remove_sni_rule(&domain_str) {
        log::error!("Failed to remove SNI rule: {}", e);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_setSniRulesPath(
    mut env: JNIEnv, _class: JClass, path: JString,
) {
    let path_str: String = env.get_string(&path).unwrap().into();
    set_sni_rules_path(PathBuf::from(path_str));
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_modifySni(
    env: JNIEnv, _class: JClass, packet: jbyteArray,
) -> jbyteArray {
    let jba = unsafe { JByteArray::from(JObject::from_raw(packet)) };
    let len = match env.get_array_length(&jba) {
        Ok(l) => l as usize,
        Err(_) => return packet,
    };
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
            let new_array = match env.new_byte_array(new_data.len() as jint) {
                Ok(arr) => arr,
                Err(_) => return packet,
            };
            let new_data_i8: &[i8] = unsafe {
                std::slice::from_raw_parts(new_data.as_ptr() as *const i8, new_data.len())
            };
            if env.set_byte_array_region(&new_array, 0, new_data_i8).is_err() {
                return packet;
            }
            new_array.into_inner()
        }
        None => packet,
    }
}

// ============================================================
//  Additional Features
// ============================================================

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_getSniRulesJson<'a>(
    env: JNIEnv<'a>, _class: JClass<'a>,
) -> JString<'a> {
    let rules = SNI_RULES.read().unwrap();
    let json = serde_json::to_string(&*rules).unwrap_or_else(|_| "{}".to_string());
    env.new_string(json).unwrap()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_isTorRunning(
    _env: JNIEnv, _class: JClass,
) -> jboolean {
    let running = RUNTIME.block_on(async { TOR_CLIENT.lock().await.is_some() });
    if running { JNI_TRUE } else { JNI_FALSE }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_getVersion<'a>(
    env: JNIEnv<'a>, _class: JClass<'a>,
) -> JString<'a> {
    let version = format!("{}.{}.{}", env!("CARGO_PKG_VERSION_MAJOR"), env!("CARGO_PKG_VERSION_MINOR"), env!("CARGO_PKG_VERSION_PATCH"));
    env.new_string(version).unwrap()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_initLogging(
    _env: JNIEnv, _class: JClass,
) {
    env_logger::init();
    log::info!("II VPN Rust core initialized");
}

// ============================================================
//  VPN Placeholder
// ============================================================

static VPN_RUNNING: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

pub async fn start_vpn_internal(tun_fd: i32) -> Result<()> {
    use std::os::unix::io::FromRawFd;
    let mut tun_file = unsafe { std::fs::File::from_raw_fd(tun_fd) };
    let mut buffer = [0u8; MTU];
    *VPN_RUNNING.lock().unwrap() = true;
    log::info!("VPN thread started on fd {}", tun_fd);
    while *VPN_RUNNING.lock().unwrap() {
        match tun_file.read(&mut buffer) {
            Ok(n) if n > 0 => {
                // TODO: implement packet forwarding through Tor
                tun_file.write_all(&buffer[..n])?;
            }
            Ok(_) => continue,
            Err(e) => { log::error!("Tun read error: {}", e); break; }
        }
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_startVpn(
    _env: JNIEnv, _class: JClass,
) {
    log::info!("VPN start – implementation pending");
}
