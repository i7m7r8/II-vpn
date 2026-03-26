use bytes::BytesMut;
use jni::sys::{jbyteArray, jint, jsize};
use jni::JNIEnv;
use jni::objects::{JClass, JString, JObject, JByteArray};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;

// Correct imports for tls-parser
use tls_parser::handshake::extensions::TlsExtension;
use tls_parser::handshake::*;
use tls_parser::record::TLSMessage;
use tls_parser::{parse_tls_plaintext, TlsParserSettings};
use tls_parser::types::U24;

// ------------------------------------------------------------
// SNI rules management (domain -> replacement)
// ------------------------------------------------------------
type SniRules = HashMap<String, String>;
static SNI_RULES: Lazy<Arc<Mutex<SniRules>>> = Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

pub fn set_sni_rule(domain: &str, replacement: &str) {
    let mut rules = SNI_RULES.lock().unwrap();
    rules.insert(domain.to_string(), replacement.to_string());
    log::info!("SNI rule added: {} -> {}", domain, replacement);
}

pub fn remove_sni_rule(domain: &str) {
    let mut rules = SNI_RULES.lock().unwrap();
    rules.remove(domain);
    log::info!("SNI rule removed: {}", domain);
}

fn get_sni_replacement(domain: &str) -> Option<String> {
    let rules = SNI_RULES.lock().unwrap();
    rules.get(domain).cloned()
}

// ------------------------------------------------------------
// SNI modification: parse ClientHello, extract SNI, replace if rule exists
// ------------------------------------------------------------
pub fn modify_sni(packet: &[u8]) -> Option<Vec<u8>> {
    let (rem, tls_plaintext) = parse_tls_plaintext(packet).ok()?;
    let mut output = BytesMut::new();

    // tls_plaintext.msg is a single TLSMessage
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
                    return None;
                };

                // Build new extensions, replacing SNI
                let mut new_extensions = Vec::new();
                for ext in client_hello.extensions {
                    if ext.typ == 0x00 {
                        new_extensions.push(build_sni_extension(&new_sni));
                    } else {
                        new_extensions.push(ext);
                    }
                }

                // Rebuild ClientHello
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

fn build_handshake_record(msg_type: HandshakeType, body: &[u8]) -> Vec<u8> {
    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    record.push(msg_type as u8);
    record.extend_from_slice(&(body.len() as u24).to_be_bytes());
    record.extend_from_slice(body);
    record
}

// ------------------------------------------------------------
// Tor integration with rustls
// ------------------------------------------------------------
use arti_client::{TorClient, TorClientConfig};

static RUNTIME: Lazy<Runtime> = Lazy::new(|| Runtime::new().expect("Failed to create runtime"));
static TOR_CLIENT: Lazy<Arc<tokio::sync::Mutex<Option<TorClient<tokio::runtime::Runtime>>>>> =
    Lazy::new(|| Arc::new(tokio::sync::Mutex::new(None)));

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_startTor(
    mut _env: JNIEnv,
    _class: JClass,
) -> jint {
    let result = RUNTIME.block_on(async {
        let config = TorClientConfig::builder()
            .build()
            .expect("Failed to build Tor config");
        match TorClient::create_bootstrapped(config).await {
            Ok(client) => {
                let mut guard = TOR_CLIENT.lock().await;
                *guard = Some(client);
                log::info!("Tor started (SOCKS5 on 127.0.0.1:9150)");
                0
            }
            Err(e) => {
                log::error!("Tor start failed: {}", e);
                1
            }
        }
    });
    result
}

// ------------------------------------------------------------
// JNI functions for SNI rules
// ------------------------------------------------------------
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_setSniRule(
    mut env: JNIEnv,
    _class: JClass,
    domain: JString,
    replacement: JString,
) {
    let domain_str: String = env.get_string(&domain).unwrap().into();
    let repl_str: String = env.get_string(&replacement).unwrap().into();
    set_sni_rule(&domain_str, &repl_str);
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_removeSniRule(
    mut env: JNIEnv,
    _class: JClass,
    domain: JString,
) {
    let domain_str: String = env.get_string(&domain).unwrap().into();
    remove_sni_rule(&domain_str);
}

// ------------------------------------------------------------
// VPN placeholder (will call modify_sni on packets)
// ------------------------------------------------------------
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_startVpn(
    mut _env: JNIEnv,
    _class: JClass,
) {
    log::info!("VPN start – forwarding not yet implemented");
}

// ------------------------------------------------------------
// JNI for SNI modification (direct JNI calls, using JObject wrappers)
// ------------------------------------------------------------
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_modifySni(
    mut env: JNIEnv,
    _class: JClass,
    packet: jbyteArray,
) -> jbyteArray {
    // Wrap the raw pointer in JObject and JByteArray for safe operations
    let obj = JObject::from(packet);
    let jba = JByteArray::from(obj);

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
            // Convert JByteArray back to raw pointer
            new_array.as_obj().into_inner()
        }
        None => packet,
    }
}

// ------------------------------------------------------------
// Logging
// ------------------------------------------------------------
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_initLogging(
    mut _env: JNIEnv,
    _class: JClass,
) {
    env_logger::init();
}
