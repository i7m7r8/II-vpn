use bytes::BytesMut;
use jni::objects::{JClass, JString};
use jni::sys::{jbyteArray, jint};
use jni::JNIEnv;
use once_cell::sync::Lazy;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tls_parser::extensions::TlsExtension;
use tls_parser::handshake::*;
use tls_parser::record::TLSMessage;
use tls_parser::TlsParserSettings;

// ------------------------------------------------------------
// SNI modification: parse ClientHello, replace SNI, rebuild packet
// ------------------------------------------------------------
pub fn modify_sni(packet: &[u8], new_sni: &str) -> Option<Vec<u8>> {
    let settings = TlsParserSettings::default();
    let (rem, records) = parse_tls_plaintext(&settings, packet).ok()?;

    let mut output = BytesMut::new();

    for record in records {
        match record {
            TLSMessage::Handshake(handshake) => {
                if handshake.handshake_type == HandshakeType::ClientHello {
                    let (_, client_hello) = parse_tls_handshake_clienthello(handshake.body).ok()?;

                    // Build new extensions, replacing SNI
                    let mut new_extensions = Vec::new();
                    for ext in client_hello.extensions {
                        if ext.typ == 0x00 {
                            // SNI extension – replace
                            new_extensions.push(build_sni_extension(new_sni));
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

                    // Rebuild the handshake record
                    let record = build_handshake_record(HandshakeType::ClientHello, &new_client_hello);
                    output.extend_from_slice(&record);
                } else {
                    // Other handshake messages unchanged
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
    }

    Some(output.to_vec())
}

fn build_sni_extension(sni: &str) -> TlsExtension {
    let server_name = sni.as_bytes();
    let mut ext_data = Vec::new();
    ext_data.push(0x00); // name type: hostname
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
    record.push(0x16); // handshake record type
    record.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    record.push(msg_type as u8);
    record.extend_from_slice(&(body.len() as u24).to_be_bytes());
    record.extend_from_slice(body);
    record
}

// ------------------------------------------------------------
// Tor integration with SOCKS5
// ------------------------------------------------------------
use arti_client::{TorClient, TorClientConfig};
static RUNTIME: Lazy<Runtime> = Lazy::new(|| Runtime::new().expect("Failed to create runtime"));
static TOR_CLIENT: Lazy<Arc<tokio::sync::Mutex<Option<TorClient>>>> =
    Lazy::new(|| Arc::new(tokio::sync::Mutex::new(None)));

#[no_mangle]
pub extern "system" fn Java_com_iivpn_VpnService_startTor(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    let result = RUNTIME.block_on(async {
        let config = TorClientConfig::builder()
            .socks_port(9150) // SOCKS5 proxy on localhost:9150
            .build()
            .expect("Failed to build Tor config");
        match TorClient::create_bootstrapped(config).await {
            Ok(client) => {
                let mut guard = TOR_CLIENT.lock().await;
                *guard = Some(client);
                log::info!("Tor started with SOCKS5 on 127.0.0.1:9150");
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
// VPN placeholder (you will add packet forwarding later)
// ------------------------------------------------------------
#[no_mangle]
pub extern "system" fn Java_com_iivpn_VpnService_startVpn(
    _env: JNIEnv,
    _class: JClass,
) {
    log::info!("VPN start – forwarding not yet implemented");
}

// ------------------------------------------------------------
// JNI for SNI modification
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
// Logging
// ------------------------------------------------------------
#[no_mangle]
pub extern "system" fn Java_com_iivpn_VpnService_initLogging(
    _env: JNIEnv,
    _class: JClass,
) {
    env_logger::init();
}
