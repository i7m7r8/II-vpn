use bytes::BytesMut;
use jni::objects::{JClass, JString};
use jni::JNIEnv;
use jni::sys::{jbyteArray, jint};
use tls_parser::handshake::*;
use tls_parser::types::U24;
use tls_parser::record::TLSMessage;
use tls_parser::{parse_tls_plaintext, TlsParserSettings};

/// Modify the SNI in a TLS ClientHello packet.
/// Returns the modified packet if successful, otherwise None.
pub fn modify_sni(packet: &[u8], new_sni: &str) -> Option<Vec<u8>> {
    // Parse the TLS record(s)
    let settings = TlsParserSettings::default();
    let (rem, records) = parse_tls_plaintext(&settings, packet).ok()?;

    // We need to rebuild the entire packet. We'll collect all records into a new BytesMut.
    let mut output = BytesMut::new();

    for record in records {
        match record {
            TLSMessage::Handshake(handshake) => {
                // Check if it's a ClientHello (type 1)
                if handshake.handshake_type == HandshakeType::ClientHello {
                    // Parse the handshake body
                    let (_, client_hello) = parse_tls_handshake_clienthello(handshake.body)
                        .ok()?;

                    // Modify the extensions, specifically SNI (extension type 0)
                    let mut new_extensions = Vec::new();
                    for ext in client_hello.extensions {
                        if ext.typ == 0x00 { // SNI extension
                            // Replace with new SNI
                            let sni_extension = build_sni_extension(new_sni);
                            new_extensions.push(sni_extension);
                        } else {
                            // Keep other extensions unchanged
                            new_extensions.push(ext);
                        }
                    }

                    // Rebuild the ClientHello body with modified extensions
                    let new_client_hello = rebuild_client_hello(
                        client_hello.client_version,
                        client_hello.random,
                        client_hello.session_id,
                        client_hello.cipher_suites,
                        client_hello.compression_methods,
                        &new_extensions,
                    );

                    // Rebuild the handshake record
                    let handshake_record = build_handshake_record(HandshakeType::ClientHello, &new_client_hello);
                    output.extend_from_slice(&handshake_record);
                } else {
                    // Other handshake messages unchanged
                    let handshake_record = build_handshake_record(handshake.handshake_type, handshake.body);
                    output.extend_from_slice(&handshake_record);
                }
            }
            TLSMessage::ChangeCipherSpec(body) => {
                output.extend_from_slice(&[0x14]); // record type
                output.extend_from_slice(&(body.len() as u16).to_be_bytes());
                output.extend_from_slice(body);
            }
            TLSMessage::Alert(body) => {
                output.extend_from_slice(&[0x15]); // record type
                output.extend_from_slice(&(body.len() as u16).to_be_bytes());
                output.extend_from_slice(body);
            }
            TLSMessage::ApplicationData(body) => {
                output.extend_from_slice(&[0x17]); // record type
                output.extend_from_slice(&(body.len() as u16).to_be_bytes());
                output.extend_from_slice(body);
            }
            _ => {}
        }
    }

    Some(output.to_vec())
}

// Helper: Build the SNI extension bytes
fn build_sni_extension(sni: &str) -> tls_parser::extensions::TlsExtension {
    let server_name = sni.as_bytes();
    let mut ext_data = Vec::new();
    // SNI extension structure: list of server names, each prefixed with type (0 = hostname) and length
    ext_data.push(0x00); // name type: hostname
    ext_data.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
    ext_data.extend_from_slice(server_name);
    tls_parser::extensions::TlsExtension {
        typ: 0x00,
        data: ext_data,
    }
}

// Helper: Rebuild ClientHello bytes
fn rebuild_client_hello(
    version: u16,
    random: &[u8; 32],
    session_id: &[u8],
    cipher_suites: &[u16],
    compression_methods: &[u8],
    extensions: &[tls_parser::extensions::TlsExtension],
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

    // Extensions
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

// Helper: Build a TLS handshake record (plaintext)
fn build_handshake_record(msg_type: HandshakeType, body: &[u8]) -> Vec<u8> {
    let mut record = Vec::new();
    record.push(0x16); // handshake record type
    record.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes()); // length of fragment
    record.push(msg_type as u8);
    record.extend_from_slice(&(body.len() as u24).to_be_bytes()); // 24-bit length
    record.extend_from_slice(body);
    record
}

// JNI functions for Android

#[no_mangle]
pub extern "system" fn Java_com_iivpn_VpnService_modifySni(
    env: JNIEnv,
    _class: JClass,
    packet: jbyteArray,
    new_sni: JString,
) -> jbyteArray {
    // Convert Java byte array to Rust slice
    let packet_len = env.get_array_length(packet).unwrap() as usize;
    let mut packet_buf = vec![0u8; packet_len];
    env.get_byte_array_region(packet, 0, &mut packet_buf).unwrap();

    // Convert Java string to Rust string
    let new_sni_str: String = env.get_string(&new_sni).unwrap().into();

    // Call the modifier
    let modified = modify_sni(&packet_buf, &new_sni_str);

    // Convert back to Java byte array
    match modified {
    Some(data) => {
        let len = data.len() as jint;
        let arr = env.new_byte_array(len).unwrap();
        env.set_byte_array_region(arr, 0, &data).unwrap();
        arr.into_inner()
    },
        None => packet, // return original if modification fails
    }
}
