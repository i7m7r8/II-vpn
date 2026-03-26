//! Full SNI extraction and replacement for TLS ClientHello packets.

use bytes::BytesMut;

/// Extract SNI from a TLS ClientHello packet.
pub fn extract_sni(packet: &[u8]) -> Option<String> {
    // Minimal TLS parser: look for ClientHello (handshake type 0x01) and SNI extension (0x00)
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
    let mut pos = handshake_start + 4; // skip handshake header
    // version
    pos += 2;
    // random
    pos += 32;
    // session ID
    if pos >= packet.len() { return None; }
    let session_len = packet[pos] as usize;
    pos += 1 + session_len;
    // cipher suites
    if pos + 1 >= packet.len() { return None; }
    let cipher_len = u16::from_be_bytes([packet[pos], packet[pos+1]]) as usize;
    pos += 2 + cipher_len;
    // compression methods
    if pos >= packet.len() { return None; }
    let comp_len = packet[pos] as usize;
    pos += 1 + comp_len;
    // extensions
    if pos + 1 >= packet.len() { return None; }
    let ext_len = u16::from_be_bytes([packet[pos], packet[pos+1]]) as usize;
    pos += 2;
    let end = pos + ext_len;
    if end > packet.len() { return None; }

    while pos + 2 <= end {
        let ext_type = u16::from_be_bytes([packet[pos], packet[pos+1]]);
        pos += 2;
        if pos + 2 > end { break; }
        let ext_data_len = u16::from_be_bytes([packet[pos], packet[pos+1]]) as usize;
        pos += 2;
        if pos + ext_data_len > end { break; }
        if ext_type == 0x00 {
            // SNI extension
            let sni_data = &packet[pos..pos+ext_data_len];
            if sni_data.len() < 3 { break; }
            if sni_data[0] == 0x00 {
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

/// Replace SNI in a TLS ClientHello packet.
/// Returns the modified packet, or None if no replacement was needed.
pub fn replace_sni(packet: &[u8], new_sni: &str) -> Option<Vec<u8>> {
    // Step 1: parse the ClientHello and locate the SNI extension
    if packet.len() < 5 || packet[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([packet[3], packet[4]]) as usize;
    if packet.len() < 5 + record_len {
        return None;
    }
    let handshake_start = 5;
    if packet[handshake_start] != 0x01 {
        return None;
    }

    // We'll rebuild the packet as we go, using BytesMut
    let mut output = BytesMut::with_capacity(packet.len());

    // Copy record header (5 bytes)
    output.extend_from_slice(&packet[0..5]);

    // Start of handshake data (including handshake header)
    let mut pos = handshake_start;
    // Copy handshake header (type + length) – we'll rewrite length later
    output.extend_from_slice(&packet[pos..pos+4]); // type + 3-byte length
    pos += 4;

    // Now parse the ClientHello body (excluding handshake header)
    let body_start = pos;

    // Version
    let version = u16::from_be_bytes([packet[pos], packet[pos+1]]);
    output.extend_from_slice(&packet[pos..pos+2]);
    pos += 2;
    // Random
    output.extend_from_slice(&packet[pos..pos+32]);
    pos += 32;
    // Session ID
    let session_len = packet[pos] as usize;
    output.extend_from_slice(&packet[pos..pos+1+session_len]);
    pos += 1 + session_len;
    // Cipher suites
    let cipher_len = u16::from_be_bytes([packet[pos], packet[pos+1]]) as usize;
    output.extend_from_slice(&packet[pos..pos+2+cipher_len]);
    pos += 2 + cipher_len;
    // Compression methods
    let comp_len = packet[pos] as usize;
    output.extend_from_slice(&packet[pos..pos+1+comp_len]);
    pos += 1 + comp_len;
    // Extensions length
    let ext_len = u16::from_be_bytes([packet[pos], packet[pos+1]]) as usize;
    // We will rebuild extensions, so we don't copy the original yet.
    pos += 2;

    let ext_start = pos;
    let ext_end = ext_start + ext_len;

    // Now iterate over extensions, building a new extension list with SNI replaced
    let mut new_extensions = BytesMut::new();
    let mut sni_found = false;

    let mut ext_pos = ext_start;
    while ext_pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([packet[ext_pos], packet[ext_pos+1]]);
        ext_pos += 2;
        let ext_data_len = u16::from_be_bytes([packet[ext_pos], packet[ext_pos+1]]) as usize;
        ext_pos += 2;
        let ext_data_start = ext_pos;
        let ext_data_end = ext_pos + ext_data_len;
        if ext_data_end > ext_end { break; }

        if ext_type == 0x00 && !sni_found {
            // This is the SNI extension – replace it
            sni_found = true;
            // Build new SNI extension data
            let mut sni_ext_data = Vec::new();
            sni_ext_data.push(0x00); // name type: hostname
            sni_ext_data.extend_from_slice(&(new_sni.len() as u16).to_be_bytes());
            sni_ext_data.extend_from_slice(new_sni.as_bytes());
            new_extensions.extend_from_slice(&ext_type.to_be_bytes());
            new_extensions.extend_from_slice(&(sni_ext_data.len() as u16).to_be_bytes());
            new_extensions.extend_from_slice(&sni_ext_data);
        } else {
            // Copy unchanged extension
            new_extensions.extend_from_slice(&packet[ext_pos-4..ext_data_end]);
        }
        ext_pos = ext_data_end;
    }

    // If SNI was not found, we cannot replace (nothing to replace)
    if !sni_found {
        return None;
    }

    // Write the new extensions length and extensions
    output.extend_from_slice(&(new_extensions.len() as u16).to_be_bytes());
    output.extend_from_slice(&new_extensions);

    // Now we have the full ClientHello body (including extensions).
    let client_hello_body = &output[body_start..];

    // Update the handshake length (the 3-byte length after the handshake type)
    let handshake_body_len = client_hello_body.len();
    let handshake_len_bytes = (handshake_body_len as u32).to_be_bytes();
    output[handshake_start + 1] = handshake_len_bytes[1]; // 3 bytes (big-endian)
    output[handshake_start + 2] = handshake_len_bytes[2];
    output[handshake_start + 3] = handshake_len_bytes[3];

    // Update the record length (the 2-byte length in the TLS record header)
    let record_body_len = output.len() - 5;
    let record_len_bytes = (record_body_len as u16).to_be_bytes();
    output[3] = record_len_bytes[0];
    output[4] = record_len_bytes[1];

    Some(output.to_vec())
}
