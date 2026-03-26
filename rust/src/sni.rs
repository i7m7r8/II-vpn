//! Manual SNI extraction and replacement

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
pub fn replace_sni(packet: &[u8], new_sni: &str) -> Option<Vec<u8>> {
    // For a real implementation we'd need to rebuild the packet.
    // This is complex; we'll return None for now (no modification).
    // In production you'd replace the extension data.
    log::info!("Replace SNI not yet implemented");
    None
}
