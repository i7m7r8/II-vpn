use sni::TlsSni;

pub fn extract_sni(packet: &[u8]) -> Option<String> {
    match sni::extract_sni(packet) {
        TlsSni::Some(sni) => Some(sni.to_string()),
        _ => None,
    }
}

pub fn replace_sni(packet: &[u8], new_sni: &str) -> Option<Vec<u8>> {
    sni::replace_sni(packet, new_sni).ok()
}
