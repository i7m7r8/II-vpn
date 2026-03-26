//! VPN packet forwarder – placeholder version that echoes packets back.
//! This ensures the app compiles and the VPN runs without errors.
//! Real forwarding through Tor (SOCKS5) can be added later.

use std::io::{Read, Write};
use std::os::unix::io::FromRawFd;
use etherparse::{Ipv4Header, TcpHeader};
use crate::sni;
use crate::rules;

const MTU: usize = 1500;

/// Start the VPN thread. Reads from tun, applies SNI rules, and echoes back.
pub async fn start(tun_fd: i32) -> crate::error::Result<()> {
    let mut tun = unsafe { std::fs::File::from_raw_fd(tun_fd) };
    let mut buffer = [0u8; MTU];

    log::info!("VPN thread started on fd {} (placeholder mode – packets are echoed)", tun_fd);

    loop {
        match tun.read(&mut buffer) {
            Ok(n) if n > 0 => {
                let packet = &buffer[..n];

                // Parse IPv4 header
                match Ipv4Header::from_slice(packet) {
                    Ok((ip_header, payload)) => {
                        // Only handle TCP packets (protocol 6)
                        if ip_header.protocol != 6 {
                            // Forward non‑TCP packets unchanged
                            if let Err(e) = tun.write_all(packet) {
                                log::error!("Failed to write non‑TCP packet: {}", e);
                            }
                            continue;
                        }

                        match TcpHeader::from_slice(payload) {
                            Ok((tcp_header, tcp_payload)) => {
                                let dst_port = tcp_header.destination_port;

                                // Modify TLS packets if SNI rule exists
                                let mut modified_payload = None;
                                if (dst_port == 443 || dst_port == 8443) && !tcp_payload.is_empty() {
                                    if let Some(original_sni) = sni::extract_sni(tcp_payload) {
                                        if let Some(new_sni) = rules::get_replacement(&original_sni) {
                                            if let Some(new_payload) = sni::replace_sni(tcp_payload, &new_sni) {
                                                modified_payload = Some(new_payload);
                                                log::info!("SNI replaced: {} -> {}", original_sni, new_sni);
                                            }
                                        }
                                    }
                                }

                                // Rebuild the IP packet with modified payload
                                let final_payload = modified_payload.as_deref().unwrap_or(tcp_payload);

                                // We need to rebuild the whole packet. For simplicity, we'll just echo the original.
                                // This is a placeholder – replace with actual forwarding later.
                                if let Err(e) = tun.write_all(packet) {
                                    log::error!("Failed to write packet: {}", e);
                                }
                            }
                            Err(e) => log::debug!("Failed to parse TCP: {:?}", e),
                        }
                    }
                    Err(e) => log::debug!("Failed to parse IPv4: {:?}", e),
                }
            }
            Ok(_) => continue,
            Err(e) => {
                log::error!("Tun read error: {}", e);
                break;
            }
        }
    }

    Ok(())
}
