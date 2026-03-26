use std::os::unix::io::FromRawFd;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::runtime::Handle;
use bytes::BytesMut;
use etherparse::{Ipv4Header, TcpHeader, TransportSlice};
use crate::error::Result;
use crate::sni;

const MTU: usize = 1500;
const TOR_SOCKS_ADDR: &str = "127.0.0.1:9150";

// Shared mapping of connection tracking (source -> destination via Tor)
type ConnMap = std::collections::HashMap<(u32, u16), (u32, u16)>; // (src_ip, src_port) -> (dst_ip, dst_port)

static CONNECTIONS: tokio::sync::Mutex<ConnMap> = tokio::sync::Mutex::new(ConnMap::new());

pub async fn start(tun_fd: i32) -> Result<()> {
    let mut tun = unsafe { std::fs::File::from_raw_fd(tun_fd) };
    let mut buffer = [0u8; MTU];
    log::info!("VPN thread started on fd {}", tun_fd);

    let rt_handle = Handle::current();

    loop {
        match tun.read(&mut buffer) {
            Ok(n) if n > 0 => {
                let packet = &buffer[..n];
                // Parse IPv4 header
                match Ipv4Header::from_slice(packet) {
                    Ok((ip_header, payload)) => {
                        let src_ip = u32::from_be_bytes(ip_header.source.octets());
                        let dst_ip = u32::from_be_bytes(ip_header.destination.octets());

                        // Only handle TCP packets
                        if ip_header.protocol != 6 {
                            // Not TCP, just forward directly? For now, we'll just drop non-TCP.
                            continue;
                        }

                        match TcpHeader::from_slice(payload) {
                            Ok((tcp_header, tcp_payload)) => {
                                let src_port = tcp_header.source;
                                let dst_port = tcp_header.destination;

                                // Check if this is TLS (port 443 or a configured port)
                                let is_tls = dst_port == 443 || dst_port == 8443;

                                let modified_payload = if is_tls && !tcp_payload.is_empty() {
                                    // Try to extract SNI and replace if a rule exists
                                    if let Some(new_sni) = {
                                        let sni = sni::extract_sni(tcp_payload)?;
                                        crate::rules::get_replacement(&sni)
                                    } {
                                        if let Some(modified_tls) = sni::replace_sni(tcp_payload, &new_sni) {
                                            Some(modified_tls)
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                };

                                let final_payload = modified_payload.as_deref().unwrap_or(tcp_payload);

                                // Forward this packet through Tor's SOCKS5 proxy.
                                // We need to establish a TCP connection to the destination via Tor.
                                // For simplicity, we'll spawn a new task for each new connection.
                                let key = (src_ip, src_port);
                                let dst = (dst_ip, dst_port);
                                {
                                    let mut conns = CONNECTIONS.lock().await;
                                    if !conns.contains_key(&key) {
                                        conns.insert(key, dst);
                                        // Spawn a task to handle the connection
                                        let tun_fd_clone = tun_fd;
                                        let rt_handle = rt_handle.clone();
                                        rt_handle.spawn(async move {
                                            handle_tcp_connection(tun_fd_clone, src_ip, src_port, dst_ip, dst_port).await;
                                        });
                                    }
                                }

                                // Write the packet back to the tun (the modified packet will be sent
                                // via the TCP stream, not directly here). Actually, for the initial SYN,
                                // we need to let the system know we accepted it.
                                // For now, we'll just write the packet unchanged to the tun.
                                // A full implementation would forward data through the TCP stream.
                                // We'll implement handle_tcp_connection separately.
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

async fn handle_tcp_connection(tun_fd: i32, src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) {
    // Connect to Tor SOCKS5 proxy
    let proxy_addr = TOR_SOCKS_ADDR.parse::<SocketAddr>().unwrap();
    let mut proxy_stream = match TcpStream::connect(proxy_addr).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to connect to Tor proxy: {}", e);
            return;
        }
    };

    // Send SOCKS5 handshake
    // Simplified: we assume no authentication, and send the destination address
    // This is a minimal implementation; you'd need to handle the full SOCKS5 protocol.
    // For brevity, we'll skip the full handshake here; in production, use a proper SOCKS5 library.
    // Instead, we'll just forward raw packets to the proxy (which expects the data after handshake).
    // For a real VPN, you'd need to implement SOCKS5 connection establishment.
    // We'll leave this as a placeholder.

    // Now, we need to read data from the tun and forward to the proxy, and read from proxy and write to tun.
    // This requires two bidirectional loops. For simplicity, we'll just log.
    log::info!("TCP connection handled (placeholder)");
}
