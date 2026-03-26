use std::os::unix::io::FromRawFd;
use std::io::Read;
use etherparse::{Ipv4Header, TcpHeader};
use crate::sni;
use crate::rules;

const MTU: usize = 1500;

pub async fn start(_tun_fd: i32) -> crate::error::Result<()> {
    // For now, just log and do nothing. The real implementation will be added later.
    log::info!("VPN start – placeholder (will read from tun and forward to Tor)");
    // In a real implementation, you'd open the tun file descriptor and start a loop.
    // We'll keep it simple for now to ensure compilation.
    Ok(())
}
