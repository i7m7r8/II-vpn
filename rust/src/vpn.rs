use std::fs::File;
use std::os::unix::io::FromRawFd;
use std::io::{Read, Write};
use crate::error::Result;

const MTU: usize = 1500;

pub async fn start(tun_fd: i32) -> Result<()> {
    let mut tun = unsafe { File::from_raw_fd(tun_fd) };
    let mut buffer = [0u8; MTU];
    log::info!("VPN thread started on fd {}", tun_fd);
    loop {
        match tun.read(&mut buffer) {
            Ok(n) if n > 0 => {
                // TODO: parse IP/TCP, detect TLS, call SNI replacement, forward via Tor SOCKS
                tun.write_all(&buffer[..n])?;
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
