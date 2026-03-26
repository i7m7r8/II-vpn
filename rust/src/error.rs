use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IIVpnError {
    #[error("JNI error: {0}")]
    Jni(String),
    #[error("Tor error: {0}")]
    Tor(String),
    #[error("SNI error: {0}")]
    Sni(String),
    #[error("VPN error: {0}")]
    Vpn(String),
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Serde error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, IIVpnError>;
