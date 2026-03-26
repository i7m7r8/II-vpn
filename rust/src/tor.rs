use arti_client::{TorClient, TorClientConfig};
use std::sync::Arc;
use tokio::sync::Mutex;
use once_cell::sync::Lazy;
use tokio::runtime::Runtime;
use crate::error::Result;

static RUNTIME: Lazy<Runtime> = Lazy::new(|| Runtime::new().expect("Failed to create Tokio runtime"));
static TOR_CLIENT: Lazy<Arc<Mutex<Option<TorClient<arti_client::tor_rtcompat::PreferredRuntime>>>>> =
    Lazy::new(|| Arc::new(Mutex::new(None)));

pub async fn start() -> Result<()> {
    let config = TorClientConfig::builder()
        .socks_port(9150)
        .build()
        .map_err(|e| crate::error::IIVpnError::Tor(e.to_string()))?;
    let client = TorClient::create_bootstrapped(config)
        .await
        .map_err(|e| crate::error::IIVpnError::Tor(e.to_string()))?;
    let mut guard = TOR_CLIENT.lock().await;
    *guard = Some(client);
    log::info!("Tor started on port 9150");
    Ok(())
}

pub async fn is_running() -> bool {
    TOR_CLIENT.lock().await.is_some()
}

pub fn start_sync() -> i32 {
    RUNTIME.block_on(async {
        match start().await {
            Ok(_) => 0,
            Err(e) => {
                log::error!("Tor start failed: {}", e);
                1
            }
        }
    })
}

pub fn is_running_sync() -> bool {
    RUNTIME.block_on(is_running())
}
