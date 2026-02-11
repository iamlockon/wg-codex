mod api;
mod auth;
mod models;
mod session;
mod storage;
mod wireguard;

use api::EntryApi;
use session::DesktopClient;
use storage::FileSecureStorage;
use wireguard::NoopTunnelController;

fn state_file_path() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("WG_WINDOWS_CLIENT_STATE_FILE") {
        return std::path::PathBuf::from(path);
    }
    std::env::temp_dir().join("wg-windows-client-state.json")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let entry_base_url =
        std::env::var("ENTRY_API_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let storage_key = std::env::var("WG_WINDOWS_CLIENT_STORAGE_KEY")
        .unwrap_or_else(|_| "wg-local-obfuscation-key".to_string());

    let api = EntryApi::new(entry_base_url);
    let storage = FileSecureStorage::new(state_file_path(), storage_key);
    let tunnel = NoopTunnelController::new("wg-client".to_string());
    let _client = DesktopClient::new(api, storage, tunnel)
        .map_err(|e| anyhow::anyhow!("client init failed: {e}"))?;

    println!("wg windows desktop core initialized");
    Ok(())
}
