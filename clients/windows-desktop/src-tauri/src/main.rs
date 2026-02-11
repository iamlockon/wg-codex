mod api;
mod auth;
mod models;
mod session;
mod storage;
#[cfg(windows)]
mod storage_windows;
mod wireguard;

use api::EntryApi;
use session::DesktopClient;
#[cfg(not(windows))]
use storage::FileSecureStorage;
#[cfg(not(windows))]
use wireguard::NoopTunnelController;
#[cfg(windows)]
use wireguard::WireGuardWindowsController;

fn state_file_path() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("WG_WINDOWS_CLIENT_STATE_FILE") {
        return std::path::PathBuf::from(path);
    }
    #[cfg(windows)]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            return std::path::PathBuf::from(local_app_data)
                .join("wg-windows-client")
                .join("state.json");
        }
    }
    std::env::temp_dir().join("wg-windows-client-state.json")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let entry_base_url =
        std::env::var("ENTRY_API_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let api = EntryApi::new(entry_base_url);
    #[cfg(windows)]
    let _client = {
        let storage = storage_windows::DpapiFileSecureStorage::new(state_file_path());
        let tunnel_name =
            std::env::var("WG_WINDOWS_TUNNEL_NAME").unwrap_or_else(|_| "wg-client".to_string());
        let tunnel = WireGuardWindowsController::new(
            tunnel_name,
            std::env::var("WG_WINDOWS_WIREGUARD_EXE")
                .ok()
                .map(std::path::PathBuf::from),
            std::env::var("WG_WINDOWS_CONFIG_DIR")
                .ok()
                .map(std::path::PathBuf::from),
        );
        DesktopClient::new(api, storage, tunnel)
            .map_err(|e| anyhow::anyhow!("client init failed: {e}"))?
    };

    #[cfg(not(windows))]
    let _client = {
        let storage_key = std::env::var("WG_WINDOWS_CLIENT_STORAGE_KEY")
            .unwrap_or_else(|_| "wg-local-obfuscation-key".to_string());
        let storage = FileSecureStorage::new(state_file_path(), storage_key);
        let tunnel = NoopTunnelController::new("wg-client".to_string());
        DesktopClient::new(api, storage, tunnel)
            .map_err(|e| anyhow::anyhow!("client init failed: {e}"))?
    };

    println!("wg windows desktop core initialized");
    Ok(())
}
