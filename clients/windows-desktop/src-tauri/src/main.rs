mod api;
mod auth;
mod models;
mod session;
mod storage;
#[cfg(windows)]
mod storage_windows;
mod wireguard;

use api::EntryApi;
use auth::AuthState;
use models::Device;
use session::DesktopClient;
#[cfg(not(windows))]
use storage::FileSecureStorage;
use tauri::Manager;
use tokio::sync::Mutex;
#[cfg(not(windows))]
use wireguard::NoopTunnelController;
#[cfg(windows)]
use wireguard::WireGuardWindowsController;

#[derive(Clone)]
struct AppConfig {
    entry_base_url: String,
    state_file_path: std::path::PathBuf,
    #[cfg(not(windows))]
    storage_key: String,
    #[cfg(windows)]
    tunnel_name: String,
    #[cfg(windows)]
    wireguard_exe: Option<std::path::PathBuf>,
    #[cfg(windows)]
    wireguard_config_dir: Option<std::path::PathBuf>,
}

struct AppState {
    config: AppConfig,
    op_lock: Mutex<()>,
}

#[derive(serde::Serialize)]
struct UiStatus {
    authenticated: bool,
    customer_id: Option<String>,
    selected_device_id: Option<String>,
    active_session_key: Option<String>,
    last_region: Option<String>,
}

#[derive(serde::Serialize)]
struct ConnectResult {
    session_key: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct OAuthLoginInput {
    provider: String,
    code: String,
    code_verifier: Option<String>,
    nonce: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterDeviceInput {
    name: String,
    public_key: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SelectDeviceInput {
    device_id: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectInput {
    region: String,
}

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

#[cfg(windows)]
type ClientType =
    DesktopClient<storage_windows::DpapiFileSecureStorage, WireGuardWindowsController>;
#[cfg(not(windows))]
type ClientType = DesktopClient<FileSecureStorage, NoopTunnelController>;

fn build_client(config: &AppConfig) -> Result<ClientType, String> {
    let api = EntryApi::new(config.entry_base_url.clone());

    #[cfg(windows)]
    let storage = storage_windows::DpapiFileSecureStorage::new(config.state_file_path.clone());

    #[cfg(not(windows))]
    let storage =
        FileSecureStorage::new(config.state_file_path.clone(), config.storage_key.clone());

    #[cfg(windows)]
    let tunnel = WireGuardWindowsController::new(
        config.tunnel_name.clone(),
        config.wireguard_exe.clone(),
        config.wireguard_config_dir.clone(),
    );

    #[cfg(not(windows))]
    let tunnel = NoopTunnelController::new("wg-client".to_string());

    DesktopClient::new(api, storage, tunnel).map_err(|e| e.to_string())
}

fn to_ui_status(client: &ClientType) -> UiStatus {
    let auth = client.auth_state().cloned();
    let runtime = client.runtime_state().clone();
    UiStatus {
        authenticated: auth.is_some(),
        customer_id: auth.map(|a: AuthState| a.customer_id),
        selected_device_id: runtime.selected_device_id,
        active_session_key: runtime.last_session_key,
        last_region: runtime.last_region,
    }
}

#[tauri::command]
async fn get_status(state: tauri::State<'_, AppState>) -> Result<UiStatus, String> {
    let _guard = state.op_lock.lock().await;
    let client = build_client(&state.config)?;
    Ok(to_ui_status(&client))
}

#[tauri::command]
async fn oauth_login(
    state: tauri::State<'_, AppState>,
    input: OAuthLoginInput,
) -> Result<UiStatus, String> {
    let _guard = state.op_lock.lock().await;
    let mut client = build_client(&state.config)?;
    client
        .login_oauth_callback(
            &input.provider,
            &input.code,
            input.code_verifier,
            input.nonce,
        )
        .await
        .map_err(|e| e.to_string())?;
    Ok(to_ui_status(&client))
}

#[tauri::command]
async fn list_devices(state: tauri::State<'_, AppState>) -> Result<Vec<Device>, String> {
    let _guard = state.op_lock.lock().await;
    let client = build_client(&state.config)?;
    client.list_devices().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn register_device(
    state: tauri::State<'_, AppState>,
    input: RegisterDeviceInput,
) -> Result<Device, String> {
    let _guard = state.op_lock.lock().await;
    let mut client = build_client(&state.config)?;
    client
        .register_device(&input.name, &input.public_key)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn select_device(
    state: tauri::State<'_, AppState>,
    input: SelectDeviceInput,
) -> Result<UiStatus, String> {
    let _guard = state.op_lock.lock().await;
    let mut client = build_client(&state.config)?;
    client
        .select_device(input.device_id)
        .map_err(|e| e.to_string())?;
    Ok(to_ui_status(&client))
}

#[tauri::command]
async fn connect(
    state: tauri::State<'_, AppState>,
    input: ConnectInput,
) -> Result<ConnectResult, String> {
    let _guard = state.op_lock.lock().await;
    let mut client = build_client(&state.config)?;
    let session_key = client
        .connect(&input.region)
        .await
        .map_err(|e| e.to_string())?;
    Ok(ConnectResult { session_key })
}

#[tauri::command]
async fn disconnect(state: tauri::State<'_, AppState>) -> Result<UiStatus, String> {
    let _guard = state.op_lock.lock().await;
    let mut client = build_client(&state.config)?;
    client.disconnect().await.map_err(|e| e.to_string())?;
    Ok(to_ui_status(&client))
}

#[tauri::command]
async fn logout(state: tauri::State<'_, AppState>) -> Result<UiStatus, String> {
    let _guard = state.op_lock.lock().await;
    let mut client = build_client(&state.config)?;
    client.logout().await.map_err(|e| e.to_string())?;
    Ok(to_ui_status(&client))
}

#[tauri::command]
async fn restore_and_reconnect(state: tauri::State<'_, AppState>) -> Result<UiStatus, String> {
    let _guard = state.op_lock.lock().await;
    let mut client = build_client(&state.config)?;
    let _ = client
        .restore_and_reconnect()
        .await
        .map_err(|e| e.to_string())?;
    Ok(to_ui_status(&client))
}

fn app_config() -> AppConfig {
    let entry_base_url =
        std::env::var("ENTRY_API_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());

    #[cfg(not(windows))]
    let storage_key = std::env::var("WG_WINDOWS_CLIENT_STORAGE_KEY")
        .unwrap_or_else(|_| "wg-local-obfuscation-key".to_string());

    #[cfg(windows)]
    let tunnel_name =
        std::env::var("WG_WINDOWS_TUNNEL_NAME").unwrap_or_else(|_| "wg-client".to_string());

    #[cfg(windows)]
    let wireguard_exe = std::env::var("WG_WINDOWS_WIREGUARD_EXE")
        .ok()
        .map(std::path::PathBuf::from);

    #[cfg(windows)]
    let wireguard_config_dir = std::env::var("WG_WINDOWS_CONFIG_DIR")
        .ok()
        .map(std::path::PathBuf::from);

    AppConfig {
        entry_base_url,
        state_file_path: state_file_path(),
        #[cfg(not(windows))]
        storage_key,
        #[cfg(windows)]
        tunnel_name,
        #[cfg(windows)]
        wireguard_exe,
        #[cfg(windows)]
        wireguard_config_dir,
    }
}

fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let state = AppState {
        config: app_config(),
        op_lock: Mutex::new(()),
    };

    tauri::Builder::default()
        .setup(|app| {
            let window = app.get_webview_window("main").expect("main window");
            window.set_title("WG Windows Client")?;
            Ok(())
        })
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            get_status,
            oauth_login,
            list_devices,
            register_device,
            select_device,
            connect,
            disconnect,
            logout,
            restore_and_reconnect
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
