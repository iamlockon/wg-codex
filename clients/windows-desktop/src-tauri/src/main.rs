#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod auth;
mod models;
mod session;
mod storage;
#[cfg(windows)]
mod storage_windows;
mod wireguard;

use api::EntryApi;
use auth::{AuthState, RuntimeState};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use models::Device;
use rand_core::OsRng;
use session::DesktopClient;
use std::collections::HashMap;
#[cfg(not(windows))]
use storage::FileSecureStorage;
use tauri::Manager;
use tokio::sync::Mutex;
#[cfg(not(windows))]
use wireguard::NoopTunnelController;
#[cfg(windows)]
use wireguard::{NoopTunnelController, WireGuardWindowsController, WindowsTunnelController};
use x25519_dalek::{PublicKey, StaticSecret};

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
    #[cfg(windows)]
    noop_tunnel: bool,
}

struct AppState {
    config: AppConfig,
    op_lock: Mutex<()>,
}

#[derive(serde::Serialize)]
struct UiStatus {
    authenticated: bool,
    customer_id: Option<String>,
    email: Option<String>,
    name: Option<String>,
    selected_device_id: Option<String>,
    active_session_key: Option<String>,
    last_region: Option<String>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct UiPublicConfig {
    google_oidc_client_id: String,
    google_oidc_redirect_uri: String,
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

fn parse_dotenv(content: &str) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let without_export = line.strip_prefix("export ").unwrap_or(line).trim();
        let Some((key, value)) = without_export.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let mut value = value.trim().to_string();
        if (value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\''))
        {
            value = value[1..value.len() - 1].to_string();
        }
        if value.trim().is_empty() {
            continue;
        }
        vars.insert(key.to_string(), value);
    }
    vars
}

fn read_dotenv_from_candidates() -> HashMap<String, String> {
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();

    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join(".env"));
        candidates.push(cwd.join("src-tauri").join("app.env"));
        candidates.push(cwd.join("ui").join(".env"));
        candidates.push(cwd.join("ui").join("src").join(".env"));
        candidates.push(
            cwd.join("clients")
                .join("windows-desktop")
                .join("src-tauri")
                .join("app.env"),
        );
        candidates.push(
            cwd.join("clients")
                .join("windows-desktop")
                .join("ui")
                .join("src")
                .join(".env"),
        );
    }

    if let Ok(exe) = std::env::current_exe()
        && let Some(app_dir) = exe.parent()
    {
        candidates.push(app_dir.join(".env"));
        candidates.push(app_dir.join("app.env"));
        candidates.push(app_dir.join("ui").join("src").join(".env"));
        candidates.push(app_dir.join("resources").join("app.env"));
        candidates.push(app_dir.join("resources").join("ui").join("src").join(".env"));
        if let Some(parent) = app_dir.parent() {
            candidates.push(parent.join("app.env"));
            candidates.push(parent.join("resources").join("app.env"));
        }
    }

    let mut merged = HashMap::new();
    for candidate in candidates {
        if let Ok(content) = std::fs::read_to_string(&candidate) {
            for (k, v) in parse_dotenv(&content) {
                merged.insert(k, v);
            }
        }
    }

    merged
}

fn config_var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .and_then(|v| {
            if v.trim().is_empty() {
                None
            } else {
                Some(v)
            }
        })
        .or_else(|| read_dotenv_from_candidates().get(name).cloned())
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
    DesktopClient<storage_windows::DpapiFileSecureStorage, WindowsTunnelController>;
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
    let tunnel = if config.noop_tunnel {
        tracing::warn!("WG_WINDOWS_NOOP_TUNNEL enabled; VPN tunnel actions are no-op");
        WindowsTunnelController::Noop(NoopTunnelController::new(config.tunnel_name.clone()))
    } else {
        WindowsTunnelController::Real(WireGuardWindowsController::new(
            config.tunnel_name.clone(),
            config.wireguard_exe.clone(),
            config.wireguard_config_dir.clone(),
        ))
    };

    #[cfg(not(windows))]
    let tunnel = NoopTunnelController::new("wg-client".to_string());

    DesktopClient::new(api, storage, tunnel).map_err(|e| e.to_string())
}

fn to_ui_status(client: &ClientType) -> UiStatus {
    let auth = client.auth_state().cloned();
    let runtime = client.runtime_state().clone();
    UiStatus {
        authenticated: auth.is_some(),
        customer_id: auth.as_ref().map(|a: &AuthState| a.customer_id.clone()),
        email: auth.as_ref().and_then(|a: &AuthState| a.email.clone()),
        name: auth.as_ref().and_then(|a: &AuthState| a.name.clone()),
        selected_device_id: runtime.selected_device_id,
        active_session_key: runtime.last_session_key,
        last_region: runtime.last_region,
    }
}

#[tauri::command]
async fn get_status(state: tauri::State<'_, AppState>) -> Result<UiStatus, String> {
    let _guard = state.op_lock.lock().await;
    let mut client = build_client(&state.config)?;
    client.reconcile_auth().await.map_err(|e| e.to_string())?;
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
async fn register_default_device(state: tauri::State<'_, AppState>) -> Result<Device, String> {
    let _guard = state.op_lock.lock().await;
    let mut client = build_client(&state.config)?;
    let devices = client.list_devices().await.map_err(|e| e.to_string())?;
    if let Some(existing) = pick_reusable_device(&devices, client.runtime_state()) {
        client
            .select_device(existing.id.clone())
            .map_err(|e| e.to_string())?;
        return Ok(existing);
    }

    let name = default_device_name();
    let (private_key, public_key) = generate_wireguard_keypair();
    let device = client
        .register_device(&name, &public_key)
        .await
        .map_err(|e| e.to_string())?;
    client
        .remember_device_private_key(device.id.clone(), private_key)
        .map_err(|e| e.to_string())?;
    Ok(device)
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
    // Keep disconnect independent from op_lock so users can always force local teardown.
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
    let entry_base_url = config_var("ENTRY_API_BASE_URL")
        .unwrap_or_else(|| "http://127.0.0.1:8080".to_string());

    #[cfg(not(windows))]
    let storage_key = std::env::var("WG_WINDOWS_CLIENT_STORAGE_KEY")
        .unwrap_or_else(|_| "wg-local-obfuscation-key".to_string());

    #[cfg(windows)]
    let tunnel_name = config_var("WG_WINDOWS_TUNNEL_NAME").unwrap_or_else(|| "wg-client".to_string());

    #[cfg(windows)]
    let wireguard_exe = config_var("WG_WINDOWS_WIREGUARD_EXE").map(std::path::PathBuf::from);

    #[cfg(windows)]
    let wireguard_config_dir = config_var("WG_WINDOWS_CONFIG_DIR").map(std::path::PathBuf::from);

    #[cfg(windows)]
    let noop_tunnel = config_var("WG_WINDOWS_NOOP_TUNNEL")
        .map(|v| {
            let value = v.trim().to_ascii_lowercase();
            value == "1" || value == "true" || value == "yes" || value == "on"
        })
        .unwrap_or(false);

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
        #[cfg(windows)]
        noop_tunnel,
    }
}

#[tauri::command]
async fn get_public_config() -> Result<UiPublicConfig, String> {
    Ok(UiPublicConfig {
        google_oidc_client_id: config_var("VITE_GOOGLE_OIDC_CLIENT_ID").unwrap_or_default(),
        google_oidc_redirect_uri: config_var("VITE_GOOGLE_OIDC_REDIRECT_URI").unwrap_or_default(),
    })
}

fn default_device_name() -> String {
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "desktop".to_string());
    format!("desktop-{}", host.to_lowercase())
}

fn pick_reusable_device(devices: &[Device], runtime: &RuntimeState) -> Option<Device> {
    if let Some(selected_id) = &runtime.selected_device_id
        && runtime.device_private_keys.contains_key(selected_id)
        && let Some(selected) = devices.iter().find(|d| &d.id == selected_id)
    {
        return Some(selected.clone());
    }

    devices
        .iter()
        .filter(|d| runtime.device_private_keys.contains_key(&d.id))
        .max_by(|a, b| a.created_at.cmp(&b.created_at))
        .cloned()
}

fn generate_wireguard_keypair() -> (String, String) {
    let private_key = StaticSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&private_key);
    (
        STANDARD.encode(private_key.to_bytes()),
        STANDARD.encode(public_key.as_bytes()),
    )
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
            get_public_config,
            oauth_login,
            list_devices,
            register_device,
            register_default_device,
            select_device,
            connect,
            disconnect,
            logout,
            restore_and_reconnect
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
