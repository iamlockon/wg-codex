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
use wireguard::{NoopTunnelController, WindowsTunnelController, WireGuardWindowsController};
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
    ui_overrides: Mutex<UiConfigOverrides>,
    ui_overrides_path: std::path::PathBuf,
    op_lock: Mutex<()>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct UiConfigOverrides {
    entry_api_base_url: Option<String>,
    #[cfg(windows)]
    wireguard_exe: Option<String>,
    google_oidc_client_id: Option<String>,
    google_oidc_redirect_uri: Option<String>,
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
struct UiPublicConfig {
    google_oidc_client_id: String,
    google_oidc_redirect_uri: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct UiAppConfig {
    entry_api_base_url: String,
    #[cfg(windows)]
    wireguard_exe: String,
    google_oidc_client_id: String,
    google_oidc_redirect_uri: String,
}

#[derive(serde::Serialize)]
struct ConnectResult {
    session_key: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateUiAppConfigInput {
    entry_api_base_url: String,
    #[cfg(windows)]
    wireguard_exe: String,
    google_oidc_client_id: String,
    google_oidc_redirect_uri: String,
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
        candidates.push(
            app_dir
                .join("resources")
                .join("ui")
                .join("src")
                .join(".env"),
        );
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
        .and_then(|v| if v.trim().is_empty() { None } else { Some(v) })
        .or_else(|| read_dotenv_from_candidates().get(name).cloned())
}

fn normalize_optional_value(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalize_optional_http_url(raw: &str) -> Result<Option<String>, String> {
    let Some(value) = normalize_optional_value(raw) else {
        return Ok(None);
    };
    let parsed =
        reqwest::Url::parse(&value).map_err(|err| format!("invalid_entry_api_base_url: {err}"))?;
    match parsed.scheme() {
        "http" | "https" => Ok(Some(value)),
        _ => Err("invalid_entry_api_base_url: scheme must be http or https".to_string()),
    }
}

fn ui_overrides_path(state_file_path: &std::path::Path) -> std::path::PathBuf {
    if let Some(parent) = state_file_path.parent() {
        return parent.join("ui-overrides.json");
    }
    std::env::temp_dir().join("wg-windows-client-ui-overrides.json")
}

fn load_ui_overrides(path: &std::path::Path) -> UiConfigOverrides {
    match std::fs::read_to_string(path) {
        Ok(content) => match serde_json::from_str::<UiConfigOverrides>(&content) {
            Ok(parsed) => parsed,
            Err(err) => {
                tracing::warn!(
                    "failed to parse UI overrides at {}: {}",
                    path.display(),
                    err
                );
                UiConfigOverrides::default()
            }
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => UiConfigOverrides::default(),
        Err(err) => {
            tracing::warn!("failed to read UI overrides at {}: {}", path.display(), err);
            UiConfigOverrides::default()
        }
    }
}

fn save_ui_overrides(path: &std::path::Path, overrides: &UiConfigOverrides) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create config directory: {err}"))?;
    }
    let serialized = serde_json::to_string_pretty(overrides)
        .map_err(|err| format!("serialize failed: {err}"))?;
    std::fs::write(path, serialized).map_err(|err| format!("write failed: {err}"))?;
    Ok(())
}

fn ui_app_config_from(base: &AppConfig, overrides: &UiConfigOverrides) -> UiAppConfig {
    let effective = base.with_ui_overrides(overrides);
    UiAppConfig {
        entry_api_base_url: effective.entry_base_url,
        #[cfg(windows)]
        wireguard_exe: effective
            .wireguard_exe
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default(),
        google_oidc_client_id: overrides.google_oidc_client_id.clone().unwrap_or_default(),
        google_oidc_redirect_uri: overrides
            .google_oidc_redirect_uri
            .clone()
            .unwrap_or_default(),
    }
}

impl AppConfig {
    fn with_ui_overrides(&self, overrides: &UiConfigOverrides) -> Self {
        let mut next = self.clone();
        if let Some(entry_api_base_url) = overrides.entry_api_base_url.as_ref() {
            next.entry_base_url = entry_api_base_url.clone();
        }
        #[cfg(windows)]
        if let Some(wireguard_exe) = overrides.wireguard_exe.as_ref() {
            next.wireguard_exe = Some(std::path::PathBuf::from(wireguard_exe));
        }
        next
    }
}

impl AppState {
    async fn effective_config(&self) -> AppConfig {
        let overrides = self.ui_overrides.lock().await.clone();
        self.config.with_ui_overrides(&overrides)
    }

    async fn ui_app_config(&self) -> UiAppConfig {
        let overrides = self.ui_overrides.lock().await.clone();
        ui_app_config_from(&self.config, &overrides)
    }
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
type ClientType = DesktopClient<storage_windows::DpapiFileSecureStorage, WindowsTunnelController>;
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
    let config = state.effective_config().await;
    let mut client = build_client(&config)?;
    client.reconcile_auth().await.map_err(|e| e.to_string())?;
    Ok(to_ui_status(&client))
}

#[tauri::command]
async fn oauth_login(
    state: tauri::State<'_, AppState>,
    input: OAuthLoginInput,
) -> Result<UiStatus, String> {
    let _guard = state.op_lock.lock().await;
    let config = state.effective_config().await;
    let mut client = build_client(&config)?;
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
    let config = state.effective_config().await;
    let client = build_client(&config)?;
    client.list_devices().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn register_device(
    state: tauri::State<'_, AppState>,
    input: RegisterDeviceInput,
) -> Result<Device, String> {
    let _guard = state.op_lock.lock().await;
    let config = state.effective_config().await;
    let mut client = build_client(&config)?;
    client
        .register_device(&input.name, &input.public_key)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn register_default_device(state: tauri::State<'_, AppState>) -> Result<Device, String> {
    let _guard = state.op_lock.lock().await;
    let config = state.effective_config().await;
    let mut client = build_client(&config)?;
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
    let config = state.effective_config().await;
    let mut client = build_client(&config)?;
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
    let config = state.effective_config().await;
    let mut client = build_client(&config)?;
    let session_key = client
        .connect(&input.region)
        .await
        .map_err(|e| e.to_string())?;
    Ok(ConnectResult { session_key })
}

#[tauri::command]
async fn disconnect(state: tauri::State<'_, AppState>) -> Result<UiStatus, String> {
    // Keep disconnect independent from op_lock so users can always force local teardown.
    let config = state.effective_config().await;
    let mut client = build_client(&config)?;
    client.disconnect().await.map_err(|e| e.to_string())?;
    Ok(to_ui_status(&client))
}

#[tauri::command]
async fn logout(state: tauri::State<'_, AppState>) -> Result<UiStatus, String> {
    let _guard = state.op_lock.lock().await;
    let config = state.effective_config().await;
    let mut client = build_client(&config)?;
    client.logout().await.map_err(|e| e.to_string())?;
    Ok(to_ui_status(&client))
}

#[tauri::command]
async fn restore_and_reconnect(state: tauri::State<'_, AppState>) -> Result<UiStatus, String> {
    let _guard = state.op_lock.lock().await;
    let config = state.effective_config().await;
    let mut client = build_client(&config)?;
    let _ = client
        .restore_and_reconnect()
        .await
        .map_err(|e| e.to_string())?;
    Ok(to_ui_status(&client))
}

fn app_config() -> AppConfig {
    let entry_base_url =
        config_var("ENTRY_API_BASE_URL").unwrap_or_else(|| "http://127.0.0.1:8080".to_string());

    #[cfg(not(windows))]
    let storage_key = std::env::var("WG_WINDOWS_CLIENT_STORAGE_KEY")
        .unwrap_or_else(|_| "wg-local-obfuscation-key".to_string());

    #[cfg(windows)]
    let tunnel_name =
        config_var("WG_WINDOWS_TUNNEL_NAME").unwrap_or_else(|| "wg-client".to_string());

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
async fn get_app_config(state: tauri::State<'_, AppState>) -> Result<UiAppConfig, String> {
    Ok(state.ui_app_config().await)
}

#[tauri::command]
async fn set_app_config(
    state: tauri::State<'_, AppState>,
    input: UpdateUiAppConfigInput,
) -> Result<UiAppConfig, String> {
    let _guard = state.op_lock.lock().await;
    let mut overrides = state.ui_overrides.lock().await;
    overrides.entry_api_base_url = normalize_optional_http_url(&input.entry_api_base_url)?;
    #[cfg(windows)]
    {
        overrides.wireguard_exe = normalize_optional_value(&input.wireguard_exe);
    }
    overrides.google_oidc_client_id = normalize_optional_value(&input.google_oidc_client_id);
    overrides.google_oidc_redirect_uri = normalize_optional_value(&input.google_oidc_redirect_uri);
    save_ui_overrides(&state.ui_overrides_path, &overrides)?;
    Ok(ui_app_config_from(&state.config, &overrides))
}

#[tauri::command]
async fn get_public_config(state: tauri::State<'_, AppState>) -> Result<UiPublicConfig, String> {
    let overrides = state.ui_overrides.lock().await.clone();
    let effective_config = state.config.with_ui_overrides(&overrides);
    let api = EntryApi::new(effective_config.entry_base_url);
    let mut merged = match api.public_client_config().await {
        Ok(remote) => UiPublicConfig {
            google_oidc_client_id: remote.google_oidc_client_id,
            google_oidc_redirect_uri: remote.google_oidc_redirect_uri,
        },
        Err(err) => {
            tracing::warn!("failed to load public config from entry: {}", err);
            UiPublicConfig {
                google_oidc_client_id: String::new(),
                google_oidc_redirect_uri: String::new(),
            }
        }
    };

    if let Some(client_id) = overrides.google_oidc_client_id.as_ref() {
        merged.google_oidc_client_id = client_id.clone();
    }
    if let Some(redirect_uri) = overrides.google_oidc_redirect_uri.as_ref() {
        merged.google_oidc_redirect_uri = redirect_uri.clone();
    }

    if merged.google_oidc_client_id.trim().is_empty()
        || merged.google_oidc_redirect_uri.trim().is_empty()
    {
        return Err("missing_google_oauth_ui_config (configure GOOGLE_OIDC_CLIENT_ID and GOOGLE_OIDC_REDIRECT_URI in entry, or set local app overrides in Settings)".to_string());
    }
    Ok(merged)
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
    let config = app_config();
    let ui_overrides_path = ui_overrides_path(&config.state_file_path);
    let ui_overrides = load_ui_overrides(&ui_overrides_path);
    let state = AppState {
        config,
        ui_overrides: Mutex::new(ui_overrides),
        ui_overrides_path,
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
            get_app_config,
            set_app_config,
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
