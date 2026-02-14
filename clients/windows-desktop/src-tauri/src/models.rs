use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub customer_id: String,
    pub name: String,
    pub public_key: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardClientConfig {
    pub endpoint: String,
    pub server_public_key: String,
    pub preshared_key: Option<String>,
    pub assigned_ip: String,
    pub dns_servers: Vec<String>,
    pub persistent_keepalive_secs: i32,
    pub qr_payload: String,
    #[serde(default)]
    pub client_private_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum StartSessionResponse {
    Active {
        session_key: String,
        region: String,
        config: WireGuardClientConfig,
    },
    Conflict {
        existing_session_key: String,
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentSessionResponse {
    pub active: bool,
    pub session_key: Option<String>,
    pub region: Option<String>,
    pub device_id: Option<String>,
    pub connected_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCallbackRequest {
    pub code: String,
    pub code_verifier: Option<String>,
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCallbackResponse {
    pub provider: String,
    pub customer_id: String,
    pub access_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDeviceRequest {
    pub name: String,
    pub public_key: String,
}
