use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Requested,
    Provisioning,
    Active,
    Terminating,
    Terminated,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub session_key: String,
    pub customer_id: Uuid,
    pub device_id: Uuid,
    pub region: String,
    pub node_id: Option<Uuid>,
    pub state: SessionState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: Uuid,
    pub customer_id: Uuid,
    pub name: String,
    pub public_key: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnNode {
    pub id: Uuid,
    pub region: String,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub healthy: bool,
    pub active_peer_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardClientConfig {
    pub endpoint: String,
    pub server_public_key: String,
    pub preshared_key: Option<String>,
    pub assigned_ip: String,
    pub dns_servers: Vec<String>,
    pub persistent_keepalive_secs: u16,
    pub qr_payload: String,
}
