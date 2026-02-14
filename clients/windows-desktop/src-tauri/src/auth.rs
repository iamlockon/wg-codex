use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthState {
    pub customer_id: String,
    pub access_token: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeState {
    pub selected_device_id: Option<String>,
    pub last_region: Option<String>,
    pub last_session_key: Option<String>,
    #[serde(default)]
    pub device_private_keys: HashMap<String, String>,
}
