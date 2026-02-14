use crate::api::{EntryApi, EntryApiError, StartSessionRequest};
use crate::auth::{AuthState, RuntimeState};
use crate::models::{OAuthCallbackRequest, RegisterDeviceRequest, StartSessionResponse};
use crate::storage::SecureStorage;
use crate::wireguard::TunnelController;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("not authenticated")]
    NotAuthenticated,
    #[error("no selected device")]
    NoSelectedDevice,
    #[error("api error: {0}")]
    Api(#[from] EntryApiError),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("tunnel error: {0}")]
    Tunnel(String),
}

pub struct DesktopClient<S: SecureStorage, T: TunnelController> {
    api: EntryApi,
    storage: S,
    tunnel: T,
    auth: Option<AuthState>,
    runtime: RuntimeState,
}

impl<S: SecureStorage, T: TunnelController> DesktopClient<S, T> {
    pub fn new(api: EntryApi, storage: S, tunnel: T) -> Result<Self, ClientError> {
        let auth = storage
            .load_auth_state()
            .map_err(|e| ClientError::Storage(e.to_string()))?;
        let runtime = storage
            .load_runtime_state()
            .map_err(|e| ClientError::Storage(e.to_string()))?;
        Ok(Self {
            api,
            storage,
            tunnel,
            auth,
            runtime,
        })
    }

    pub fn auth_state(&self) -> Option<&AuthState> {
        self.auth.as_ref()
    }

    pub fn runtime_state(&self) -> &RuntimeState {
        &self.runtime
    }

    pub fn select_device(&mut self, device_id: String) -> Result<(), ClientError> {
        self.runtime.selected_device_id = Some(device_id);
        self.storage
            .save_runtime_state(&self.runtime)
            .map_err(|e| ClientError::Storage(e.to_string()))
    }

    pub fn remember_device_private_key(
        &mut self,
        device_id: String,
        private_key: String,
    ) -> Result<(), ClientError> {
        self.runtime.device_private_keys.insert(device_id, private_key);
        self.storage
            .save_runtime_state(&self.runtime)
            .map_err(|e| ClientError::Storage(e.to_string()))
    }

    pub async fn login_oauth_callback(
        &mut self,
        provider: &str,
        code: &str,
        code_verifier: Option<String>,
        nonce: Option<String>,
    ) -> Result<(), ClientError> {
        let response = self
            .api
            .oauth_callback(
                provider,
                OAuthCallbackRequest {
                    code: code.to_string(),
                    code_verifier,
                    nonce,
                },
            )
            .await?;
        self.auth = Some(AuthState {
            customer_id: response.customer_id,
            access_token: response.access_token,
        });
        self.storage
            .save_auth_state(self.auth.as_ref().expect("just set"))
            .map_err(|e| ClientError::Storage(e.to_string()))
    }

    pub async fn list_devices(&self) -> Result<Vec<crate::models::Device>, ClientError> {
        let token = self.access_token()?;
        self.api.list_devices(token).await.map_err(Into::into)
    }

    pub async fn register_device(
        &mut self,
        name: &str,
        public_key: &str,
    ) -> Result<crate::models::Device, ClientError> {
        let token = self.access_token()?;
        let device = self
            .api
            .register_device(
                token,
                RegisterDeviceRequest {
                    name: name.to_string(),
                    public_key: public_key.to_string(),
                },
            )
            .await?;
        self.select_device(device.id.clone())?;
        Ok(device)
    }

    pub async fn connect(&mut self, region: &str) -> Result<String, ClientError> {
        let token = self.access_token()?;
        let device_id = self
            .runtime
            .selected_device_id
            .clone()
            .ok_or(ClientError::NoSelectedDevice)?;

        let first = self
            .api
            .start_session(
                token,
                StartSessionRequest {
                    device_id: device_id.clone(),
                    region: region.to_string(),
                    country_code: None,
                    city_code: None,
                    pool: None,
                    reconnect_session_key: None,
                    node_hint: None,
                },
            )
            .await?;

        let response = match first {
            StartSessionResponse::Active {
                session_key,
                region,
                mut config,
            } => {
                if let Some(private_key) = self.runtime.device_private_keys.get(&device_id).cloned() {
                    config.client_private_key = Some(private_key);
                }
                self.tunnel
                    .apply_and_up(&config)
                    .map_err(|e| ClientError::Tunnel(e.to_string()))?;
                self.runtime.last_session_key = Some(session_key.clone());
                self.runtime.last_region = Some(region);
                self.storage
                    .save_runtime_state(&self.runtime)
                    .map_err(|e| ClientError::Storage(e.to_string()))?;
                return Ok(session_key);
            }
            StartSessionResponse::Conflict {
                existing_session_key,
                ..
            } => {
                self.api
                    .start_session(
                        token,
                        StartSessionRequest {
                            device_id: device_id.clone(),
                            region: region.to_string(),
                            country_code: None,
                            city_code: None,
                            pool: None,
                            reconnect_session_key: Some(existing_session_key),
                            node_hint: None,
                        },
                    )
                    .await?
            }
        };

        match response {
            StartSessionResponse::Active {
                session_key,
                region,
                mut config,
            } => {
                if let Some(private_key) = self.runtime.device_private_keys.get(&device_id).cloned() {
                    config.client_private_key = Some(private_key);
                }
                self.tunnel
                    .apply_and_up(&config)
                    .map_err(|e| ClientError::Tunnel(e.to_string()))?;
                self.runtime.last_session_key = Some(session_key.clone());
                self.runtime.last_region = Some(region);
                self.storage
                    .save_runtime_state(&self.runtime)
                    .map_err(|e| ClientError::Storage(e.to_string()))?;
                Ok(session_key)
            }
            StartSessionResponse::Conflict { .. } => Err(ClientError::Api(EntryApiError::Api {
                status: 409,
                code: "active_session_exists".to_string(),
            })),
        }
    }

    pub async fn disconnect(&mut self) -> Result<(), ClientError> {
        let token = self.auth.as_ref().map(|auth| auth.access_token.clone());
        let session_key = self.runtime.last_session_key.clone();
        self.tunnel
            .down()
            .map_err(|e| ClientError::Tunnel(e.to_string()))?;
        self.runtime.last_session_key = None;
        self.storage
            .save_runtime_state(&self.runtime)
            .map_err(|e| ClientError::Storage(e.to_string()))?;
        if let (Some(token), Some(session_key)) = (token, session_key) {
            let api = self.api.clone();
            tokio::spawn(async move {
                if let Err(err) = api.terminate_session(&token, &session_key).await {
                    tracing::warn!(
                        "best-effort session termination failed during disconnect: {}",
                        err
                    );
                }
            });
        }
        Ok(())
    }

    pub async fn logout(&mut self) -> Result<(), ClientError> {
        if let Some(auth) = &self.auth {
            let _ = self.api.logout(&auth.access_token).await;
        }
        self.tunnel
            .down()
            .map_err(|e| ClientError::Tunnel(e.to_string()))?;
        self.auth = None;
        self.runtime.last_session_key = None;
        self.runtime.last_region = None;
        self.runtime.selected_device_id = None;
        self.storage
            .clear_auth_state()
            .map_err(|e| ClientError::Storage(e.to_string()))?;
        self.storage
            .save_runtime_state(&self.runtime)
            .map_err(|e| ClientError::Storage(e.to_string()))
    }

    pub async fn restore_and_reconnect(&mut self) -> Result<Option<String>, ClientError> {
        let token = self.access_token()?;
        let device_id = self
            .runtime
            .selected_device_id
            .clone()
            .ok_or(ClientError::NoSelectedDevice)?;

        let current = self.api.current_session(token).await?;
        if !current.active {
            self.runtime.last_session_key = None;
            self.storage
                .save_runtime_state(&self.runtime)
                .map_err(|e| ClientError::Storage(e.to_string()))?;
            return Ok(None);
        }

        let session_key = current
            .session_key
            .clone()
            .or_else(|| self.runtime.last_session_key.clone())
            .ok_or_else(|| {
                ClientError::Api(EntryApiError::Api {
                    status: 500,
                    code: "missing_session_key".to_string(),
                })
            })?;
        let region = current
            .region
            .clone()
            .or_else(|| self.runtime.last_region.clone())
            .unwrap_or_else(|| "us-west1".to_string());

        let response = self
            .api
            .start_session(
                token,
                StartSessionRequest {
                    device_id,
                    region,
                    country_code: None,
                    city_code: None,
                    pool: None,
                    reconnect_session_key: Some(session_key),
                    node_hint: None,
                },
            )
            .await?;

        match response {
            StartSessionResponse::Active {
                session_key,
                region,
                config,
            } => {
                self.tunnel
                    .apply_and_up(&config)
                    .map_err(|e| ClientError::Tunnel(e.to_string()))?;
                self.runtime.last_session_key = Some(session_key.clone());
                self.runtime.last_region = Some(region);
                self.storage
                    .save_runtime_state(&self.runtime)
                    .map_err(|e| ClientError::Storage(e.to_string()))?;
                Ok(Some(session_key))
            }
            StartSessionResponse::Conflict { .. } => Ok(None),
        }
    }

    fn access_token(&self) -> Result<&str, ClientError> {
        self.auth
            .as_ref()
            .map(|a| a.access_token.as_str())
            .ok_or(ClientError::NotAuthenticated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::EntryApi;
    use crate::storage::FileSecureStorage;
    use crate::wireguard::RecordingTunnelController;
    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use serde::{Deserialize, Serialize};
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Debug, Clone)]
    struct MockState {
        token: String,
        customer_id: String,
        revoked: Arc<Mutex<HashSet<String>>>,
        devices: Arc<Mutex<Vec<crate::models::Device>>>,
        active_session: Arc<Mutex<Option<(String, String, String)>>>,
    }

    #[derive(Debug, Deserialize)]
    struct StartReq {
        device_id: String,
        region: String,
        reconnect_session_key: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct DeviceReq {
        name: String,
        public_key: String,
    }

    #[derive(Debug, Deserialize)]
    struct OAuthReq {
        code: String,
        code_verifier: Option<String>,
        nonce: Option<String>,
    }

    #[derive(Debug, Serialize)]
    struct ErrPayload {
        error: String,
    }

    #[tokio::test]
    async fn lifecycle_login_register_connect_disconnect_works() {
        let (base_url, _guard) = run_mock_server().await;
        let storage_path = unique_tmp_file("wg-desktop-lifecycle");
        let storage = FileSecureStorage::new(storage_path, "k1".to_string());
        let tunnel = RecordingTunnelController::default();
        let tunnel_probe = tunnel.clone();
        let api = EntryApi::new(base_url);
        let mut client = DesktopClient::new(api, storage, tunnel).expect("client");

        client
            .login_oauth_callback(
                "google",
                "ok-code",
                Some("pkce".to_string()),
                Some("n".to_string()),
            )
            .await
            .expect("login");
        let device = client
            .register_device("laptop", "pubkey")
            .await
            .expect("register");
        assert_eq!(
            client.runtime_state().selected_device_id.as_deref(),
            Some(device.id.as_str())
        );

        let session_key = client.connect("us-west1").await.expect("connect");
        assert!(session_key.starts_with("sess_"));

        client.disconnect().await.expect("disconnect");
        assert!(client.runtime_state().last_session_key.is_none());

        let events = tunnel_probe.events();
        assert!(events.iter().any(|e| e.starts_with("up:")));
        assert!(events.iter().any(|e| e == "down"));
    }

    #[tokio::test]
    async fn logout_revokes_token_and_clears_local_state() {
        let (base_url, state_guard) = run_mock_server().await;
        let storage_path = unique_tmp_file("wg-desktop-logout");
        let storage = FileSecureStorage::new(storage_path, "k2".to_string());
        let api = EntryApi::new(base_url);
        let mut client =
            DesktopClient::new(api.clone(), storage, RecordingTunnelController::default())
                .expect("client");

        client
            .login_oauth_callback("google", "ok-code", None, None)
            .await
            .expect("login");
        let token = client.auth_state().expect("auth").access_token.clone();
        let _ = client
            .register_device("laptop", "pubkey")
            .await
            .expect("register");

        client.logout().await.expect("logout");
        assert!(client.auth_state().is_none());
        assert!(client.runtime_state().selected_device_id.is_none());

        {
            let revoked = state_guard.revoked.lock().expect("lock");
            assert!(revoked.contains(&token));
        }

        let err = api
            .list_devices(&token)
            .await
            .expect_err("token should be revoked");
        match err {
            EntryApiError::Api { status, code } => {
                assert_eq!(status, 401);
                assert_eq!(code, "revoked_access_token");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn reconnect_after_restart_restores_active_session() {
        let (base_url, _guard) = run_mock_server().await;
        let storage_path = unique_tmp_file("wg-desktop-restart");

        let mut first = DesktopClient::new(
            EntryApi::new(base_url.clone()),
            FileSecureStorage::new(storage_path.clone(), "k3".to_string()),
            RecordingTunnelController::default(),
        )
        .expect("client1");
        first
            .login_oauth_callback("google", "ok-code", None, None)
            .await
            .expect("login");
        let _ = first
            .register_device("laptop", "pubkey")
            .await
            .expect("register");
        let first_session = first.connect("us-west1").await.expect("connect");
        assert!(!first_session.is_empty());

        let tunnel2 = RecordingTunnelController::default();
        let tunnel_probe = tunnel2.clone();
        let mut second = DesktopClient::new(
            EntryApi::new(base_url),
            FileSecureStorage::new(storage_path, "k3".to_string()),
            tunnel2,
        )
        .expect("client2");

        let resumed = second
            .restore_and_reconnect()
            .await
            .expect("restore")
            .expect("expected active session");
        assert_eq!(resumed, first_session);
        assert!(tunnel_probe.events().iter().any(|e| e.starts_with("up:")));
    }

    #[tokio::test]
    async fn disconnect_still_succeeds_when_terminate_session_fails() {
        let (base_url, _guard) = run_mock_server().await;
        let storage_path = unique_tmp_file("wg-desktop-disconnect-best-effort");
        let storage = FileSecureStorage::new(storage_path, "k4".to_string());
        let tunnel = RecordingTunnelController::default();
        let tunnel_probe = tunnel.clone();
        let mut client = DesktopClient::new(EntryApi::new(base_url), storage, tunnel).expect("client");

        client
            .login_oauth_callback("google", "ok-code", None, None)
            .await
            .expect("login");
        let _ = client
            .register_device("laptop", "pubkey")
            .await
            .expect("register");
        let _ = client.connect("us-west1").await.expect("connect");

        client.auth.as_mut().expect("auth").access_token = "bad-token".to_string();
        client.disconnect().await.expect("disconnect must remain usable");
        assert!(client.runtime_state().last_session_key.is_none());
        assert!(tunnel_probe.events().iter().any(|e| e == "down"));
    }

    async fn run_mock_server() -> (String, MockState) {
        let state = MockState {
            token: "token-abc".to_string(),
            customer_id: "customer-1".to_string(),
            revoked: Arc::new(Mutex::new(HashSet::new())),
            devices: Arc::new(Mutex::new(Vec::new())),
            active_session: Arc::new(Mutex::new(None)),
        };

        let app = Router::new()
            .route("/v1/auth/oauth/{provider}/callback", post(oauth_callback))
            .route("/v1/auth/logout", post(logout))
            .route("/v1/devices", get(list_devices).post(register_device))
            .route("/v1/sessions/start", post(start_session))
            .route("/v1/sessions/current", get(current_session))
            .route(
                "/v1/sessions/{session_key}/terminate",
                post(terminate_session),
            )
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        (format!("http://{}", addr), state)
    }

    async fn oauth_callback(
        State(state): State<MockState>,
        Path(_provider): Path<String>,
        Json(payload): Json<OAuthReq>,
    ) -> Result<Json<crate::models::OAuthCallbackResponse>, (StatusCode, Json<ErrPayload>)> {
        if payload.code.trim().is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrPayload {
                    error: "missing_oauth_code".to_string(),
                }),
            ));
        }
        let _ = payload.code_verifier;
        let _ = payload.nonce;

        Ok(Json(crate::models::OAuthCallbackResponse {
            provider: "google".to_string(),
            customer_id: state.customer_id,
            access_token: state.token,
        }))
    }

    async fn logout(
        State(state): State<MockState>,
        headers: HeaderMap,
    ) -> Result<StatusCode, (StatusCode, Json<ErrPayload>)> {
        let token = bearer_token(&headers)?;
        state.revoked.lock().expect("lock").insert(token);
        Ok(StatusCode::NO_CONTENT)
    }

    async fn list_devices(
        State(state): State<MockState>,
        headers: HeaderMap,
    ) -> Result<Json<Vec<crate::models::Device>>, (StatusCode, Json<ErrPayload>)> {
        ensure_token(&state, &headers)?;
        Ok(Json(state.devices.lock().expect("lock").clone()))
    }

    async fn register_device(
        State(state): State<MockState>,
        headers: HeaderMap,
        Json(payload): Json<DeviceReq>,
    ) -> Result<Json<crate::models::Device>, (StatusCode, Json<ErrPayload>)> {
        ensure_token(&state, &headers)?;
        let device = crate::models::Device {
            id: "device-1".to_string(),
            customer_id: state.customer_id.clone(),
            name: payload.name,
            public_key: payload.public_key,
            created_at: "2026-02-11T00:00:00Z".to_string(),
        };
        state.devices.lock().expect("lock").push(device.clone());
        Ok(Json(device))
    }

    async fn start_session(
        State(state): State<MockState>,
        headers: HeaderMap,
        Json(payload): Json<StartReq>,
    ) -> Result<Json<StartSessionResponse>, (StatusCode, Json<ErrPayload>)> {
        ensure_token(&state, &headers)?;
        let mut active = state.active_session.lock().expect("lock");
        if let Some((session_key, existing_region, _device_id)) = active.clone() {
            if payload.reconnect_session_key.as_deref() == Some(session_key.as_str()) {
                return Ok(Json(StartSessionResponse::Active {
                    session_key,
                    region: existing_region,
                    config: test_wg_config(),
                }));
            }
            return Ok(Json(StartSessionResponse::Conflict {
                existing_session_key: session_key,
                message: "active_session_exists".to_string(),
            }));
        }

        let session_key = "sess_mock_1".to_string();
        *active = Some((
            session_key.clone(),
            payload.region.clone(),
            payload.device_id.clone(),
        ));
        Ok(Json(StartSessionResponse::Active {
            session_key,
            region: payload.region,
            config: test_wg_config(),
        }))
    }

    async fn current_session(
        State(state): State<MockState>,
        headers: HeaderMap,
    ) -> Result<Json<crate::models::CurrentSessionResponse>, (StatusCode, Json<ErrPayload>)> {
        ensure_token(&state, &headers)?;
        let current = state.active_session.lock().expect("lock").clone();
        Ok(Json(match current {
            None => crate::models::CurrentSessionResponse {
                active: false,
                session_key: None,
                region: None,
                device_id: None,
                connected_at: None,
            },
            Some((session_key, region, device_id)) => crate::models::CurrentSessionResponse {
                active: true,
                session_key: Some(session_key),
                region: Some(region),
                device_id: Some(device_id),
                connected_at: Some("2026-02-11T00:00:00Z".to_string()),
            },
        }))
    }

    async fn terminate_session(
        State(state): State<MockState>,
        Path(session_key): Path<String>,
        headers: HeaderMap,
    ) -> Result<StatusCode, (StatusCode, Json<ErrPayload>)> {
        ensure_token(&state, &headers)?;
        let mut active = state.active_session.lock().expect("lock");
        if let Some((existing, _, _)) = active.clone()
            && existing == session_key
        {
            *active = None;
            return Ok(StatusCode::NO_CONTENT);
        }
        Err((
            StatusCode::BAD_REQUEST,
            Json(ErrPayload {
                error: "session_key_mismatch".to_string(),
            }),
        ))
    }

    fn ensure_token(
        state: &MockState,
        headers: &HeaderMap,
    ) -> Result<(), (StatusCode, Json<ErrPayload>)> {
        let token = bearer_token(headers)?;
        if token != state.token {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrPayload {
                    error: "invalid_access_token".to_string(),
                }),
            ));
        }
        if state.revoked.lock().expect("lock").contains(&token) {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrPayload {
                    error: "revoked_access_token".to_string(),
                }),
            ));
        }
        Ok(())
    }

    fn bearer_token(headers: &HeaderMap) -> Result<String, (StatusCode, Json<ErrPayload>)> {
        let raw = headers
            .get("authorization")
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrPayload {
                        error: "missing_bearer_token".to_string(),
                    }),
                )
            })?
            .to_str()
            .map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrPayload {
                        error: "invalid_access_token".to_string(),
                    }),
                )
            })?;

        if !raw.starts_with("Bearer ") {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrPayload {
                    error: "invalid_access_token".to_string(),
                }),
            ));
        }
        Ok(raw.trim_start_matches("Bearer ").to_string())
    }

    fn test_wg_config() -> crate::models::WireGuardClientConfig {
        crate::models::WireGuardClientConfig {
            endpoint: "node.example:51820".to_string(),
            server_public_key: "server-key".to_string(),
            preshared_key: None,
            assigned_ip: "10.80.0.2/24".to_string(),
            dns_servers: vec!["1.1.1.1".to_string()],
            persistent_keepalive_secs: 25,
            qr_payload: "wgcfg".to_string(),
            client_private_key: Some("test-private-key".to_string()),
        }
    }

    fn unique_tmp_file(prefix: &str) -> std::path::PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{now}.json"))
    }
}
