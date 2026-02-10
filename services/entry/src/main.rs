mod google_oidc;
mod node_repo;
mod oauth_repo;
mod postgres_session_repo;
mod session_repo;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use control_plane::proto::{ConnectRequest, DisconnectRequest, GetSessionRequest};
use control_plane::{ControlPlaneClient, config_from_proto, maybe_uuid_to_string, parse_rfc3339};
use domain::{Device, WireGuardClientConfig};
use google_oidc::{GoogleOidcConfig, OidcError, authenticate_google};
use node_repo::{NodeRecord, NodeRepoError, PostgresNodeRepository, UpsertNodeInput};
use oauth_repo::{OAuthRepoError, PostgresOAuthRepository};
use postgres_session_repo::{PostgresRepoError, PostgresSessionRepository};
use serde::{Deserialize, Serialize};
use session_repo::{InMemorySessionRepository, RepoError, SessionRepository, StartSessionOutcome};
use sqlx::postgres::PgPoolOptions;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("entry=info")
        .without_time()
        .init();

    let grpc_target =
        std::env::var("CORE_GRPC_URL").unwrap_or_else(|_| "http://127.0.0.1:50051".to_string());
    let core_client = ControlPlaneClient::connect(grpc_target.clone()).await?;

    let (session_store, identity_store, node_store) =
        if let Ok(database_url) = std::env::var("DATABASE_URL") {
            let pool = PgPoolOptions::new()
                .max_connections(10)
                .connect(&database_url)
                .await?;
            info!("entry using postgres session/oauth/node stores");
            (
                SessionStore::Postgres(PostgresSessionRepository::new(pool.clone())),
                IdentityStore::Postgres(PostgresOAuthRepository::new(pool.clone())),
                NodeStore::Postgres(PostgresNodeRepository::new(pool)),
            )
        } else {
            warn!("DATABASE_URL not set; entry using in-memory session/oauth/node stores");
            (
                SessionStore::InMemory(Mutex::new(InMemorySessionRepository::default())),
                IdentityStore::InMemory(Mutex::new(HashMap::new())),
                NodeStore::InMemory(Mutex::new(HashMap::new())),
            )
        };

    let state = Arc::new(AppState {
        runtime_sessions_by_customer: RwLock::new(HashMap::new()),
        devices_by_customer: RwLock::new(HashMap::new()),
        core_client: Mutex::new(core_client),
        session_store,
        http_client: reqwest::Client::new(),
        google_oidc: GoogleOidcConfig::from_env(),
        identity_store,
        node_store,
        admin_api_token: std::env::var("ADMIN_API_TOKEN").ok(),
    });

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/auth/oauth/:provider/callback", post(oauth_callback))
        .route("/v1/devices", post(register_device).get(list_devices))
        .route("/v1/sessions/start", post(start_session))
        .route("/v1/sessions/current", get(current_session))
        .route("/v1/admin/nodes", post(upsert_node).get(list_nodes))
        .route("/v1/internal/nodes/health", post(update_node_health))
        .route(
            "/v1/sessions/:session_key/terminate",
            post(terminate_session),
        )
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    info!(%addr, grpc_target, "entry service started");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

struct AppState {
    runtime_sessions_by_customer: RwLock<HashMap<Uuid, ActiveSession>>,
    devices_by_customer: RwLock<HashMap<Uuid, Vec<Device>>>,
    core_client: Mutex<ControlPlaneClient<tonic::transport::Channel>>,
    session_store: SessionStore,
    http_client: reqwest::Client,
    google_oidc: Option<GoogleOidcConfig>,
    identity_store: IdentityStore,
    node_store: NodeStore,
    admin_api_token: Option<String>,
}

#[derive(Clone)]
struct ActiveSession {
    session_key: String,
    region: String,
    config: WireGuardClientConfig,
}

enum SessionStore {
    InMemory(Mutex<InMemorySessionRepository>),
    Postgres(PostgresSessionRepository),
}

enum IdentityStore {
    InMemory(Mutex<HashMap<(String, String), Uuid>>),
    Postgres(PostgresOAuthRepository),
}

enum NodeStore {
    InMemory(Mutex<HashMap<Uuid, NodeRecord>>),
    Postgres(PostgresNodeRepository),
}

impl IdentityStore {
    async fn resolve_or_create_customer(
        &self,
        provider: &str,
        subject: &str,
        email: Option<&str>,
    ) -> Result<Uuid, ApiError> {
        match self {
            IdentityStore::InMemory(store) => {
                let mut store = store.lock().await;
                let key = (provider.to_string(), subject.to_string());
                let id = store
                    .entry(key)
                    .or_insert_with(|| Uuid::new_v5(&Uuid::NAMESPACE_OID, subject.as_bytes()));
                Ok(*id)
            }
            IdentityStore::Postgres(repo) => repo
                .resolve_or_create_customer(provider, subject, email)
                .await
                .map_err(map_oauth_repo_error),
        }
    }
}

impl NodeStore {
    async fn select_node(&self, region: &str) -> Result<Option<Uuid>, ApiError> {
        match self {
            NodeStore::InMemory(store) => {
                let store = store.lock().await;
                Ok(store
                    .values()
                    .filter(|n| n.region == region && n.healthy)
                    .min_by_key(|n| n.active_peer_count)
                    .map(|n| n.id))
            }
            NodeStore::Postgres(repo) => {
                repo.select_node(region).await.map_err(map_node_repo_error)
            }
        }
    }

    fn requires_selection(&self) -> bool {
        matches!(self, NodeStore::Postgres(_))
    }

    async fn list_nodes(&self) -> Result<Vec<NodeRecord>, ApiError> {
        match self {
            NodeStore::InMemory(store) => {
                let store = store.lock().await;
                let mut nodes: Vec<NodeRecord> = store.values().cloned().collect();
                nodes.sort_by(|a, b| {
                    a.region
                        .cmp(&b.region)
                        .then_with(|| a.active_peer_count.cmp(&b.active_peer_count))
                });
                Ok(nodes)
            }
            NodeStore::Postgres(repo) => repo.list_nodes().await.map_err(map_node_repo_error),
        }
    }

    async fn upsert_node(&self, input: UpsertNodeInput) -> Result<NodeRecord, ApiError> {
        match self {
            NodeStore::InMemory(store) => {
                let mut store = store.lock().await;
                let record = NodeRecord {
                    id: input.id,
                    region: input.region,
                    provider: input.provider,
                    endpoint_host: input.endpoint_host,
                    endpoint_port: input.endpoint_port,
                    healthy: input.healthy,
                    active_peer_count: input.active_peer_count,
                };
                store.insert(record.id, record.clone());
                Ok(record)
            }
            NodeStore::Postgres(repo) => repo.upsert_node(input).await.map_err(map_node_repo_error),
        }
    }

    async fn update_node_health(
        &self,
        node_id: Uuid,
        healthy: bool,
        active_peer_count: i64,
    ) -> Result<Option<NodeRecord>, ApiError> {
        match self {
            NodeStore::InMemory(store) => {
                let mut store = store.lock().await;
                if let Some(node) = store.get_mut(&node_id) {
                    node.healthy = healthy;
                    node.active_peer_count = active_peer_count;
                    return Ok(Some(node.clone()));
                }
                Ok(None)
            }
            NodeStore::Postgres(repo) => repo
                .update_node_health(node_id, healthy, active_peer_count)
                .await
                .map_err(map_node_repo_error),
        }
    }
}

impl SessionStore {
    async fn start_session(
        &self,
        customer_id: Uuid,
        device_id: Uuid,
        region: String,
        requested_session_key: String,
        reconnect_session_key: Option<&str>,
    ) -> Result<StartSessionOutcome, ApiError> {
        match self {
            SessionStore::InMemory(repo) => {
                let mut repo = repo.lock().await;
                Ok(repo.start_session(
                    customer_id,
                    device_id,
                    region,
                    requested_session_key,
                    reconnect_session_key,
                ))
            }
            SessionStore::Postgres(repo) => repo
                .start_session(
                    customer_id,
                    device_id,
                    region,
                    requested_session_key,
                    reconnect_session_key,
                )
                .await
                .map_err(map_pg_repo_error),
        }
    }

    async fn terminate_session(
        &self,
        customer_id: Uuid,
        session_key: &str,
    ) -> Result<(), ApiError> {
        match self {
            SessionStore::InMemory(repo) => {
                let mut repo = repo.lock().await;
                repo.terminate_session(customer_id, session_key)
                    .map_err(map_repo_error)
            }
            SessionStore::Postgres(repo) => repo
                .terminate_session(customer_id, session_key)
                .await
                .map_err(map_pg_repo_error),
        }
    }

    async fn get_active_session(
        &self,
        customer_id: Uuid,
    ) -> Result<Option<session_repo::SessionRow>, ApiError> {
        match self {
            SessionStore::InMemory(repo) => {
                let repo = repo.lock().await;
                Ok(repo.get_active_session(customer_id))
            }
            SessionStore::Postgres(repo) => repo
                .get_active_session(customer_id)
                .await
                .map_err(map_pg_repo_error),
        }
    }
}

async fn healthz() -> &'static str {
    "ok"
}

#[derive(Deserialize)]
struct OAuthCallbackRequest {
    code: String,
    code_verifier: Option<String>,
    nonce: Option<String>,
}

#[derive(Serialize)]
struct OAuthCallbackResponse {
    provider: String,
    customer_id: Uuid,
    access_token: String,
}

async fn oauth_callback(
    State(state): State<Arc<AppState>>,
    Path(provider): Path<String>,
    Json(payload): Json<OAuthCallbackRequest>,
) -> Result<Json<OAuthCallbackResponse>, ApiError> {
    if provider != "google" {
        return Err(ApiError::bad_request("unsupported_provider"));
    }

    if payload.code.trim().is_empty() {
        return Err(ApiError::bad_request("missing_oauth_code"));
    }

    let google_oidc = state
        .google_oidc
        .as_ref()
        .ok_or_else(|| ApiError::service_unavailable("google_oidc_not_configured"))?;
    let identity = authenticate_google(
        &state.http_client,
        google_oidc,
        &payload.code,
        payload.code_verifier.as_deref(),
        payload.nonce.as_deref(),
    )
    .await
    .map_err(map_oidc_error)?;

    let customer_id = state
        .identity_store
        .resolve_or_create_customer("google", &identity.sub, identity.email.as_deref())
        .await?;
    Ok(Json(OAuthCallbackResponse {
        provider,
        customer_id,
        access_token: format!("dev-token-{customer_id}"),
    }))
}

#[derive(Deserialize)]
struct RegisterDeviceRequest {
    name: String,
    public_key: String,
}

async fn register_device(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<RegisterDeviceRequest>,
) -> Result<Json<Device>, ApiError> {
    let customer_id = customer_id_from_headers(&headers)?;
    if payload.name.trim().is_empty() || payload.public_key.trim().is_empty() {
        return Err(ApiError::bad_request("invalid_device_payload"));
    }

    let mut devices_map = state.devices_by_customer.write().await;
    let entry = devices_map.entry(customer_id).or_default();
    let device = Device {
        id: Uuid::new_v4(),
        customer_id,
        name: payload.name,
        public_key: payload.public_key,
        created_at: Utc::now(),
    };
    entry.push(device.clone());
    Ok(Json(device))
}

async fn list_devices(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<Device>>, ApiError> {
    let customer_id = customer_id_from_headers(&headers)?;
    let devices_map = state.devices_by_customer.read().await;
    Ok(Json(
        devices_map
            .get(&customer_id)
            .cloned()
            .unwrap_or_else(Vec::new),
    ))
}

#[derive(Deserialize)]
struct UpsertNodeRequest {
    id: Option<Uuid>,
    region: String,
    provider: String,
    endpoint_host: String,
    endpoint_port: u16,
    healthy: Option<bool>,
    active_peer_count: Option<i64>,
}

#[derive(Deserialize)]
struct UpdateNodeHealthRequest {
    node_id: Uuid,
    healthy: bool,
    active_peer_count: i64,
}

#[derive(Serialize)]
struct NodeResponse {
    id: Uuid,
    region: String,
    provider: String,
    endpoint_host: String,
    endpoint_port: u16,
    healthy: bool,
    active_peer_count: i64,
}

impl From<NodeRecord> for NodeResponse {
    fn from(value: NodeRecord) -> Self {
        Self {
            id: value.id,
            region: value.region,
            provider: value.provider,
            endpoint_host: value.endpoint_host,
            endpoint_port: value.endpoint_port,
            healthy: value.healthy,
            active_peer_count: value.active_peer_count,
        }
    }
}

async fn list_nodes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<NodeResponse>>, ApiError> {
    require_admin_token(&state, &headers)?;
    let nodes = state.node_store.list_nodes().await?;
    Ok(Json(nodes.into_iter().map(NodeResponse::from).collect()))
}

async fn upsert_node(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<UpsertNodeRequest>,
) -> Result<Json<NodeResponse>, ApiError> {
    require_admin_token(&state, &headers)?;
    if payload.region.trim().is_empty()
        || payload.provider.trim().is_empty()
        || payload.endpoint_host.trim().is_empty()
    {
        return Err(ApiError::bad_request("invalid_node_payload"));
    }

    let input = UpsertNodeInput {
        id: payload.id.unwrap_or_else(Uuid::new_v4),
        region: payload.region,
        provider: payload.provider,
        endpoint_host: payload.endpoint_host,
        endpoint_port: payload.endpoint_port,
        healthy: payload.healthy.unwrap_or(true),
        active_peer_count: payload.active_peer_count.unwrap_or(0),
    };

    let node = state.node_store.upsert_node(input).await?;
    Ok(Json(NodeResponse::from(node)))
}

async fn update_node_health(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<UpdateNodeHealthRequest>,
) -> Result<Json<NodeResponse>, ApiError> {
    require_admin_token(&state, &headers)?;
    let node = state
        .node_store
        .update_node_health(payload.node_id, payload.healthy, payload.active_peer_count)
        .await?
        .ok_or_else(|| ApiError::not_found("node_not_found"))?;

    Ok(Json(NodeResponse::from(node)))
}

#[derive(Deserialize)]
struct StartSessionRequest {
    device_id: Uuid,
    region: String,
    reconnect_session_key: Option<String>,
    node_hint: Option<Uuid>,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum StartSessionResponse {
    Active {
        session_key: String,
        region: String,
        config: WireGuardClientConfig,
    },
    Conflict {
        existing_session_key: String,
        message: &'static str,
    },
}

async fn start_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<StartSessionRequest>,
) -> Result<Json<StartSessionResponse>, ApiError> {
    let customer_id = customer_id_from_headers(&headers)?;

    let device = {
        let devices_map = state.devices_by_customer.read().await;
        devices_map
            .get(&customer_id)
            .and_then(|devices| devices.iter().find(|d| d.id == payload.device_id).cloned())
    }
    .ok_or_else(|| ApiError::bad_request("unknown_device"))?;

    let requested_session_key = format!("sess_{}", Uuid::new_v4().simple());
    let outcome = state
        .session_store
        .start_session(
            customer_id,
            device.id,
            payload.region.clone(),
            requested_session_key.clone(),
            payload.reconnect_session_key.as_deref(),
        )
        .await?;

    match outcome {
        StartSessionOutcome::Conflict {
            existing_session_key,
        } => {
            return Ok(Json(StartSessionResponse::Conflict {
                existing_session_key,
                message: "active_session_exists",
            }));
        }
        StartSessionOutcome::Reconnected(existing_row) => {
            let selected_node =
                resolve_node_hint(&state, existing_row.region.as_str(), payload.node_hint).await?;
            let runtime_sessions = state.runtime_sessions_by_customer.read().await;
            if let Some(existing) = runtime_sessions.get(&customer_id) {
                return Ok(Json(StartSessionResponse::Active {
                    session_key: existing.session_key.clone(),
                    region: existing.region.clone(),
                    config: existing.config.clone(),
                }));
            }

            drop(runtime_sessions);
            // Runtime config can be missing after service restart. Re-issue connect to fetch config.
            let request = ConnectRequest {
                request_id: Uuid::new_v4().to_string(),
                session_key: existing_row.session_key.clone(),
                customer_id: customer_id.to_string(),
                device_id: device.id.to_string(),
                device_public_key: device.public_key,
                region: existing_row.region.clone(),
                node_hint: maybe_uuid_to_string(selected_node),
            };
            let connect_response = {
                let mut client = state.core_client.lock().await;
                client
                    .connect_device(request)
                    .await
                    .map_err(|_| ApiError::service_unavailable("core_connect_failed"))?
                    .into_inner()
            };
            let config = connect_response
                .config
                .map(config_from_proto)
                .ok_or_else(|| ApiError::service_unavailable("core_missing_config"))?;

            state.runtime_sessions_by_customer.write().await.insert(
                customer_id,
                ActiveSession {
                    session_key: existing_row.session_key.clone(),
                    region: existing_row.region.clone(),
                    config: config.clone(),
                },
            );

            return Ok(Json(StartSessionResponse::Active {
                session_key: existing_row.session_key,
                region: existing_row.region,
                config,
            }));
        }
        StartSessionOutcome::Created(created_row) => {
            let selected_node =
                resolve_node_hint(&state, payload.region.as_str(), payload.node_hint).await?;
            let request = ConnectRequest {
                request_id: Uuid::new_v4().to_string(),
                session_key: created_row.session_key.clone(),
                customer_id: customer_id.to_string(),
                device_id: device.id.to_string(),
                device_public_key: device.public_key,
                region: payload.region.clone(),
                node_hint: maybe_uuid_to_string(selected_node),
            };

            let connect_response = {
                let mut client = state.core_client.lock().await;
                client
                    .connect_device(request)
                    .await
                    .map_err(|_| ApiError::service_unavailable("core_connect_failed"))?
                    .into_inner()
            };

            let config = connect_response
                .config
                .map(config_from_proto)
                .ok_or_else(|| ApiError::service_unavailable("core_missing_config"))?;

            state.runtime_sessions_by_customer.write().await.insert(
                customer_id,
                ActiveSession {
                    session_key: created_row.session_key.clone(),
                    region: payload.region.clone(),
                    config: config.clone(),
                },
            );

            return Ok(Json(StartSessionResponse::Active {
                session_key: created_row.session_key,
                region: payload.region,
                config,
            }));
        }
    }
}

#[derive(Serialize)]
struct CurrentSessionResponse {
    active: bool,
    session_key: Option<String>,
    region: Option<String>,
    device_id: Option<Uuid>,
    connected_at: Option<String>,
}

async fn current_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<CurrentSessionResponse>, ApiError> {
    let customer_id = customer_id_from_headers(&headers)?;

    let response = {
        let mut client = state.core_client.lock().await;
        client
            .get_session(GetSessionRequest {
                customer_id: customer_id.to_string(),
            })
            .await
            .map_err(|_| ApiError::service_unavailable("core_session_lookup_failed"))?
            .into_inner()
    };

    if let Some(session) = response.session {
        let connected_at = parse_rfc3339(&session.connected_at, "connected_at")
            .map(|ts| ts.to_rfc3339())
            .ok();

        let device_id = state
            .session_store
            .get_active_session(customer_id)
            .await?
            .map(|s| s.device_id);

        return Ok(Json(CurrentSessionResponse {
            active: true,
            session_key: Some(session.session_key),
            region: Some(session.region),
            device_id,
            connected_at,
        }));
    }

    Ok(Json(CurrentSessionResponse {
        active: false,
        session_key: None,
        region: None,
        device_id: None,
        connected_at: None,
    }))
}

async fn terminate_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_key): Path<String>,
) -> Result<StatusCode, ApiError> {
    let customer_id = customer_id_from_headers(&headers)?;

    state
        .session_store
        .terminate_session(customer_id, &session_key)
        .await?;

    {
        let mut client = state.core_client.lock().await;
        client
            .disconnect_device(DisconnectRequest {
                request_id: Uuid::new_v4().to_string(),
                session_key: session_key.clone(),
                customer_id: customer_id.to_string(),
            })
            .await
            .map_err(|_| ApiError::service_unavailable("core_disconnect_failed"))?;
    }

    state
        .runtime_sessions_by_customer
        .write()
        .await
        .remove(&customer_id);
    Ok(StatusCode::NO_CONTENT)
}

fn customer_id_from_headers(headers: &HeaderMap) -> Result<Uuid, ApiError> {
    let raw = headers
        .get("x-customer-id")
        .ok_or_else(|| ApiError::unauthorized("missing_x_customer_id"))?
        .to_str()
        .map_err(|_| ApiError::unauthorized("invalid_x_customer_id"))?;

    Uuid::parse_str(raw).map_err(|_| ApiError::unauthorized("invalid_customer_id"))
}

fn require_admin_token(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let configured = state
        .admin_api_token
        .as_ref()
        .ok_or_else(|| ApiError::service_unavailable("admin_api_not_configured"))?;
    let provided = headers
        .get("x-admin-token")
        .ok_or_else(|| ApiError::unauthorized("missing_x_admin_token"))?
        .to_str()
        .map_err(|_| ApiError::unauthorized("invalid_x_admin_token"))?;

    if provided != configured {
        return Err(ApiError::unauthorized("invalid_admin_token"));
    }

    Ok(())
}

async fn resolve_node_hint(
    state: &Arc<AppState>,
    region: &str,
    requested_hint: Option<Uuid>,
) -> Result<Option<Uuid>, ApiError> {
    if let Some(hint) = requested_hint {
        return Ok(Some(hint));
    }

    let selected = state.node_store.select_node(region).await?;
    if selected.is_none() && state.node_store.requires_selection() {
        return Err(ApiError::bad_request("no_nodes_available_in_region"));
    }

    Ok(selected)
}

fn map_repo_error(err: RepoError) -> ApiError {
    match err {
        RepoError::NotFound => ApiError::not_found("no_active_session"),
        RepoError::SessionKeyMismatch => ApiError::bad_request("session_key_mismatch"),
    }
}

fn map_pg_repo_error(err: PostgresRepoError) -> ApiError {
    match err {
        PostgresRepoError::NotFound => ApiError::not_found("no_active_session"),
        PostgresRepoError::SessionKeyMismatch => ApiError::bad_request("session_key_mismatch"),
        PostgresRepoError::Database(_) => ApiError::service_unavailable("session_store_failed"),
    }
}

fn map_oidc_error(err: OidcError) -> ApiError {
    match err {
        OidcError::MissingIdToken
        | OidcError::MissingKeyId
        | OidcError::UnknownKeyId
        | OidcError::InvalidNonce
        | OidcError::Jwt(_) => ApiError::unauthorized("oauth_invalid_identity"),
        OidcError::Http(_) => ApiError::service_unavailable("oauth_provider_unreachable"),
    }
}

fn map_oauth_repo_error(err: OAuthRepoError) -> ApiError {
    match err {
        OAuthRepoError::Database(_) => ApiError::service_unavailable("identity_store_failed"),
    }
}

fn map_node_repo_error(err: NodeRepoError) -> ApiError {
    match err {
        NodeRepoError::Database(_) => ApiError::service_unavailable("node_store_failed"),
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
}

impl ApiError {
    fn bad_request(code: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
        }
    }

    fn unauthorized(code: &'static str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code,
        }
    }

    fn not_found(code: &'static str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code,
        }
    }

    fn service_unavailable(code: &'static str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (
            self.status,
            Json(serde_json::json!({
                "error": self.code,
            })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use jsonwebtoken::errors::{Error as JwtError, ErrorKind};

    #[test]
    fn customer_id_from_headers_reads_valid_uuid() {
        let customer_id = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-customer-id",
            HeaderValue::from_str(&customer_id.to_string()).expect("header value"),
        );

        let parsed = customer_id_from_headers(&headers).expect("valid customer id");
        assert_eq!(parsed, customer_id);
    }

    #[test]
    fn customer_id_from_headers_rejects_missing_header() {
        let headers = HeaderMap::new();
        let err = customer_id_from_headers(&headers).expect_err("missing header should fail");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.code, "missing_x_customer_id");
    }

    #[test]
    fn map_oidc_error_for_invalid_nonce_is_unauthorized() {
        let err = map_oidc_error(OidcError::InvalidNonce);
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.code, "oauth_invalid_identity");
    }

    #[test]
    fn map_oidc_error_for_jwt_is_unauthorized() {
        let jwt_err = JwtError::from(ErrorKind::InvalidToken);
        let err = map_oidc_error(OidcError::Jwt(jwt_err));
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.code, "oauth_invalid_identity");
    }
}
