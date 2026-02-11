mod google_oidc;
mod node_repo;
mod oauth_repo;
mod postgres_session_repo;
mod privacy_repo;
mod session_repo;
mod subscription_repo;
mod token_repo;

use std::collections::HashMap;
use std::fs;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use control_plane::proto::{ConnectRequest, DisconnectRequest, GetSessionRequest};
use control_plane::{ControlPlaneClient, config_from_proto, maybe_uuid_to_string, parse_rfc3339};
use domain::{Device, WireGuardClientConfig};
use google_oidc::{GoogleOidcConfig, OidcError, authenticate_google};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode_header, encode,
};
use node_repo::{
    NodeRecord, NodeRepoError, NodeSelectionCriteria, PostgresNodeRepository, UpsertNodeInput,
};
use oauth_repo::{OAuthRepoError, PostgresOAuthRepository};
use postgres_session_repo::{PostgresRepoError, PostgresSessionRepository};
use privacy_repo::PostgresPrivacyRepository;
use serde::{Deserialize, Serialize};
use session_repo::{InMemorySessionRepository, RepoError, SessionRepository, StartSessionOutcome};
use sqlx::postgres::PgPoolOptions;
use subscription_repo::{
    Entitlements, PostgresSubscriptionRepository, SubscriptionRecord, SubscriptionRepoError,
    SubscriptionStatus,
};
use subtle::ConstantTimeEq;
use token_repo::{PostgresTokenRepository, TokenRepoError};
use tokio::sync::{Mutex, RwLock};
use tokio::time::{Duration, sleep};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Clone, Copy, PartialEq, Eq)]
enum RuntimeMode {
    Development,
    Production,
}

#[derive(Clone, Copy)]
enum LogRedactionMode {
    Off,
    Partial,
    Strict,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("entry=info")
        .without_time()
        .init();
    let mode = runtime_mode();

    let grpc_target =
        std::env::var("CORE_GRPC_URL").unwrap_or_else(|_| "http://127.0.0.1:50051".to_string());
    let core_client = build_core_client(&grpc_target).await?;

    let (session_store, identity_store, node_store, token_store, subscription_store, privacy_store) =
        if let Ok(database_url) = std::env::var("DATABASE_URL") {
            let pool = PgPoolOptions::new()
                .max_connections(10)
                .connect(&database_url)
                .await?;
            info!("entry using postgres session/oauth/node stores");
            (
                SessionStore::Postgres(PostgresSessionRepository::new(pool.clone())),
                IdentityStore::Postgres(PostgresOAuthRepository::new(pool.clone())),
                NodeStore::Postgres(PostgresNodeRepository::new(pool.clone())),
                Some(PostgresTokenRepository::new(pool.clone())),
                SubscriptionStore::Postgres(PostgresSubscriptionRepository::new(pool.clone())),
                Some(PostgresPrivacyRepository::new(pool.clone())),
            )
        } else {
            warn!("DATABASE_URL not set; entry using in-memory session/oauth/node stores");
            (
                SessionStore::InMemory(Mutex::new(InMemorySessionRepository::default())),
                IdentityStore::InMemory(Mutex::new(HashMap::new())),
                NodeStore::InMemory(Mutex::new(HashMap::new())),
                None,
                SubscriptionStore::InMemory(Mutex::new(HashMap::new())),
                None,
            )
        };
    let jwt_keys = JwtKeyStore::from_env();
    if jwt_keys.using_insecure_default {
        warn!("APP_JWT_SIGNING_KEY(S) not set; using insecure development signing key");
    }
    let terminated_session_retention_days = std::env::var("APP_TERMINATED_SESSION_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(7);
    let audit_retention_days = std::env::var("APP_AUDIT_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(30);

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
        jwt_keys,
        allow_legacy_customer_header: std::env::var("APP_ALLOW_LEGACY_CUSTOMER_HEADER")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(true),
        revoked_token_ids: Mutex::new(HashMap::new()),
        token_store,
        subscription_store,
        privacy_store,
        runtime_mode: mode,
        log_redaction_mode: log_redaction_mode(mode),
        terminated_session_retention_days,
        audit_retention_days,
        node_freshness_secs: std::env::var("APP_NODE_FRESHNESS_SECS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(60),
    });
    validate_runtime_configuration(mode, &state)?;

    if let Some(repo) = state.token_store.clone() {
        tokio::spawn(revocation_cleanup_loop(repo));
    }
    if let Some(repo) = state.privacy_store.clone() {
        tokio::spawn(privacy_cleanup_loop(
            repo,
            terminated_session_retention_days,
            audit_retention_days,
        ));
    }

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/auth/oauth/:provider/callback", post(oauth_callback))
        .route("/v1/auth/logout", post(logout))
        .route("/v1/devices", post(register_device).get(list_devices))
        .route("/v1/sessions/start", post(start_session))
        .route("/v1/sessions/current", get(current_session))
        .route("/v1/admin/nodes", post(upsert_node).get(list_nodes))
        .route("/v1/admin/privacy/policy", get(get_privacy_policy))
        .route("/v1/admin/core/status", get(get_core_status))
        .route(
            "/v1/admin/subscriptions",
            post(upsert_subscription).get(list_subscriptions),
        )
        .route(
            "/v1/admin/subscriptions/:customer_id",
            get(get_subscription),
        )
        .route(
            "/v1/admin/subscriptions/:customer_id/history",
            get(get_subscription_history),
        )
        .route("/v1/internal/nodes/health", post(update_node_health))
        .route(
            "/v1/sessions/:session_key/terminate",
            post(terminate_session),
        )
        .with_state(state);

    let addr = std::env::var("ENTRY_BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse::<SocketAddr>()?;
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
    jwt_keys: JwtKeyStore,
    allow_legacy_customer_header: bool,
    revoked_token_ids: Mutex<HashMap<String, usize>>,
    token_store: Option<PostgresTokenRepository>,
    subscription_store: SubscriptionStore,
    privacy_store: Option<PostgresPrivacyRepository>,
    runtime_mode: RuntimeMode,
    log_redaction_mode: LogRedactionMode,
    terminated_session_retention_days: i64,
    audit_retention_days: i64,
    node_freshness_secs: i64,
}

struct AuthContext {
    customer_id: Uuid,
    token_id: Option<String>,
    token_exp: Option<usize>,
}

#[derive(Clone)]
struct JwtKeyStore {
    active_kid: String,
    keys: HashMap<String, String>,
    using_insecure_default: bool,
}

impl JwtKeyStore {
    fn from_env() -> Self {
        if let Ok(raw) = std::env::var("APP_JWT_SIGNING_KEYS") {
            let mut keys = HashMap::new();
            for part in raw.split(',') {
                let mut chunks = part.splitn(2, ':');
                let kid = chunks.next().unwrap_or_default().trim();
                let secret = chunks.next().unwrap_or_default().trim();
                if !kid.is_empty() && !secret.is_empty() {
                    keys.insert(kid.to_string(), secret.to_string());
                }
            }
            if let Some(active_kid) = std::env::var("APP_JWT_ACTIVE_KID")
                .ok()
                .filter(|v| keys.contains_key(v))
            {
                return Self {
                    active_kid,
                    keys,
                    using_insecure_default: false,
                };
            }
            if let Some(first) = keys.keys().next().cloned() {
                return Self {
                    active_kid: first,
                    keys,
                    using_insecure_default: false,
                };
            }
        }

        let key = std::env::var("APP_JWT_SIGNING_KEY")
            .unwrap_or_else(|_| "dev-insecure-signing-key-change-me".to_string());
        let mut keys = HashMap::new();
        keys.insert("v1".to_string(), key.clone());
        Self {
            active_kid: "v1".to_string(),
            keys,
            using_insecure_default: key == "dev-insecure-signing-key-change-me",
        }
    }

    fn active_signing_key(&self) -> Option<(&str, &str)> {
        self.keys
            .get(&self.active_kid)
            .map(|secret| (self.active_kid.as_str(), secret.as_str()))
    }

    fn key_for_kid(&self, kid: &str) -> Option<&str> {
        self.keys.get(kid).map(|v| v.as_str())
    }
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

enum SubscriptionStore {
    InMemory(Mutex<HashMap<Uuid, SubscriptionProfile>>),
    Postgres(PostgresSubscriptionRepository),
}

#[derive(Clone)]
struct SubscriptionProfile {
    entitlements: Entitlements,
    session_eligible: bool,
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
    async fn select_node(
        &self,
        criteria: &NodeSelectionCriteria,
        freshness_seconds: i64,
    ) -> Result<Option<NodeRecord>, ApiError> {
        match self {
            NodeStore::InMemory(store) => {
                let store = store.lock().await;
                let now = Utc::now();
                Ok(store
                    .values()
                    .filter(|n| {
                        criteria
                            .region
                            .as_deref()
                            .map_or(true, |region| n.region == region)
                            && criteria
                                .country_code
                                .as_deref()
                                .map_or(true, |cc| n.country_code == cc)
                            && criteria
                                .city_code
                                .as_deref()
                                .map_or(true, |city| n.city_code.as_deref() == Some(city))
                            && criteria.pool.as_deref().map_or(true, |pool| n.pool == pool)
                            && n.healthy
                            && n.active_peer_count < n.capacity_peers
                            && (now - n.updated_at).num_seconds() <= freshness_seconds
                    })
                    .min_by_key(|n| n.active_peer_count)
                    .cloned())
            }
            NodeStore::Postgres(repo) => repo
                .select_node(criteria, freshness_seconds)
                .await
                .map_err(map_node_repo_error),
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
                    country_code: input.country_code,
                    city_code: input.city_code,
                    pool: input.pool,
                    provider: input.provider,
                    endpoint_host: input.endpoint_host,
                    endpoint_port: input.endpoint_port,
                    healthy: input.healthy,
                    active_peer_count: input.active_peer_count,
                    capacity_peers: input.capacity_peers,
                    updated_at: Utc::now(),
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
                    node.updated_at = Utc::now();
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

impl SubscriptionStore {
    async fn entitlements_for_customer(&self, customer_id: Uuid) -> Result<Entitlements, ApiError> {
        match self {
            SubscriptionStore::InMemory(store) => {
                let store = store.lock().await;
                Ok(store
                    .get(&customer_id)
                    .map(|v| v.entitlements.clone())
                    .unwrap_or_default())
            }
            SubscriptionStore::Postgres(repo) => repo
                .entitlements_for_customer(customer_id)
                .await
                .map_err(map_subscription_repo_error),
        }
    }

    async fn is_customer_session_eligible(&self, customer_id: Uuid) -> Result<bool, ApiError> {
        match self {
            SubscriptionStore::InMemory(store) => {
                let store = store.lock().await;
                Ok(store
                    .get(&customer_id)
                    .map(|v| v.session_eligible)
                    .unwrap_or(true))
            }
            SubscriptionStore::Postgres(repo) => repo
                .is_customer_session_eligible(customer_id)
                .await
                .map_err(map_subscription_repo_error),
        }
    }

    async fn upsert_customer_subscription(
        &self,
        customer_id: Uuid,
        plan_code: &str,
        status: SubscriptionStatus,
    ) -> Result<(), ApiError> {
        match self {
            SubscriptionStore::InMemory(store) => {
                let mut store = store.lock().await;
                let session_eligible = matches!(
                    status,
                    SubscriptionStatus::Active | SubscriptionStatus::Trialing
                );
                let profile = store
                    .entry(customer_id)
                    .or_insert_with(|| SubscriptionProfile {
                        entitlements: Entitlements::default(),
                        session_eligible: true,
                    });
                profile.session_eligible = session_eligible;
                profile.entitlements.max_active_sessions = 1;
                if plan_code == "plus" {
                    profile.entitlements.max_devices = 7;
                } else if plan_code == "max" {
                    profile.entitlements.max_devices = 10;
                } else {
                    profile.entitlements.max_devices = 3;
                }
                Ok(())
            }
            SubscriptionStore::Postgres(repo) => repo
                .upsert_customer_subscription(customer_id, plan_code, status)
                .await
                .map_err(map_subscription_repo_error),
        }
    }

    async fn get_customer_subscription(
        &self,
        customer_id: Uuid,
    ) -> Result<Option<SubscriptionRecord>, ApiError> {
        match self {
            SubscriptionStore::InMemory(store) => {
                let store = store.lock().await;
                Ok(store.get(&customer_id).map(|p| SubscriptionRecord {
                    customer_id,
                    plan_code: "in_memory".to_string(),
                    status: if p.session_eligible {
                        "active".to_string()
                    } else {
                        "canceled".to_string()
                    },
                    starts_at: Utc::now(),
                    ends_at: None,
                }))
            }
            SubscriptionStore::Postgres(repo) => repo
                .get_customer_subscription(customer_id)
                .await
                .map_err(map_subscription_repo_error),
        }
    }

    async fn list_subscriptions(
        &self,
        limit: i64,
        offset: i64,
        status: Option<&str>,
        plan_code: Option<&str>,
    ) -> Result<Vec<SubscriptionRecord>, ApiError> {
        match self {
            SubscriptionStore::InMemory(store) => {
                let store = store.lock().await;
                let mut rows: Vec<SubscriptionRecord> = store
                    .iter()
                    .map(|(customer_id, p)| SubscriptionRecord {
                        customer_id: *customer_id,
                        plan_code: "in_memory".to_string(),
                        status: if p.session_eligible {
                            "active".to_string()
                        } else {
                            "canceled".to_string()
                        },
                        starts_at: Utc::now(),
                        ends_at: None,
                    })
                    .collect();

                if let Some(status) = status {
                    rows.retain(|r| r.status == status);
                }
                if let Some(plan_code) = plan_code {
                    rows.retain(|r| r.plan_code == plan_code);
                }
                rows.sort_by_key(|r| r.customer_id);
                let start = offset.max(0) as usize;
                let end = (start + limit.max(0) as usize).min(rows.len());
                if start >= rows.len() {
                    return Ok(Vec::new());
                }
                Ok(rows[start..end].to_vec())
            }
            SubscriptionStore::Postgres(repo) => repo
                .list_subscriptions(limit, offset, status, plan_code)
                .await
                .map_err(map_subscription_repo_error),
        }
    }

    async fn get_customer_subscription_history(
        &self,
        customer_id: Uuid,
        limit: i64,
    ) -> Result<Vec<SubscriptionRecord>, ApiError> {
        match self {
            SubscriptionStore::InMemory(store) => {
                let store = store.lock().await;
                Ok(store
                    .get(&customer_id)
                    .map(|p| {
                        vec![SubscriptionRecord {
                            customer_id,
                            plan_code: "in_memory".to_string(),
                            status: if p.session_eligible {
                                "active".to_string()
                            } else {
                                "canceled".to_string()
                            },
                            starts_at: Utc::now(),
                            ends_at: None,
                        }]
                    })
                    .unwrap_or_default()
                    .into_iter()
                    .take(limit.max(0) as usize)
                    .collect())
            }
            SubscriptionStore::Postgres(repo) => repo
                .get_customer_subscription_history(customer_id, limit)
                .await
                .map_err(map_subscription_repo_error),
        }
    }
}

async fn healthz() -> &'static str {
    "ok"
}

async fn revocation_cleanup_loop(repo: PostgresTokenRepository) {
    loop {
        if let Ok(removed) = repo.purge_expired().await {
            if removed > 0 {
                info!(removed, "purged expired revoked tokens");
            }
        }
        sleep(Duration::from_secs(3600)).await;
    }
}

async fn privacy_cleanup_loop(
    repo: PostgresPrivacyRepository,
    session_retention_days: i64,
    audit_retention_days: i64,
) {
    loop {
        if let Ok((sessions, audits)) = repo
            .purge_expired_metadata(session_retention_days, audit_retention_days)
            .await
        {
            if sessions > 0 || audits > 0 {
                info!(
                    sessions,
                    audits, "purged expired privacy-sensitive metadata"
                );
            }
        }
        sleep(Duration::from_secs(6 * 3600)).await;
    }
}

async fn build_core_client(grpc_target: &str) -> anyhow::Result<ControlPlaneClient<Channel>> {
    let mut endpoint = Endpoint::from_shared(grpc_target.to_string())?;
    let require_tls = std::env::var("APP_REQUIRE_CORE_TLS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if let Some(tls) = client_tls_config_from_env()? {
        endpoint = endpoint.tls_config(tls)?;
    } else if require_tls {
        return Err(anyhow::anyhow!(
            "APP_REQUIRE_CORE_TLS is enabled but CORE_GRPC_TLS_CA_CERT_PATH is not configured"
        ));
    }

    let channel = endpoint.connect().await?;
    Ok(ControlPlaneClient::new(channel))
}

fn client_tls_config_from_env() -> anyhow::Result<Option<ClientTlsConfig>> {
    let ca_path = std::env::var("CORE_GRPC_TLS_CA_CERT_PATH").ok();
    let Some(ca_path) = ca_path else {
        return Ok(None);
    };

    let domain =
        std::env::var("CORE_GRPC_TLS_DOMAIN").unwrap_or_else(|_| "core.internal".to_string());
    let ca = fs::read(ca_path)?;
    let mut tls = ClientTlsConfig::new()
        .domain_name(domain)
        .ca_certificate(Certificate::from_pem(ca));

    let cert_path = std::env::var("CORE_GRPC_TLS_CLIENT_CERT_PATH").ok();
    let key_path = std::env::var("CORE_GRPC_TLS_CLIENT_KEY_PATH").ok();
    if let (Some(cert_path), Some(key_path)) = (cert_path, key_path) {
        let cert = fs::read(cert_path)?;
        let key = fs::read(key_path)?;
        tls = tls.identity(Identity::from_pem(cert, key));
    }

    Ok(Some(tls))
}

fn runtime_mode() -> RuntimeMode {
    match std::env::var("APP_ENV")
        .unwrap_or_else(|_| "development".to_string())
        .to_lowercase()
        .as_str()
    {
        "production" => RuntimeMode::Production,
        _ => RuntimeMode::Development,
    }
}

fn env_flag(name: &str, default: bool) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(default)
}

fn log_redaction_mode(mode: RuntimeMode) -> LogRedactionMode {
    if let Ok(raw) = std::env::var("APP_LOG_REDACTION_MODE") {
        return match raw.to_lowercase().as_str() {
            "off" => LogRedactionMode::Off,
            "partial" => LogRedactionMode::Partial,
            _ => LogRedactionMode::Strict,
        };
    }
    match mode {
        RuntimeMode::Production => LogRedactionMode::Strict,
        RuntimeMode::Development => LogRedactionMode::Partial,
    }
}

fn runtime_mode_label(mode: RuntimeMode) -> &'static str {
    match mode {
        RuntimeMode::Development => "development",
        RuntimeMode::Production => "production",
    }
}

fn log_redaction_mode_label(mode: LogRedactionMode) -> &'static str {
    match mode {
        LogRedactionMode::Off => "off",
        LogRedactionMode::Partial => "partial",
        LogRedactionMode::Strict => "strict",
    }
}

fn redact_value(mode: LogRedactionMode, value: &str) -> String {
    match mode {
        LogRedactionMode::Off => value.to_string(),
        LogRedactionMode::Partial => {
            if value.len() <= 8 {
                "***".to_string()
            } else {
                format!("{}...{}", &value[..4], &value[value.len() - 4..])
            }
        }
        LogRedactionMode::Strict => {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            value.hash(&mut hasher);
            format!("h:{:016x}", hasher.finish())
        }
    }
}

fn redact_uuid(mode: LogRedactionMode, id: Uuid) -> String {
    redact_value(mode, &id.to_string())
}

fn validate_runtime_configuration(mode: RuntimeMode, state: &AppState) -> anyhow::Result<()> {
    if mode != RuntimeMode::Production {
        return Ok(());
    }

    if std::env::var("DATABASE_URL").is_err() {
        anyhow::bail!("DATABASE_URL is required in APP_ENV=production");
    }
    if state.jwt_keys.using_insecure_default {
        anyhow::bail!("APP_JWT_SIGNING_KEYS or APP_JWT_SIGNING_KEY must be set in production");
    }
    if state.allow_legacy_customer_header {
        anyhow::bail!("APP_ALLOW_LEGACY_CUSTOMER_HEADER must be false in production");
    }
    if state.admin_api_token.is_none() {
        anyhow::bail!("ADMIN_API_TOKEN is required in production");
    }
    if !env_flag("APP_REQUIRE_CORE_TLS", false) {
        anyhow::bail!("APP_REQUIRE_CORE_TLS must be true in production");
    }
    if !matches!(state.log_redaction_mode, LogRedactionMode::Strict) {
        anyhow::bail!("APP_LOG_REDACTION_MODE must be strict in production");
    }
    if state.google_oidc.is_none() {
        anyhow::bail!("Google OIDC configuration is required in production");
    }
    Ok(())
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
    let access_token = issue_access_token(customer_id, &state.jwt_keys)
        .map_err(|_| ApiError::service_unavailable("oauth_token_issue_failed"))?;
    info!(
        provider=%provider,
        customer=redact_uuid(state.log_redaction_mode, customer_id),
        "oauth login succeeded"
    );
    Ok(Json(OAuthCallbackResponse {
        provider,
        customer_id,
        access_token,
    }))
}

async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let ctx = auth_context_from_request(&state, &headers).await?;
    let token_id = ctx
        .token_id
        .ok_or_else(|| ApiError::bad_request("token_missing_jti"))?;
    let token_exp = ctx
        .token_exp
        .ok_or_else(|| ApiError::bad_request("token_missing_exp"))?;
    state
        .revoked_token_ids
        .lock()
        .await
        .insert(token_id.clone(), token_exp);
    if let Some(repo) = &state.token_store {
        let expires_at = chrono::DateTime::<Utc>::from_timestamp(token_exp as i64, 0)
            .ok_or_else(|| ApiError::bad_request("token_invalid_exp"))?;
        repo.revoke_token(&token_id, ctx.customer_id, expires_at)
            .await
            .map_err(map_token_repo_error)?;
    }
    info!(
        customer = redact_uuid(state.log_redaction_mode, ctx.customer_id),
        token = redact_value(state.log_redaction_mode, &token_id),
        "logout revoked access token"
    );
    Ok(StatusCode::NO_CONTENT)
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
    let customer_id = customer_id_from_request(&state, &headers).await?;
    if payload.name.trim().is_empty() || payload.public_key.trim().is_empty() {
        return Err(ApiError::bad_request("invalid_device_payload"));
    }
    let entitlements = state
        .subscription_store
        .entitlements_for_customer(customer_id)
        .await?;

    let mut devices_map = state.devices_by_customer.write().await;
    let entry = devices_map.entry(customer_id).or_default();
    if entry.len() as i32 >= entitlements.max_devices {
        return Err(ApiError::bad_request("device_limit_reached"));
    }
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
    let customer_id = customer_id_from_request(&state, &headers).await?;
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
    country_code: Option<String>,
    city_code: Option<String>,
    pool: Option<String>,
    provider: String,
    endpoint_host: String,
    endpoint_port: u16,
    healthy: Option<bool>,
    active_peer_count: Option<i64>,
    capacity_peers: Option<i64>,
}

#[derive(Deserialize)]
struct UpdateNodeHealthRequest {
    node_id: Uuid,
    healthy: bool,
    active_peer_count: i64,
}

#[derive(Deserialize)]
struct UpsertSubscriptionRequest {
    customer_id: Uuid,
    plan_code: String,
    status: String,
}

#[derive(Serialize)]
struct UpsertSubscriptionResponse {
    customer_id: Uuid,
    plan_code: String,
    status: String,
}

#[derive(Serialize)]
struct SubscriptionResponse {
    customer_id: Uuid,
    plan_code: String,
    status: String,
    starts_at: chrono::DateTime<Utc>,
    ends_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Deserialize)]
struct ListSubscriptionsQuery {
    limit: Option<i64>,
    offset: Option<i64>,
    status: Option<String>,
    plan_code: Option<String>,
}

#[derive(Deserialize)]
struct SubscriptionHistoryQuery {
    limit: Option<i64>,
}

#[derive(Serialize)]
struct ListSubscriptionsResponse {
    items: Vec<SubscriptionResponse>,
    limit: i64,
    offset: i64,
}

#[derive(Serialize)]
struct PrivacyPolicyResponse {
    mode: String,
    log_redaction_mode: String,
    terminated_session_retention_days: i64,
    audit_retention_days: i64,
    compliant: bool,
    notes: Vec<&'static str>,
}

#[derive(Serialize)]
struct CoreStatusResponse {
    healthy: bool,
    active_peer_count: i64,
    nat_driver: String,
    dataplane_mode: String,
    native_nft_supported: bool,
}

impl From<SubscriptionRecord> for SubscriptionResponse {
    fn from(value: SubscriptionRecord) -> Self {
        Self {
            customer_id: value.customer_id,
            plan_code: value.plan_code,
            status: value.status,
            starts_at: value.starts_at,
            ends_at: value.ends_at,
        }
    }
}

#[derive(Serialize)]
struct NodeResponse {
    id: Uuid,
    region: String,
    country_code: String,
    city_code: Option<String>,
    pool: String,
    provider: String,
    endpoint_host: String,
    endpoint_port: u16,
    healthy: bool,
    active_peer_count: i64,
    capacity_peers: i64,
    updated_at: chrono::DateTime<Utc>,
}

impl From<NodeRecord> for NodeResponse {
    fn from(value: NodeRecord) -> Self {
        Self {
            id: value.id,
            region: value.region,
            country_code: value.country_code,
            city_code: value.city_code,
            pool: value.pool,
            provider: value.provider,
            endpoint_host: value.endpoint_host,
            endpoint_port: value.endpoint_port,
            healthy: value.healthy,
            active_peer_count: value.active_peer_count,
            capacity_peers: value.capacity_peers,
            updated_at: value.updated_at,
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

async fn get_privacy_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<PrivacyPolicyResponse>, ApiError> {
    require_admin_token(&state, &headers)?;
    let mut notes = Vec::new();
    let mut compliant = true;

    if state.terminated_session_retention_days > 30 {
        compliant = false;
        notes.push("terminated session retention exceeds 30-day policy target");
    }
    if state.audit_retention_days > 90 {
        compliant = false;
        notes.push("audit retention exceeds 90-day policy target");
    }
    if state.runtime_mode == RuntimeMode::Production
        && !matches!(state.log_redaction_mode, LogRedactionMode::Strict)
    {
        compliant = false;
        notes.push("production requires strict log redaction");
    }

    Ok(Json(PrivacyPolicyResponse {
        mode: runtime_mode_label(state.runtime_mode).to_string(),
        log_redaction_mode: log_redaction_mode_label(state.log_redaction_mode).to_string(),
        terminated_session_retention_days: state.terminated_session_retention_days,
        audit_retention_days: state.audit_retention_days,
        compliant,
        notes,
    }))
}

async fn get_core_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<CoreStatusResponse>, ApiError> {
    require_admin_token(&state, &headers)?;
    let response = {
        let mut client = state.core_client.lock().await;
        client
            .get_node_status(control_plane::proto::GetNodeStatusRequest {
                request_id: Uuid::new_v4().to_string(),
            })
            .await
            .map_err(|_| ApiError::service_unavailable("core_status_failed"))?
            .into_inner()
    };

    Ok(Json(CoreStatusResponse {
        healthy: response.healthy,
        active_peer_count: response.active_peer_count,
        nat_driver: response.nat_driver,
        dataplane_mode: response.dataplane_mode,
        native_nft_supported: response.native_nft_supported,
    }))
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
    let country_code = payload
        .country_code
        .unwrap_or_else(|| "US".to_string())
        .trim()
        .to_uppercase();
    if country_code.len() != 2 {
        return Err(ApiError::bad_request("invalid_country_code"));
    }
    let capacity_peers = payload.capacity_peers.unwrap_or(10000);
    if capacity_peers <= 0 {
        return Err(ApiError::bad_request("invalid_capacity_peers"));
    }

    let input = UpsertNodeInput {
        id: payload.id.unwrap_or_else(Uuid::new_v4),
        region: payload.region,
        country_code,
        city_code: payload.city_code,
        pool: payload.pool.unwrap_or_else(|| "general".to_string()),
        provider: payload.provider,
        endpoint_host: payload.endpoint_host,
        endpoint_port: payload.endpoint_port,
        healthy: payload.healthy.unwrap_or(true),
        active_peer_count: payload.active_peer_count.unwrap_or(0),
        capacity_peers,
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

async fn upsert_subscription(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<UpsertSubscriptionRequest>,
) -> Result<Json<UpsertSubscriptionResponse>, ApiError> {
    require_admin_token(&state, &headers)?;
    if payload.plan_code.trim().is_empty() {
        return Err(ApiError::bad_request("invalid_plan_code"));
    }
    let normalized_plan = payload.plan_code.trim().to_lowercase();
    let status = SubscriptionStatus::parse(payload.status.trim())
        .ok_or_else(|| ApiError::bad_request("invalid_subscription_status"))?;
    state
        .subscription_store
        .upsert_customer_subscription(payload.customer_id, &normalized_plan, status)
        .await?;
    info!(
        customer=redact_uuid(state.log_redaction_mode, payload.customer_id),
        plan_code=%payload.plan_code,
        status=%payload.status,
        "subscription updated"
    );

    Ok(Json(UpsertSubscriptionResponse {
        customer_id: payload.customer_id,
        plan_code: normalized_plan,
        status: payload.status,
    }))
}

async fn get_subscription(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(customer_id): Path<Uuid>,
) -> Result<Json<SubscriptionResponse>, ApiError> {
    require_admin_token(&state, &headers)?;
    let sub = state
        .subscription_store
        .get_customer_subscription(customer_id)
        .await?
        .ok_or_else(|| ApiError::not_found("subscription_not_found"))?;

    Ok(Json(sub.into()))
}

async fn list_subscriptions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ListSubscriptionsQuery>,
) -> Result<Json<ListSubscriptionsResponse>, ApiError> {
    require_admin_token(&state, &headers)?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0).max(0);

    let items = state
        .subscription_store
        .list_subscriptions(
            limit,
            offset,
            query.status.as_deref(),
            query.plan_code.as_deref(),
        )
        .await?;

    Ok(Json(ListSubscriptionsResponse {
        items: items.into_iter().map(Into::into).collect(),
        limit,
        offset,
    }))
}

async fn get_subscription_history(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(customer_id): Path<Uuid>,
    Query(query): Query<SubscriptionHistoryQuery>,
) -> Result<Json<Vec<SubscriptionResponse>>, ApiError> {
    require_admin_token(&state, &headers)?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let items = state
        .subscription_store
        .get_customer_subscription_history(customer_id, limit)
        .await?;
    Ok(Json(items.into_iter().map(Into::into).collect()))
}

#[derive(Deserialize)]
struct StartSessionRequest {
    device_id: Uuid,
    region: Option<String>,
    country_code: Option<String>,
    city_code: Option<String>,
    pool: Option<String>,
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
    let customer_id = customer_id_from_request(&state, &headers).await?;
    if !state
        .subscription_store
        .is_customer_session_eligible(customer_id)
        .await?
    {
        return Err(ApiError::unauthorized("subscription_inactive"));
    }
    let entitlements = state
        .subscription_store
        .entitlements_for_customer(customer_id)
        .await?;

    let requested_region = payload.region.clone().unwrap_or_default();
    if requested_region.trim().is_empty() {
        return Err(ApiError::bad_request("missing_region"));
    }
    if let Some(allowed_regions) = &entitlements.allowed_regions {
        if !requested_region.is_empty() && !allowed_regions.iter().any(|r| r == &requested_region) {
            return Err(ApiError::bad_request("region_not_allowed_by_plan"));
        }
    }

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
            requested_region.clone(),
            requested_session_key.clone(),
            payload.reconnect_session_key.as_deref(),
        )
        .await?;

    match outcome {
        StartSessionOutcome::Conflict {
            existing_session_key,
        } => {
            info!(
                customer = redact_uuid(state.log_redaction_mode, customer_id),
                existing_session = redact_value(state.log_redaction_mode, &existing_session_key),
                "session start conflict due to active session"
            );
            return Ok(Json(StartSessionResponse::Conflict {
                existing_session_key,
                message: "active_session_exists",
            }));
        }
        StartSessionOutcome::Reconnected(existing_row) => {
            let selected_node =
                resolve_node_selection(&state, &payload, Some(existing_row.region.as_str()))
                    .await?;
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
                node_hint: maybe_uuid_to_string(selected_node.map(|n| n.id)),
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
            info!(
                customer=redact_uuid(state.log_redaction_mode, customer_id),
                session=redact_value(state.log_redaction_mode, &existing_row.session_key),
                region=%existing_row.region,
                "session reconnected"
            );

            return Ok(Json(StartSessionResponse::Active {
                session_key: existing_row.session_key,
                region: existing_row.region,
                config,
            }));
        }
        StartSessionOutcome::Created(created_row) => {
            let selected_node =
                resolve_node_selection(&state, &payload, Some(created_row.region.as_str())).await?;
            let effective_region = selected_node
                .as_ref()
                .map(|n| n.region.clone())
                .or_else(|| payload.region.clone())
                .unwrap_or_else(|| created_row.region.clone());
            let request = ConnectRequest {
                request_id: Uuid::new_v4().to_string(),
                session_key: created_row.session_key.clone(),
                customer_id: customer_id.to_string(),
                device_id: device.id.to_string(),
                device_public_key: device.public_key,
                region: effective_region.clone(),
                node_hint: maybe_uuid_to_string(selected_node.map(|n| n.id)),
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
                    region: effective_region.clone(),
                    config: config.clone(),
                },
            );
            info!(
                customer=redact_uuid(state.log_redaction_mode, customer_id),
                session=redact_value(state.log_redaction_mode, &created_row.session_key),
                region=%effective_region,
                "session started"
            );

            return Ok(Json(StartSessionResponse::Active {
                session_key: created_row.session_key,
                region: effective_region,
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
    let customer_id = customer_id_from_request(&state, &headers).await?;

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
    let customer_id = customer_id_from_request(&state, &headers).await?;

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
    info!(
        customer = redact_uuid(state.log_redaction_mode, customer_id),
        session = redact_value(state.log_redaction_mode, &session_key),
        "session terminated"
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn customer_id_from_request(state: &AppState, headers: &HeaderMap) -> Result<Uuid, ApiError> {
    Ok(auth_context_from_request(state, headers).await?.customer_id)
}

async fn auth_context_from_request(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthContext, ApiError> {
    if let Some(auth) = headers.get("authorization") {
        let raw = auth
            .to_str()
            .map_err(|_| ApiError::unauthorized("invalid_authorization_header"))?;
        if let Some(token) = raw.strip_prefix("Bearer ") {
            let ctx = auth_context_from_bearer(token, &state.jwt_keys)?;
            if let Some(token_id) = ctx.token_id.as_deref() {
                let now = Utc::now().timestamp() as usize;
                let mut revoked = state.revoked_token_ids.lock().await;
                revoked.retain(|_, exp| *exp > now);
                if revoked.get(token_id).is_some() {
                    return Err(ApiError::unauthorized("revoked_access_token"));
                }
                drop(revoked);
                if let Some(repo) = &state.token_store {
                    if repo
                        .is_revoked(token_id)
                        .await
                        .map_err(map_token_repo_error)?
                    {
                        state
                            .revoked_token_ids
                            .lock()
                            .await
                            .insert(token_id.to_string(), ctx.token_exp.unwrap_or(now + 900));
                        return Err(ApiError::unauthorized("revoked_access_token"));
                    }
                }
            }
            return Ok(ctx);
        }
    }

    if !state.allow_legacy_customer_header {
        return Err(ApiError::unauthorized("missing_bearer_token"));
    }

    Ok(AuthContext {
        customer_id: customer_id_from_headers(headers)?,
        token_id: None,
        token_exp: None,
    })
}

fn auth_context_from_bearer(token: &str, keys: &JwtKeyStore) -> Result<AuthContext, ApiError> {
    let header =
        decode_header(token).map_err(|_| ApiError::unauthorized("invalid_access_token"))?;
    let kid = header
        .kid
        .as_deref()
        .ok_or_else(|| ApiError::unauthorized("invalid_access_token"))?;
    let secret = keys
        .key_for_kid(kid)
        .ok_or_else(|| ApiError::unauthorized("invalid_access_token"))?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&["entry"]);
    let decoded = jsonwebtoken::decode::<AccessTokenClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|_| ApiError::unauthorized("invalid_access_token"))?;

    Ok(AuthContext {
        customer_id: Uuid::parse_str(&decoded.claims.sub)
            .map_err(|_| ApiError::unauthorized("invalid_customer_id"))?,
        token_id: decoded.claims.jti,
        token_exp: Some(decoded.claims.exp),
    })
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

    if provided.len() != configured.len()
        || provided.as_bytes().ct_eq(configured.as_bytes()).unwrap_u8() != 1
    {
        return Err(ApiError::unauthorized("invalid_admin_token"));
    }

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct AccessTokenClaims {
    sub: String,
    iss: String,
    jti: Option<String>,
    iat: usize,
    exp: usize,
}

fn issue_access_token(
    customer_id: Uuid,
    keys: &JwtKeyStore,
) -> Result<String, jsonwebtoken::errors::Error> {
    let (kid, signing_key) = keys.active_signing_key().ok_or_else(|| {
        jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidKeyFormat)
    })?;
    let now = Utc::now().timestamp() as usize;
    let claims = AccessTokenClaims {
        sub: customer_id.to_string(),
        iss: "entry".to_string(),
        jti: Some(Uuid::new_v4().to_string()),
        iat: now,
        exp: now + 15 * 60,
    };
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(kid.to_string());
    encode(
        &header,
        &claims,
        &EncodingKey::from_secret(signing_key.as_bytes()),
    )
}

async fn resolve_node_selection(
    state: &Arc<AppState>,
    payload: &StartSessionRequest,
    default_region: Option<&str>,
) -> Result<Option<NodeRecord>, ApiError> {
    let requested_hint = payload.node_hint;
    if let Some(hint) = requested_hint {
        let region = payload
            .region
            .clone()
            .or_else(|| default_region.map(ToString::to_string))
            .unwrap_or_default();
        return Ok(Some(NodeRecord {
            id: hint,
            region,
            country_code: payload
                .country_code
                .clone()
                .unwrap_or_else(|| "US".to_string())
                .to_uppercase(),
            city_code: payload.city_code.clone(),
            pool: payload
                .pool
                .clone()
                .unwrap_or_else(|| "general".to_string()),
            provider: "hint".to_string(),
            endpoint_host: String::new(),
            endpoint_port: 0,
            healthy: true,
            active_peer_count: 0,
            capacity_peers: i64::MAX,
            updated_at: Utc::now(),
        }));
    }

    let criteria = NodeSelectionCriteria {
        region: payload
            .region
            .clone()
            .or_else(|| default_region.map(ToString::to_string))
            .filter(|v| !v.trim().is_empty()),
        country_code: payload.country_code.clone().map(|v| v.to_uppercase()),
        city_code: payload.city_code.clone(),
        pool: payload.pool.clone(),
    };
    let selected = state
        .node_store
        .select_node(&criteria, state.node_freshness_secs)
        .await?;
    if selected.is_none() && state.node_store.requires_selection() {
        return Err(ApiError::bad_request("no_nodes_available_for_selection"));
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

fn map_token_repo_error(err: TokenRepoError) -> ApiError {
    match err {
        TokenRepoError::Database(_) => ApiError::service_unavailable("token_store_failed"),
    }
}

fn map_node_repo_error(err: NodeRepoError) -> ApiError {
    match err {
        NodeRepoError::Database(_) => ApiError::service_unavailable("node_store_failed"),
    }
}

fn map_subscription_repo_error(err: SubscriptionRepoError) -> ApiError {
    match err {
        SubscriptionRepoError::PlanNotFound => ApiError::bad_request("plan_not_found"),
        SubscriptionRepoError::Database(_) => {
            ApiError::service_unavailable("subscription_store_failed")
        }
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
    use chrono::Duration;
    use jsonwebtoken::errors::{Error as JwtError, ErrorKind};

    fn test_keys() -> JwtKeyStore {
        let mut keys = HashMap::new();
        keys.insert("v1".to_string(), "test-key".to_string());
        JwtKeyStore {
            active_kid: "v1".to_string(),
            keys,
            using_insecure_default: false,
        }
    }

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

    #[test]
    fn issue_access_token_embeds_customer_subject() {
        let customer_id = Uuid::new_v4();
        let token = issue_access_token(customer_id, &test_keys()).expect("token");
        let decoded = jsonwebtoken::decode::<AccessTokenClaims>(
            &token,
            &jsonwebtoken::DecodingKey::from_secret("test-key".as_bytes()),
            &jsonwebtoken::Validation::new(Algorithm::HS256),
        )
        .expect("decoded");
        assert_eq!(decoded.claims.sub, customer_id.to_string());
        assert_eq!(decoded.claims.iss, "entry");
        assert!(decoded.claims.jti.is_some());
    }

    #[test]
    fn customer_id_from_bearer_parses_signed_token() {
        let customer_id = Uuid::new_v4();
        let keys = test_keys();
        let token = issue_access_token(customer_id, &keys).expect("token");
        let parsed = auth_context_from_bearer(&token, &keys).expect("parsed");
        assert_eq!(parsed.customer_id, customer_id);
        assert!(parsed.token_id.is_some());
    }

    #[test]
    fn customer_id_from_bearer_rejects_bad_token() {
        let err = auth_context_from_bearer("bad-token", &test_keys()).expect_err("should fail");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.code, "invalid_access_token");
    }

    #[test]
    fn redact_value_strict_is_stable_but_not_plaintext() {
        let input = "sess_1234567890";
        let redacted = redact_value(LogRedactionMode::Strict, input);
        assert_ne!(redacted, input);
        assert!(redacted.starts_with("h:"));
    }

    #[test]
    fn redact_value_partial_masks_middle() {
        let input = "sess_1234567890";
        let redacted = redact_value(LogRedactionMode::Partial, input);
        assert!(redacted.starts_with("sess"));
        assert!(redacted.ends_with("7890"));
        assert!(redacted.contains("..."));
    }

    #[tokio::test]
    async fn get_core_status_requires_admin_token_header() {
        let state = Arc::new(AppState {
            runtime_sessions_by_customer: RwLock::new(HashMap::new()),
            devices_by_customer: RwLock::new(HashMap::new()),
            core_client: Mutex::new(ControlPlaneClient::new(
                tonic::transport::Endpoint::from_static("http://127.0.0.1:50051").connect_lazy(),
            )),
            session_store: SessionStore::InMemory(Mutex::new(InMemorySessionRepository::default())),
            http_client: reqwest::Client::new(),
            google_oidc: None,
            identity_store: IdentityStore::InMemory(Mutex::new(HashMap::new())),
            node_store: NodeStore::InMemory(Mutex::new(HashMap::new())),
            admin_api_token: Some("admin-secret".to_string()),
            jwt_keys: test_keys(),
            allow_legacy_customer_header: false,
            revoked_token_ids: Mutex::new(HashMap::new()),
            token_store: None,
            subscription_store: SubscriptionStore::InMemory(Mutex::new(HashMap::new())),
            privacy_store: None,
            runtime_mode: RuntimeMode::Development,
            log_redaction_mode: LogRedactionMode::Off,
            terminated_session_retention_days: 7,
            audit_retention_days: 30,
            node_freshness_secs: 60,
        });

        let err = get_core_status(State(state), HeaderMap::new())
            .await
            .expect_err("missing admin token should fail");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.code, "missing_x_admin_token");
    }

    #[tokio::test]
    async fn get_core_status_returns_service_unavailable_when_core_unreachable() {
        let state = Arc::new(AppState {
            runtime_sessions_by_customer: RwLock::new(HashMap::new()),
            devices_by_customer: RwLock::new(HashMap::new()),
            core_client: Mutex::new(ControlPlaneClient::new(
                tonic::transport::Endpoint::from_static("http://127.0.0.1:50051").connect_lazy(),
            )),
            session_store: SessionStore::InMemory(Mutex::new(InMemorySessionRepository::default())),
            http_client: reqwest::Client::new(),
            google_oidc: None,
            identity_store: IdentityStore::InMemory(Mutex::new(HashMap::new())),
            node_store: NodeStore::InMemory(Mutex::new(HashMap::new())),
            admin_api_token: Some("admin-secret".to_string()),
            jwt_keys: test_keys(),
            allow_legacy_customer_header: false,
            revoked_token_ids: Mutex::new(HashMap::new()),
            token_store: None,
            subscription_store: SubscriptionStore::InMemory(Mutex::new(HashMap::new())),
            privacy_store: None,
            runtime_mode: RuntimeMode::Development,
            log_redaction_mode: LogRedactionMode::Off,
            terminated_session_retention_days: 7,
            audit_retention_days: 30,
            node_freshness_secs: 60,
        });

        let mut headers = HeaderMap::new();
        headers.insert("x-admin-token", HeaderValue::from_static("admin-secret"));

        let err = get_core_status(State(state), headers)
            .await
            .expect_err("unreachable core should fail");
        assert_eq!(err.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.code, "core_status_failed");
    }

    #[test]
    #[tokio::test]
    async fn customer_id_from_request_requires_bearer_when_legacy_disabled() {
        let state = AppState {
            runtime_sessions_by_customer: RwLock::new(HashMap::new()),
            devices_by_customer: RwLock::new(HashMap::new()),
            core_client: Mutex::new(ControlPlaneClient::new(
                tonic::transport::Endpoint::from_static("http://127.0.0.1:50051").connect_lazy(),
            )),
            session_store: SessionStore::InMemory(Mutex::new(InMemorySessionRepository::default())),
            http_client: reqwest::Client::new(),
            google_oidc: None,
            identity_store: IdentityStore::InMemory(Mutex::new(HashMap::new())),
            node_store: NodeStore::InMemory(Mutex::new(HashMap::new())),
            admin_api_token: None,
            jwt_keys: test_keys(),
            allow_legacy_customer_header: false,
            revoked_token_ids: Mutex::new(HashMap::new()),
            token_store: None,
            subscription_store: SubscriptionStore::InMemory(Mutex::new(HashMap::new())),
            privacy_store: None,
            runtime_mode: RuntimeMode::Development,
            log_redaction_mode: LogRedactionMode::Off,
            terminated_session_retention_days: 7,
            audit_retention_days: 30,
            node_freshness_secs: 60,
        };

        let headers = HeaderMap::new();
        let err = customer_id_from_request(&state, &headers)
            .await
            .expect_err("should fail");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.code, "missing_bearer_token");
    }

    #[tokio::test]
    async fn auth_context_rejects_revoked_bearer_token() {
        let keys = test_keys();
        let customer_id = Uuid::new_v4();
        let token = issue_access_token(customer_id, &keys).expect("token");
        let ctx = auth_context_from_bearer(&token, &keys).expect("ctx");
        let mut revoked = HashMap::new();
        revoked.insert(ctx.token_id.expect("jti"), usize::MAX);

        let state = AppState {
            runtime_sessions_by_customer: RwLock::new(HashMap::new()),
            devices_by_customer: RwLock::new(HashMap::new()),
            core_client: Mutex::new(ControlPlaneClient::new(
                tonic::transport::Endpoint::from_static("http://127.0.0.1:50051").connect_lazy(),
            )),
            session_store: SessionStore::InMemory(Mutex::new(InMemorySessionRepository::default())),
            http_client: reqwest::Client::new(),
            google_oidc: None,
            identity_store: IdentityStore::InMemory(Mutex::new(HashMap::new())),
            node_store: NodeStore::InMemory(Mutex::new(HashMap::new())),
            admin_api_token: None,
            jwt_keys: keys,
            allow_legacy_customer_header: false,
            revoked_token_ids: Mutex::new(revoked),
            token_store: None,
            subscription_store: SubscriptionStore::InMemory(Mutex::new(HashMap::new())),
            privacy_store: None,
            runtime_mode: RuntimeMode::Development,
            log_redaction_mode: LogRedactionMode::Off,
            terminated_session_retention_days: 7,
            audit_retention_days: 30,
            node_freshness_secs: 60,
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).expect("header"),
        );

        let err = auth_context_from_request(&state, &headers)
            .await
            .expect_err("revoked should fail");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.code, "revoked_access_token");
    }

    #[tokio::test]
    async fn auth_context_ignores_expired_revocation_cache_entries() {
        let keys = test_keys();
        let customer_id = Uuid::new_v4();
        let token = issue_access_token(customer_id, &keys).expect("token");
        let ctx = auth_context_from_bearer(&token, &keys).expect("ctx");
        let token_id = ctx.token_id.clone().expect("jti");
        let mut revoked = HashMap::new();
        revoked.insert(token_id.clone(), 0usize);

        let state = AppState {
            runtime_sessions_by_customer: RwLock::new(HashMap::new()),
            devices_by_customer: RwLock::new(HashMap::new()),
            core_client: Mutex::new(ControlPlaneClient::new(
                tonic::transport::Endpoint::from_static("http://127.0.0.1:50051").connect_lazy(),
            )),
            session_store: SessionStore::InMemory(Mutex::new(InMemorySessionRepository::default())),
            http_client: reqwest::Client::new(),
            google_oidc: None,
            identity_store: IdentityStore::InMemory(Mutex::new(HashMap::new())),
            node_store: NodeStore::InMemory(Mutex::new(HashMap::new())),
            admin_api_token: None,
            jwt_keys: keys,
            allow_legacy_customer_header: false,
            revoked_token_ids: Mutex::new(revoked),
            token_store: None,
            subscription_store: SubscriptionStore::InMemory(Mutex::new(HashMap::new())),
            privacy_store: None,
            runtime_mode: RuntimeMode::Development,
            log_redaction_mode: LogRedactionMode::Off,
            terminated_session_retention_days: 7,
            audit_retention_days: 30,
            node_freshness_secs: 60,
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).expect("header"),
        );

        let parsed = auth_context_from_request(&state, &headers)
            .await
            .expect("expired cache entry should be purged");
        assert_eq!(parsed.customer_id, customer_id);

        let revoked_after = state.revoked_token_ids.lock().await;
        assert!(!revoked_after.contains_key(&token_id));
    }

    #[tokio::test]
    async fn node_selection_skips_stale_nodes_and_prefers_lowest_load_fresh_node() {
        let stale_id = Uuid::new_v4();
        let fresh_busy_id = Uuid::new_v4();
        let fresh_best_id = Uuid::new_v4();
        let mut nodes = HashMap::new();
        nodes.insert(
            stale_id,
            NodeRecord {
                id: stale_id,
                region: "us-west1".to_string(),
                country_code: "US".to_string(),
                city_code: Some("SFO".to_string()),
                pool: "general".to_string(),
                provider: "gcp".to_string(),
                endpoint_host: "stale.example.com".to_string(),
                endpoint_port: 51820,
                healthy: true,
                active_peer_count: 0,
                capacity_peers: 100,
                updated_at: Utc::now() - Duration::seconds(120),
            },
        );
        nodes.insert(
            fresh_busy_id,
            NodeRecord {
                id: fresh_busy_id,
                region: "us-west1".to_string(),
                country_code: "US".to_string(),
                city_code: Some("SFO".to_string()),
                pool: "general".to_string(),
                provider: "gcp".to_string(),
                endpoint_host: "busy.example.com".to_string(),
                endpoint_port: 51820,
                healthy: true,
                active_peer_count: 5,
                capacity_peers: 100,
                updated_at: Utc::now(),
            },
        );
        nodes.insert(
            fresh_best_id,
            NodeRecord {
                id: fresh_best_id,
                region: "us-west1".to_string(),
                country_code: "US".to_string(),
                city_code: Some("SFO".to_string()),
                pool: "general".to_string(),
                provider: "gcp".to_string(),
                endpoint_host: "best.example.com".to_string(),
                endpoint_port: 51820,
                healthy: true,
                active_peer_count: 2,
                capacity_peers: 100,
                updated_at: Utc::now(),
            },
        );

        let store = NodeStore::InMemory(Mutex::new(nodes));
        let selected = store
            .select_node(
                &NodeSelectionCriteria {
                    region: Some("us-west1".to_string()),
                    country_code: Some("US".to_string()),
                    city_code: Some("SFO".to_string()),
                    pool: Some("general".to_string()),
                },
                60,
            )
            .await
            .expect("select node");
        assert_eq!(selected.map(|n| n.id), Some(fresh_best_id));
    }

    #[tokio::test]
    async fn register_device_rejects_when_plan_device_limit_reached() {
        let customer_id = Uuid::new_v4();
        let existing = Device {
            id: Uuid::new_v4(),
            customer_id,
            name: "existing".to_string(),
            public_key: "pk-existing".to_string(),
            created_at: Utc::now(),
        };
        let mut devices = HashMap::new();
        devices.insert(customer_id, vec![existing]);

        let mut subscriptions = HashMap::new();
        subscriptions.insert(
            customer_id,
            SubscriptionProfile {
                entitlements: Entitlements {
                    max_active_sessions: 1,
                    max_devices: 1,
                    allowed_regions: None,
                },
                session_eligible: true,
            },
        );

        let state = Arc::new(AppState {
            runtime_sessions_by_customer: RwLock::new(HashMap::new()),
            devices_by_customer: RwLock::new(devices),
            core_client: Mutex::new(ControlPlaneClient::new(
                tonic::transport::Endpoint::from_static("http://127.0.0.1:50051").connect_lazy(),
            )),
            session_store: SessionStore::InMemory(Mutex::new(InMemorySessionRepository::default())),
            http_client: reqwest::Client::new(),
            google_oidc: None,
            identity_store: IdentityStore::InMemory(Mutex::new(HashMap::new())),
            node_store: NodeStore::InMemory(Mutex::new(HashMap::new())),
            admin_api_token: None,
            jwt_keys: test_keys(),
            allow_legacy_customer_header: true,
            revoked_token_ids: Mutex::new(HashMap::new()),
            token_store: None,
            subscription_store: SubscriptionStore::InMemory(Mutex::new(subscriptions)),
            privacy_store: None,
            runtime_mode: RuntimeMode::Development,
            log_redaction_mode: LogRedactionMode::Off,
            terminated_session_retention_days: 7,
            audit_retention_days: 30,
            node_freshness_secs: 60,
        });

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-customer-id",
            HeaderValue::from_str(&customer_id.to_string()).expect("header"),
        );

        let err = register_device(
            State(state),
            headers,
            Json(RegisterDeviceRequest {
                name: "new".to_string(),
                public_key: "pk-new".to_string(),
            }),
        )
        .await
        .expect_err("device limit should fail");
        assert_eq!(err.code, "device_limit_reached");
    }

    #[tokio::test]
    async fn start_session_rejects_region_not_allowed_by_plan() {
        let customer_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let mut devices = HashMap::new();
        devices.insert(
            customer_id,
            vec![Device {
                id: device_id,
                customer_id,
                name: "phone".to_string(),
                public_key: "pk".to_string(),
                created_at: Utc::now(),
            }],
        );

        let mut subscriptions = HashMap::new();
        subscriptions.insert(
            customer_id,
            SubscriptionProfile {
                entitlements: Entitlements {
                    max_active_sessions: 1,
                    max_devices: 3,
                    allowed_regions: Some(vec!["us-east1".to_string()]),
                },
                session_eligible: true,
            },
        );

        let state = Arc::new(AppState {
            runtime_sessions_by_customer: RwLock::new(HashMap::new()),
            devices_by_customer: RwLock::new(devices),
            core_client: Mutex::new(ControlPlaneClient::new(
                tonic::transport::Endpoint::from_static("http://127.0.0.1:50051").connect_lazy(),
            )),
            session_store: SessionStore::InMemory(Mutex::new(InMemorySessionRepository::default())),
            http_client: reqwest::Client::new(),
            google_oidc: None,
            identity_store: IdentityStore::InMemory(Mutex::new(HashMap::new())),
            node_store: NodeStore::InMemory(Mutex::new(HashMap::new())),
            admin_api_token: None,
            jwt_keys: test_keys(),
            allow_legacy_customer_header: true,
            revoked_token_ids: Mutex::new(HashMap::new()),
            token_store: None,
            subscription_store: SubscriptionStore::InMemory(Mutex::new(subscriptions)),
            privacy_store: None,
            runtime_mode: RuntimeMode::Development,
            log_redaction_mode: LogRedactionMode::Off,
            terminated_session_retention_days: 7,
            audit_retention_days: 30,
            node_freshness_secs: 60,
        });

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-customer-id",
            HeaderValue::from_str(&customer_id.to_string()).expect("header"),
        );

        let err = start_session(
            State(state),
            headers,
            Json(StartSessionRequest {
                device_id,
                region: Some("us-west1".to_string()),
                country_code: Some("US".to_string()),
                city_code: None,
                pool: Some("general".to_string()),
                reconnect_session_key: None,
                node_hint: None,
            }),
        )
        .await
        .expect_err("region policy should reject");
        assert_eq!(err.code, "region_not_allowed_by_plan");
    }

    #[tokio::test]
    async fn start_session_rejects_when_subscription_inactive() {
        let customer_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let mut devices = HashMap::new();
        devices.insert(
            customer_id,
            vec![Device {
                id: device_id,
                customer_id,
                name: "phone".to_string(),
                public_key: "pk".to_string(),
                created_at: Utc::now(),
            }],
        );

        let mut subscriptions = HashMap::new();
        subscriptions.insert(
            customer_id,
            SubscriptionProfile {
                entitlements: Entitlements::default(),
                session_eligible: false,
            },
        );

        let state = Arc::new(AppState {
            runtime_sessions_by_customer: RwLock::new(HashMap::new()),
            devices_by_customer: RwLock::new(devices),
            core_client: Mutex::new(ControlPlaneClient::new(
                tonic::transport::Endpoint::from_static("http://127.0.0.1:50051").connect_lazy(),
            )),
            session_store: SessionStore::InMemory(Mutex::new(InMemorySessionRepository::default())),
            http_client: reqwest::Client::new(),
            google_oidc: None,
            identity_store: IdentityStore::InMemory(Mutex::new(HashMap::new())),
            node_store: NodeStore::InMemory(Mutex::new(HashMap::new())),
            admin_api_token: None,
            jwt_keys: test_keys(),
            allow_legacy_customer_header: true,
            revoked_token_ids: Mutex::new(HashMap::new()),
            token_store: None,
            subscription_store: SubscriptionStore::InMemory(Mutex::new(subscriptions)),
            privacy_store: None,
            runtime_mode: RuntimeMode::Development,
            log_redaction_mode: LogRedactionMode::Off,
            terminated_session_retention_days: 7,
            audit_retention_days: 30,
            node_freshness_secs: 60,
        });

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-customer-id",
            HeaderValue::from_str(&customer_id.to_string()).expect("header"),
        );

        let err = start_session(
            State(state),
            headers,
            Json(StartSessionRequest {
                device_id,
                region: Some("us-west1".to_string()),
                country_code: Some("US".to_string()),
                city_code: None,
                pool: Some("general".to_string()),
                reconnect_session_key: None,
                node_hint: None,
            }),
        )
        .await
        .expect_err("inactive subscription should reject");
        assert_eq!(err.code, "subscription_inactive");
    }
}
