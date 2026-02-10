mod dataplane;
mod ip_pool;
mod wg_uapi;

use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use chrono::Utc;
use control_plane::proto::{
    ConnectRequest, ConnectResponse, DisconnectRequest, DisconnectResponse, GetSessionRequest,
    GetSessionResponse, SessionSnapshot,
};
use control_plane::{
    ControlPlane, ControlPlaneServer, config_to_proto, into_rfc3339, parse_optional_uuid,
    parse_uuid,
};
use dataplane::{DataPlane, LinuxDataPlaneConfig, LinuxShellDataPlane, NoopDataPlane, PeerSpec};
use domain::WireGuardClientConfig;
use ip_pool::Ipv4Pool;
use tokio::sync::RwLock;
use tokio::time::{Duration, sleep};
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use tonic::{Code, Request, Response, Status};
use tracing::{error, info};
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("core=info")
        .without_time()
        .init();

    let addr = "127.0.0.1:50051".parse()?;
    let endpoint_template = std::env::var("WG_ENDPOINT_TEMPLATE")
        .unwrap_or_else(|_| "{region}.gcp.vpn.example.net:51820".to_string());
    let server_public_key =
        std::env::var("WG_SERVER_PUBLIC_KEY").unwrap_or_else(|_| "<server_public_key>".to_string());

    let use_noop = std::env::var("CORE_DATAPLANE_NOOP")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);
    let dataplane: Arc<dyn DataPlane> = if use_noop {
        Arc::new(NoopDataPlane)
    } else {
        let cfg = LinuxDataPlaneConfig {
            iface: std::env::var("WG_INTERFACE").unwrap_or_else(|_| "wg0".to_string()),
            interface_cidr: std::env::var("WG_INTERFACE_CIDR")
                .unwrap_or_else(|_| "10.90.0.1/24".to_string()),
            private_key_path: std::env::var("WG_PRIVATE_KEY_PATH")
                .unwrap_or_else(|_| "/etc/wireguard/private.key".to_string()),
            listen_port: std::env::var("WG_LISTEN_PORT")
                .ok()
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(51820),
            egress_iface: std::env::var("WG_EGRESS_IFACE").unwrap_or_else(|_| "eth0".to_string()),
        };
        Arc::new(LinuxShellDataPlane::new(cfg))
    };

    dataplane.bootstrap().await.map_err(anyhow::Error::msg)?;

    let service = CoreService::new(dataplane, endpoint_template, server_public_key);

    tokio::spawn(reconciliation_loop(service.clone()));
    if let Some(cfg) = HealthReporterConfig::from_env() {
        tokio::spawn(health_report_loop(service.clone(), cfg));
    }

    info!(%addr, "core gRPC service started");
    let mut server = tonic::transport::Server::builder();
    if let Some(tls) = server_tls_config_from_env()? {
        server = server.tls_config(tls)?;
        info!("core gRPC TLS enabled");
    }
    server
        .add_service(ControlPlaneServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}

async fn reconciliation_loop(service: CoreService) {
    loop {
        let peers = service.desired_peers().await;
        if let Err(err) = service.dataplane.reconcile(&peers).await {
            error!(%err, "dataplane reconciliation failed");
        }
        sleep(Duration::from_secs(30)).await;
    }
}

#[derive(Clone)]
struct HealthReporterConfig {
    node_id: Uuid,
    entry_health_url: String,
    admin_api_token: String,
}

impl HealthReporterConfig {
    fn from_env() -> Option<Self> {
        let node_id = std::env::var("CORE_NODE_ID")
            .ok()
            .and_then(|v| Uuid::parse_str(&v).ok())?;
        let admin_api_token = std::env::var("ADMIN_API_TOKEN").ok()?;
        let entry_health_url = std::env::var("CORE_ENTRY_HEALTH_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8080/v1/internal/nodes/health".to_string());

        Some(Self {
            node_id,
            entry_health_url,
            admin_api_token,
        })
    }
}

async fn health_report_loop(service: CoreService, cfg: HealthReporterConfig) {
    let http = reqwest::Client::new();
    loop {
        let active_peer_count = service.active_peer_count().await;
        let body = serde_json::json!({
            "node_id": cfg.node_id,
            "healthy": true,
            "active_peer_count": active_peer_count,
        });

        let res = http
            .post(&cfg.entry_health_url)
            .header("x-admin-token", &cfg.admin_api_token)
            .json(&body)
            .send()
            .await;
        if let Err(err) = res {
            error!(%err, "failed to publish node health");
        }

        sleep(Duration::from_secs(10)).await;
    }
}

fn server_tls_config_from_env() -> anyhow::Result<Option<ServerTlsConfig>> {
    let cert_path = std::env::var("CORE_TLS_CERT_PATH").ok();
    let key_path = std::env::var("CORE_TLS_KEY_PATH").ok();
    let (Some(cert_path), Some(key_path)) = (cert_path, key_path) else {
        return Ok(None);
    };

    let cert = fs::read(cert_path)?;
    let key = fs::read(key_path)?;
    let identity = Identity::from_pem(cert, key);
    let mut cfg = ServerTlsConfig::new().identity(identity);

    if let Ok(ca_path) = std::env::var("CORE_TLS_CLIENT_CA_CERT_PATH") {
        let ca = fs::read(ca_path)?;
        cfg = cfg.client_ca_root(Certificate::from_pem(ca));
    }

    Ok(Some(cfg))
}

struct CoreRuntime {
    sessions: HashMap<Uuid, RuntimeSession>,
    ip_pool: Ipv4Pool,
}

impl Default for CoreRuntime {
    fn default() -> Self {
        Self {
            sessions: HashMap::new(),
            ip_pool: Ipv4Pool::new([10, 90, 0], 24, 2, 254),
        }
    }
}

#[derive(Debug, Clone)]
struct RuntimeSession {
    snapshot: SessionSnapshot,
    peer: PeerSpec,
}

#[derive(Clone)]
struct CoreService {
    runtime: Arc<RwLock<CoreRuntime>>,
    dataplane: Arc<dyn DataPlane>,
    endpoint_template: String,
    server_public_key: String,
}

impl CoreService {
    fn new(
        dataplane: Arc<dyn DataPlane>,
        endpoint_template: String,
        server_public_key: String,
    ) -> Self {
        Self::new_with_pool(
            dataplane,
            endpoint_template,
            server_public_key,
            Ipv4Pool::new([10, 90, 0], 24, 2, 254),
        )
    }

    fn new_with_pool(
        dataplane: Arc<dyn DataPlane>,
        endpoint_template: String,
        server_public_key: String,
        ip_pool: Ipv4Pool,
    ) -> Self {
        Self {
            runtime: Arc::new(RwLock::new(CoreRuntime {
                sessions: HashMap::new(),
                ip_pool,
            })),
            dataplane,
            endpoint_template,
            server_public_key,
        }
    }

    async fn desired_peers(&self) -> Vec<PeerSpec> {
        self.runtime
            .read()
            .await
            .sessions
            .values()
            .map(|s| s.peer.clone())
            .collect()
    }

    async fn active_peer_count(&self) -> i64 {
        self.runtime.read().await.sessions.len() as i64
    }

    fn endpoint_for_region(&self, region: &str) -> String {
        self.endpoint_template.replace("{region}", region)
    }
}

#[tonic::async_trait]
impl ControlPlane for CoreService {
    async fn connect_device(
        &self,
        request: Request<ConnectRequest>,
    ) -> Result<Response<ConnectResponse>, Status> {
        let req = request.into_inner();

        let customer_id = parse_uuid(&req.customer_id, "customer_id")?;
        let _device_id = parse_uuid(&req.device_id, "device_id")?;
        let node_id =
            parse_optional_uuid(&req.node_hint, "node_hint")?.unwrap_or_else(Uuid::new_v4);
        let allocated_at = Utc::now();

        let (peer, snapshot) = {
            let mut runtime = self.runtime.write().await;
            let assigned_ip = runtime
                .ip_pool
                .allocate_for(customer_id)
                .ok_or_else(|| Status::new(Code::ResourceExhausted, "ip_pool_exhausted"))?;

            let peer = PeerSpec {
                _session_key: req.session_key.clone(),
                device_public_key: req.device_public_key.clone(),
                assigned_ip: assigned_ip.clone(),
            };
            let snapshot = SessionSnapshot {
                session_key: req.session_key.clone(),
                region: req.region.clone(),
                connected_at: into_rfc3339(allocated_at),
            };
            (peer, snapshot)
        };

        if let Err(err) = self.dataplane.connect_peer(&peer).await {
            let mut runtime = self.runtime.write().await;
            runtime.ip_pool.release_for(customer_id);
            return Err(Status::new(
                Code::Internal,
                format!("dataplane_connect_failed:{err}"),
            ));
        }

        self.runtime.write().await.sessions.insert(
            customer_id,
            RuntimeSession {
                snapshot: snapshot.clone(),
                peer: peer.clone(),
            },
        );

        let config = WireGuardClientConfig {
            endpoint: self.endpoint_for_region(&req.region),
            server_public_key: self.server_public_key.clone(),
            preshared_key: None,
            assigned_ip: peer.assigned_ip.clone(),
            dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            persistent_keepalive_secs: 25,
            qr_payload: "wireguard://pending-client-config".to_string(),
        };

        Ok(Response::new(ConnectResponse {
            node_id: node_id.to_string(),
            allocated_at: into_rfc3339(allocated_at),
            config: Some(config_to_proto(config)),
        }))
    }

    async fn disconnect_device(
        &self,
        request: Request<DisconnectRequest>,
    ) -> Result<Response<DisconnectResponse>, Status> {
        let req = request.into_inner();
        let customer_id = parse_uuid(&req.customer_id, "customer_id")?;

        let session = self
            .runtime
            .read()
            .await
            .sessions
            .get(&customer_id)
            .cloned();
        if let Some(session) = session {
            if let Err(err) = self.dataplane.disconnect_peer(&session.peer).await {
                return Err(Status::new(
                    Code::Internal,
                    format!("dataplane_disconnect_failed:{err}"),
                ));
            }
            let mut runtime = self.runtime.write().await;
            runtime.sessions.remove(&customer_id);
            runtime.ip_pool.release_for(customer_id);
            return Ok(Response::new(DisconnectResponse {
                removed: true,
                completed_at: into_rfc3339(Utc::now()),
            }));
        }

        Ok(Response::new(DisconnectResponse {
            removed: false,
            completed_at: into_rfc3339(Utc::now()),
        }))
    }

    async fn get_session(
        &self,
        request: Request<GetSessionRequest>,
    ) -> Result<Response<GetSessionResponse>, Status> {
        let req = request.into_inner();
        let customer_id = parse_uuid(&req.customer_id, "customer_id")?;

        let session = self
            .runtime
            .read()
            .await
            .sessions
            .get(&customer_id)
            .map(|s| s.snapshot.clone());
        Ok(Response::new(GetSessionResponse {
            active: session.is_some(),
            session,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::async_trait;

    fn connect_request(customer_id: Uuid) -> ConnectRequest {
        ConnectRequest {
            request_id: Uuid::new_v4().to_string(),
            session_key: "sess_abc".to_string(),
            customer_id: customer_id.to_string(),
            device_id: Uuid::new_v4().to_string(),
            device_public_key: "device-public-key".to_string(),
            region: "us-central1".to_string(),
            node_hint: String::new(),
        }
    }

    fn test_service() -> CoreService {
        CoreService::new(
            Arc::new(NoopDataPlane),
            "{region}.gcp.vpn.example.net:51820".to_string(),
            "server-pub".to_string(),
        )
    }

    fn test_service_with_pool(first_host: u8, last_host: u8) -> CoreService {
        CoreService::new_with_pool(
            Arc::new(NoopDataPlane),
            "{region}.gcp.vpn.example.net:51820".to_string(),
            "server-pub".to_string(),
            Ipv4Pool::new([10, 90, 0], 24, first_host, last_host),
        )
    }

    struct FailingConnectDataPlane;
    #[async_trait]
    impl DataPlane for FailingConnectDataPlane {
        async fn bootstrap(&self) -> Result<(), String> {
            Ok(())
        }
        async fn connect_peer(&self, _peer: &PeerSpec) -> Result<(), String> {
            Err("connect boom".to_string())
        }
        async fn disconnect_peer(&self, _peer: &PeerSpec) -> Result<(), String> {
            Ok(())
        }
        async fn reconcile(&self, _desired_peers: &[PeerSpec]) -> Result<(), String> {
            Ok(())
        }
    }

    struct FailingDisconnectDataPlane;
    #[async_trait]
    impl DataPlane for FailingDisconnectDataPlane {
        async fn bootstrap(&self) -> Result<(), String> {
            Ok(())
        }
        async fn connect_peer(&self, _peer: &PeerSpec) -> Result<(), String> {
            Ok(())
        }
        async fn disconnect_peer(&self, _peer: &PeerSpec) -> Result<(), String> {
            Err("disconnect boom".to_string())
        }
        async fn reconcile(&self, _desired_peers: &[PeerSpec]) -> Result<(), String> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn connect_then_get_session_returns_active() {
        let service = test_service();
        let customer_id = Uuid::new_v4();

        let _ = service
            .connect_device(Request::new(connect_request(customer_id)))
            .await
            .expect("connect should succeed");

        let response = service
            .get_session(Request::new(GetSessionRequest {
                customer_id: customer_id.to_string(),
            }))
            .await
            .expect("session lookup should succeed")
            .into_inner();

        assert!(response.active);
        let session = response.session.expect("session should exist");
        assert_eq!(session.session_key, "sess_abc");
        assert_eq!(session.region, "us-central1");
    }

    #[tokio::test]
    async fn disconnect_removes_session() {
        let service = test_service();
        let customer_id = Uuid::new_v4();

        let _ = service
            .connect_device(Request::new(connect_request(customer_id)))
            .await
            .expect("connect should succeed");

        let disconnect = service
            .disconnect_device(Request::new(DisconnectRequest {
                request_id: Uuid::new_v4().to_string(),
                session_key: "sess_abc".to_string(),
                customer_id: customer_id.to_string(),
            }))
            .await
            .expect("disconnect should succeed")
            .into_inner();
        assert!(disconnect.removed);

        let post = service
            .get_session(Request::new(GetSessionRequest {
                customer_id: customer_id.to_string(),
            }))
            .await
            .expect("session lookup should succeed")
            .into_inner();
        assert!(!post.active);
        assert!(post.session.is_none());
    }

    #[tokio::test]
    async fn connect_assigns_client_ip_in_config() {
        let service = test_service();
        let customer_id = Uuid::new_v4();

        let response = service
            .connect_device(Request::new(connect_request(customer_id)))
            .await
            .expect("connect should succeed")
            .into_inner();

        let config = response.config.expect("config");
        assert_eq!(config.assigned_ip, "10.90.0.2/24");
    }

    #[tokio::test]
    async fn connect_rejects_invalid_customer_uuid() {
        let service = test_service();

        let err = service
            .connect_device(Request::new(ConnectRequest {
                request_id: Uuid::new_v4().to_string(),
                session_key: "sess_abc".to_string(),
                customer_id: "bad-id".to_string(),
                device_id: Uuid::new_v4().to_string(),
                device_public_key: "device-public-key".to_string(),
                region: "us-central1".to_string(),
                node_hint: String::new(),
            }))
            .await
            .expect_err("invalid customer id should fail");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), "customer_id");
    }

    #[tokio::test]
    async fn connect_returns_internal_when_dataplane_fails() {
        let service = CoreService::new(
            Arc::new(FailingConnectDataPlane),
            "{region}.gcp.vpn.example.net:51820".to_string(),
            "server-pub".to_string(),
        );

        let err = service
            .connect_device(Request::new(connect_request(Uuid::new_v4())))
            .await
            .expect_err("connect should fail");
        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(err.message().contains("dataplane_connect_failed"));
    }

    #[tokio::test]
    async fn disconnect_failure_keeps_session_active() {
        let service = CoreService::new(
            Arc::new(FailingDisconnectDataPlane),
            "{region}.gcp.vpn.example.net:51820".to_string(),
            "server-pub".to_string(),
        );
        let customer_id = Uuid::new_v4();
        let _ = service
            .connect_device(Request::new(connect_request(customer_id)))
            .await
            .expect("connect");

        let err = service
            .disconnect_device(Request::new(DisconnectRequest {
                request_id: Uuid::new_v4().to_string(),
                session_key: "sess_abc".to_string(),
                customer_id: customer_id.to_string(),
            }))
            .await
            .expect_err("disconnect should fail");
        assert_eq!(err.code(), tonic::Code::Internal);

        let still = service
            .get_session(Request::new(GetSessionRequest {
                customer_id: customer_id.to_string(),
            }))
            .await
            .expect("lookup")
            .into_inner();
        assert!(still.active);
    }

    #[tokio::test]
    async fn connect_returns_resource_exhausted_when_pool_empty() {
        let service = test_service_with_pool(2, 2);
        let first = service
            .connect_device(Request::new(connect_request(Uuid::new_v4())))
            .await;
        assert!(first.is_ok());

        let second = service
            .connect_device(Request::new(connect_request(Uuid::new_v4())))
            .await
            .expect_err("second should fail");
        assert_eq!(second.code(), tonic::Code::ResourceExhausted);
        assert_eq!(second.message(), "ip_pool_exhausted");
    }

    #[tokio::test]
    async fn get_session_rejects_invalid_customer_uuid() {
        let service = test_service();

        let err = service
            .get_session(Request::new(GetSessionRequest {
                customer_id: "bad-id".to_string(),
            }))
            .await
            .expect_err("invalid customer id should fail");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), "customer_id");
    }

    #[tokio::test]
    async fn disconnect_rejects_invalid_customer_uuid() {
        let service = test_service();

        let err = service
            .disconnect_device(Request::new(DisconnectRequest {
                request_id: Uuid::new_v4().to_string(),
                session_key: "sess_abc".to_string(),
                customer_id: "bad-id".to_string(),
            }))
            .await
            .expect_err("invalid customer id should fail");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), "customer_id");
    }
}
