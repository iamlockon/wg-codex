use std::collections::HashMap;
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
use domain::WireGuardClientConfig;
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};
use tracing::info;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("core=info")
        .without_time()
        .init();

    let addr = "127.0.0.1:50051".parse()?;
    let service = CoreService::default();

    info!(%addr, "core gRPC service started");
    tonic::transport::Server::builder()
        .add_service(ControlPlaneServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}

#[derive(Default)]
struct CoreService {
    sessions: Arc<RwLock<HashMap<Uuid, SessionSnapshot>>>,
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

        let snapshot = SessionSnapshot {
            session_key: req.session_key,
            region: req.region.clone(),
            connected_at: into_rfc3339(allocated_at),
        };

        self.sessions.write().await.insert(customer_id, snapshot);

        let endpoint = format!("{}.gcp.vpn.example.net:51820", req.region);
        let config = WireGuardClientConfig {
            endpoint,
            server_public_key: "<server_public_key>".to_string(),
            preshared_key: None,
            assigned_ip: "10.90.0.2/32".to_string(),
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

        let removed = self.sessions.write().await.remove(&customer_id).is_some();
        Ok(Response::new(DisconnectResponse {
            removed,
            completed_at: into_rfc3339(Utc::now()),
        }))
    }

    async fn get_session(
        &self,
        request: Request<GetSessionRequest>,
    ) -> Result<Response<GetSessionResponse>, Status> {
        let req = request.into_inner();
        let customer_id = parse_uuid(&req.customer_id, "customer_id")?;

        let session = self.sessions.read().await.get(&customer_id).cloned();
        Ok(Response::new(GetSessionResponse {
            active: session.is_some(),
            session,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn connect_then_get_session_returns_active() {
        let service = CoreService::default();
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
        let service = CoreService::default();
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
    async fn connect_rejects_invalid_customer_uuid() {
        let service = CoreService::default();

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
    async fn get_session_rejects_invalid_customer_uuid() {
        let service = CoreService::default();

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
        let service = CoreService::default();

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
