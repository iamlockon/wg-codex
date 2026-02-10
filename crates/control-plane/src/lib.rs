use chrono::{DateTime, Utc};
use domain::WireGuardClientConfig;
use std::str::FromStr;
use tonic::{Code, Status};
use uuid::Uuid;

pub mod proto {
    tonic::include_proto!("vpn.control.v1");
}

pub use proto::control_plane_client::ControlPlaneClient;
pub use proto::control_plane_server::{ControlPlane, ControlPlaneServer};

pub fn parse_uuid(raw: &str, field: &'static str) -> Result<Uuid, Status> {
    Uuid::parse_str(raw).map_err(|_| Status::new(Code::InvalidArgument, field))
}

pub fn parse_rfc3339(raw: &str, field: &'static str) -> Result<DateTime<Utc>, Status> {
    chrono::DateTime::parse_from_rfc3339(raw)
        .map(|v| v.with_timezone(&Utc))
        .map_err(|_| Status::new(Code::InvalidArgument, field))
}

pub fn into_rfc3339(ts: DateTime<Utc>) -> String {
    ts.to_rfc3339()
}

pub fn config_from_proto(cfg: proto::WireGuardClientConfig) -> WireGuardClientConfig {
    WireGuardClientConfig {
        endpoint: cfg.endpoint,
        server_public_key: cfg.server_public_key,
        preshared_key: if cfg.preshared_key.is_empty() {
            None
        } else {
            Some(cfg.preshared_key)
        },
        assigned_ip: cfg.assigned_ip,
        dns_servers: cfg.dns_servers,
        persistent_keepalive_secs: cfg.persistent_keepalive_secs as u16,
        qr_payload: cfg.qr_payload,
    }
}

pub fn config_to_proto(cfg: WireGuardClientConfig) -> proto::WireGuardClientConfig {
    proto::WireGuardClientConfig {
        endpoint: cfg.endpoint,
        server_public_key: cfg.server_public_key,
        preshared_key: cfg.preshared_key.unwrap_or_default(),
        assigned_ip: cfg.assigned_ip,
        dns_servers: cfg.dns_servers,
        persistent_keepalive_secs: cfg.persistent_keepalive_secs as u32,
        qr_payload: cfg.qr_payload,
    }
}

pub fn maybe_uuid_to_string(node_hint: Option<Uuid>) -> String {
    node_hint.map(|v| v.to_string()).unwrap_or_default()
}

pub fn parse_optional_uuid(raw: &str, field: &'static str) -> Result<Option<Uuid>, Status> {
    if raw.is_empty() {
        return Ok(None);
    }

    Uuid::from_str(raw)
        .map(Some)
        .map_err(|_| Status::new(Code::InvalidArgument, field))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uuid_accepts_valid_uuid() {
        let id = Uuid::new_v4();
        let parsed = parse_uuid(&id.to_string(), "id").expect("uuid should parse");
        assert_eq!(parsed, id);
    }

    #[test]
    fn parse_uuid_rejects_invalid_uuid() {
        let err = parse_uuid("bad-uuid", "id").expect_err("invalid uuid should fail");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), "id");
    }

    #[test]
    fn parse_optional_uuid_handles_empty_string() {
        let parsed = parse_optional_uuid("", "node_hint").expect("empty should be none");
        assert!(parsed.is_none());
    }

    #[test]
    fn rfc3339_round_trip() {
        let now = Utc::now();
        let encoded = into_rfc3339(now);
        let decoded = parse_rfc3339(&encoded, "ts").expect("timestamp should parse");
        assert_eq!(decoded, now);
    }

    #[test]
    fn parse_rfc3339_rejects_invalid_value() {
        let err = parse_rfc3339("not-a-time", "ts").expect_err("invalid timestamp should fail");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), "ts");
    }

    #[test]
    fn wireguard_config_proto_round_trip() {
        let cfg = WireGuardClientConfig {
            endpoint: "us-central1.vpn.example.net:51820".to_string(),
            server_public_key: "pub".to_string(),
            preshared_key: Some("psk".to_string()),
            assigned_ip: "10.90.0.2/32".to_string(),
            dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            persistent_keepalive_secs: 25,
            qr_payload: "wireguard://q".to_string(),
        };

        let proto = config_to_proto(cfg.clone());
        let decoded = config_from_proto(proto);
        assert_eq!(decoded.endpoint, cfg.endpoint);
        assert_eq!(decoded.server_public_key, cfg.server_public_key);
        assert_eq!(decoded.preshared_key, cfg.preshared_key);
        assert_eq!(decoded.assigned_ip, cfg.assigned_ip);
        assert_eq!(decoded.dns_servers, cfg.dns_servers);
        assert_eq!(
            decoded.persistent_keepalive_secs,
            cfg.persistent_keepalive_secs
        );
        assert_eq!(decoded.qr_payload, cfg.qr_payload);
    }
}
