use std::process::Command;
use tokio::task;
use tonic::async_trait;

use crate::wg_uapi::WireGuardUapiClient;

#[derive(Debug, Clone)]
pub struct PeerSpec {
    pub _session_key: String,
    pub device_public_key: String,
    pub assigned_ip: String,
}

#[derive(Debug, Clone)]
pub struct LinuxDataPlaneConfig {
    pub iface: String,
    pub interface_cidr: String,
    pub private_key_path: String,
    pub listen_port: u16,
    pub egress_iface: String,
}

#[async_trait]
pub trait DataPlane: Send + Sync {
    async fn bootstrap(&self) -> Result<(), String>;
    async fn connect_peer(&self, peer: &PeerSpec) -> Result<(), String>;
    async fn disconnect_peer(&self, peer: &PeerSpec) -> Result<(), String>;
    async fn reconcile(&self, desired_peers: &[PeerSpec]) -> Result<(), String>;
}

#[derive(Default)]
pub struct NoopDataPlane;

#[async_trait]
impl DataPlane for NoopDataPlane {
    async fn bootstrap(&self) -> Result<(), String> {
        Ok(())
    }

    async fn connect_peer(&self, _peer: &PeerSpec) -> Result<(), String> {
        Ok(())
    }

    async fn disconnect_peer(&self, _peer: &PeerSpec) -> Result<(), String> {
        Ok(())
    }

    async fn reconcile(&self, _desired_peers: &[PeerSpec]) -> Result<(), String> {
        Ok(())
    }
}

pub struct LinuxShellDataPlane {
    cfg: LinuxDataPlaneConfig,
    uapi: WireGuardUapiClient,
}

impl LinuxShellDataPlane {
    pub fn new(cfg: LinuxDataPlaneConfig) -> Self {
        let uapi = WireGuardUapiClient::new(&cfg.iface);
        Self { cfg, uapi }
    }

    fn run(args: &[&str]) -> Result<(), String> {
        let (program, rest) = args
            .split_first()
            .ok_or_else(|| "empty command".to_string())?;
        let status = Command::new(program)
            .args(rest)
            .status()
            .map_err(|err| format!("{} exec failed: {err}", program))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{} failed with status {status}", program))
        }
    }

    fn run_allow_failure(args: &[&str]) {
        let _ = Self::run(args);
    }

    fn ensure_nat_rule(&self) -> Result<(), String> {
        let check = Self::run(&[
            "iptables",
            "-t",
            "nat",
            "-C",
            "POSTROUTING",
            "-o",
            &self.cfg.egress_iface,
            "-j",
            "MASQUERADE",
        ]);

        if check.is_ok() {
            return Ok(());
        }

        Self::run(&[
            "iptables",
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-o",
            &self.cfg.egress_iface,
            "-j",
            "MASQUERADE",
        ])
    }
}

#[async_trait]
impl DataPlane for LinuxShellDataPlane {
    async fn bootstrap(&self) -> Result<(), String> {
        // Create interface if absent; ignore error when it already exists.
        Self::run_allow_failure(&[
            "ip",
            "link",
            "add",
            "dev",
            &self.cfg.iface,
            "type",
            "wireguard",
        ]);

        // Configure interface address if absent.
        Self::run_allow_failure(&[
            "ip",
            "address",
            "add",
            &self.cfg.interface_cidr,
            "dev",
            &self.cfg.iface,
        ]);

        Self::run(&[
            "wg",
            "set",
            &self.cfg.iface,
            "listen-port",
            &self.cfg.listen_port.to_string(),
            "private-key",
            &self.cfg.private_key_path,
        ])?;

        Self::run(&["ip", "link", "set", "up", "dev", &self.cfg.iface])?;
        Self::run(&["sysctl", "-w", "net.ipv4.ip_forward=1"])?;
        self.ensure_nat_rule()?;
        Ok(())
    }

    async fn connect_peer(&self, peer: &PeerSpec) -> Result<(), String> {
        let uapi = self.uapi.clone();
        let public_key = peer.device_public_key.clone();
        let allowed_ip = peer.assigned_ip.clone();
        task::spawn_blocking(move || uapi.set_peer(&public_key, Some(&allowed_ip), Some(25), false))
            .await
            .map_err(|err| format!("uapi connect join failure: {err}"))?
    }

    async fn disconnect_peer(&self, peer: &PeerSpec) -> Result<(), String> {
        let uapi = self.uapi.clone();
        let public_key = peer.device_public_key.clone();
        task::spawn_blocking(move || uapi.set_peer(&public_key, None, None, true))
            .await
            .map_err(|err| format!("uapi disconnect join failure: {err}"))?
    }

    async fn reconcile(&self, _desired_peers: &[PeerSpec]) -> Result<(), String> {
        // Placeholder reconciliation hook. A future revision should diff live peers vs desired set.
        Ok(())
    }
}
