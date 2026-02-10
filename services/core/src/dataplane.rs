use std::process::Command;
use tonic::async_trait;

#[derive(Debug, Clone)]
pub struct PeerSpec {
    pub session_key: String,
    pub device_public_key: String,
    pub assigned_ip: String,
}

#[async_trait]
pub trait DataPlane: Send + Sync {
    async fn connect_peer(&self, peer: &PeerSpec) -> Result<(), String>;
    async fn disconnect_peer(&self, peer: &PeerSpec) -> Result<(), String>;
    async fn reconcile(&self, desired_peers: &[PeerSpec]) -> Result<(), String>;
}

#[derive(Default)]
pub struct NoopDataPlane;

#[async_trait]
impl DataPlane for NoopDataPlane {
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
    iface: String,
}

impl LinuxShellDataPlane {
    pub fn new(iface: impl Into<String>) -> Self {
        Self {
            iface: iface.into(),
        }
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
}

#[async_trait]
impl DataPlane for LinuxShellDataPlane {
    async fn connect_peer(&self, peer: &PeerSpec) -> Result<(), String> {
        // Sets desired AllowedIPs for this peer in kernel WireGuard interface.
        Self::run(&[
            "wg",
            "set",
            &self.iface,
            "peer",
            &peer.device_public_key,
            "allowed-ips",
            &peer.assigned_ip,
        ])
    }

    async fn disconnect_peer(&self, peer: &PeerSpec) -> Result<(), String> {
        Self::run(&[
            "wg",
            "set",
            &self.iface,
            "peer",
            &peer.device_public_key,
            "remove",
        ])
    }

    async fn reconcile(&self, _desired_peers: &[PeerSpec]) -> Result<(), String> {
        // Placeholder reconciliation hook. A future revision should diff live peers vs desired set.
        Ok(())
    }
}
