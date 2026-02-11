use futures_util::TryStreamExt;
use ipnet::IpNet;
use std::fs;
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

    async fn configure_interface_via_netlink(&self) -> Result<(), String> {
        let (connection, handle, _) =
            rtnetlink::new_connection().map_err(|err| format!("netlink init failed: {err}"))?;
        tokio::spawn(connection);

        let mut links = handle
            .link()
            .get()
            .match_name(self.cfg.iface.clone())
            .execute();
        let link = links
            .try_next()
            .await
            .map_err(|err| format!("netlink link lookup failed: {err}"))?
            .ok_or_else(|| format!("wireguard link {} not found", self.cfg.iface))?;
        let ifindex = link.header.index;

        let cidr: IpNet = self
            .cfg
            .interface_cidr
            .parse()
            .map_err(|err| format!("invalid interface cidr: {err}"))?;
        match cidr {
            IpNet::V4(v4) => {
                let _ = handle
                    .address()
                    .add(ifindex, v4.addr().into(), v4.prefix_len())
                    .execute()
                    .await;
            }
            IpNet::V6(v6) => {
                let _ = handle
                    .address()
                    .add(ifindex, v6.addr().into(), v6.prefix_len())
                    .execute()
                    .await;
            }
        }

        handle
            .link()
            .set(ifindex)
            .up()
            .execute()
            .await
            .map_err(|err| format!("netlink set link up failed: {err}"))?;
        Ok(())
    }

    fn enable_ipv4_forwarding(&self) -> Result<(), String> {
        fs::write("/proc/sys/net/ipv4/ip_forward", b"1\n")
            .map_err(|err| format!("set ip_forward failed: {err}"))
    }

    fn ensure_nat_rule(&self) -> Result<(), String> {
        // Ensure table and chain exist (idempotent by allowing failure).
        Self::run_allow_failure(&["nft", "add", "table", "ip", "nat"]);
        Self::run_allow_failure(&[
            "nft",
            "add",
            "chain",
            "ip",
            "nat",
            "postrouting",
            "{",
            "type",
            "nat",
            "hook",
            "postrouting",
            "priority",
            "100",
            ";",
            "}",
        ]);

        let rule = format!("oifname \\\"{}\\\" masquerade", self.cfg.egress_iface);
        let check = Self::run(&["nft", "list", "chain", "ip", "nat", "postrouting"]);
        if check.is_ok() {
            let output = Command::new("nft")
                .args(["list", "chain", "ip", "nat", "postrouting"])
                .output()
                .map_err(|err| format!("nft list failed: {err}"))?;
            let text = String::from_utf8_lossy(&output.stdout);
            if text.contains(&rule) {
                return Ok(());
            }
        }

        Self::run(&[
            "nft",
            "add",
            "rule",
            "ip",
            "nat",
            "postrouting",
            "oifname",
            &self.cfg.egress_iface,
            "masquerade",
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

        let uapi = self.uapi.clone();
        let key_path = self.cfg.private_key_path.clone();
        let listen_port = self.cfg.listen_port;
        task::spawn_blocking(move || uapi.configure_device(&key_path, listen_port))
            .await
            .map_err(|err| format!("uapi bootstrap join failure: {err}"))??;

        self.configure_interface_via_netlink().await?;
        self.enable_ipv4_forwarding()?;
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
        let uapi = self.uapi.clone();
        let desired = _desired_peers.to_vec();
        task::spawn_blocking(move || {
            let live = uapi.list_peer_public_keys()?;
            let desired_keys: std::collections::HashSet<String> = desired
                .iter()
                .map(|p| p.device_public_key.clone())
                .collect();

            // Re-apply desired peer state (idempotent) to repair drift.
            for peer in &desired {
                uapi.set_peer(
                    &peer.device_public_key,
                    Some(&peer.assigned_ip),
                    Some(25),
                    false,
                )?;
            }

            // Remove peers not present in desired state.
            for public_key in live {
                if !desired_keys.contains(&public_key) {
                    uapi.set_peer(&public_key, None, None, true)?;
                }
            }
            Ok(())
        })
        .await
        .map_err(|err| format!("uapi reconcile join failure: {err}"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_op_dataplane_reconcile_accepts_any_desired_state() {
        let dp = NoopDataPlane;
        let desired = vec![PeerSpec {
            _session_key: "sess".to_string(),
            device_public_key: "pub".to_string(),
            assigned_ip: "10.90.0.2/24".to_string(),
        }];
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async move {
            dp.reconcile(&desired).await.expect("reconcile");
        });
    }
}
