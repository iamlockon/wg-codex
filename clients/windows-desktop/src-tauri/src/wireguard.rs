use crate::models::WireGuardClientConfig;
use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

pub trait TunnelController: Send + Sync {
    fn apply_and_up(&self, config: &WireGuardClientConfig) -> Result<()>;
    fn down(&self) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct NoopTunnelController {
    pub tunnel_name: String,
}

impl NoopTunnelController {
    pub fn new(tunnel_name: String) -> Self {
        Self { tunnel_name }
    }
}

impl TunnelController for NoopTunnelController {
    fn apply_and_up(&self, _config: &WireGuardClientConfig) -> Result<()> {
        Ok(())
    }

    fn down(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct WireGuardWindowsController {
    tunnel_name: String,
    wireguard_exe: PathBuf,
    config_dir: PathBuf,
}

impl WireGuardWindowsController {
    pub fn new(
        tunnel_name: String,
        wireguard_exe: Option<PathBuf>,
        config_dir: Option<PathBuf>,
    ) -> Self {
        Self {
            tunnel_name,
            wireguard_exe: wireguard_exe.unwrap_or_else(default_wireguard_exe_path),
            config_dir: config_dir
                .unwrap_or_else(|| std::env::temp_dir().join("wg-windows-client/config")),
        }
    }

    fn config_path(&self) -> PathBuf {
        self.config_dir.join(format!("{}.conf", self.tunnel_name))
    }

    fn render_config(&self, config: &WireGuardClientConfig) -> String {
        let mut lines = Vec::new();
        lines.push("[Interface]".to_string());
        lines.push(format!("Address = {}", config.assigned_ip));
        if !config.dns_servers.is_empty() {
            lines.push(format!("DNS = {}", config.dns_servers.join(", ")));
        }
        lines.push(String::new());
        lines.push("[Peer]".to_string());
        lines.push(format!("PublicKey = {}", config.server_public_key));
        if let Some(psk) = &config.preshared_key {
            lines.push(format!("PresharedKey = {psk}"));
        }
        lines.push(format!("Endpoint = {}", config.endpoint));
        lines.push("AllowedIPs = 0.0.0.0/0, ::/0".to_string());
        lines.push(format!(
            "PersistentKeepalive = {}",
            config.persistent_keepalive_secs
        ));
        lines.join("\n")
    }

    fn run_wireguard_command(&self, args: &[String]) -> Result<()> {
        let output = Command::new(&self.wireguard_exe)
            .args(args)
            .output()
            .with_context(|| {
                format!(
                    "failed to execute WireGuard command {:?} {:?}",
                    self.wireguard_exe, args
                )
            })?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "WireGuard command failed with status {}: {}",
            output
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".to_string()),
            stderr.trim()
        );
    }
}

fn default_wireguard_exe_path() -> PathBuf {
    // Standalone-default path: bundled executable in app-relative tools directory.
    // Expected package layout:
    //   <app dir>/wg-tools/wireguard.exe
    if let Ok(current_exe) = std::env::current_exe()
        && let Some(app_dir) = current_exe.parent()
    {
        return app_dir.join("wg-tools").join("wireguard.exe");
    }
    // Fallback for environments where current executable path cannot be resolved.
    PathBuf::from("wireguard.exe")
}

impl TunnelController for WireGuardWindowsController {
    fn apply_and_up(&self, config: &WireGuardClientConfig) -> Result<()> {
        fs::create_dir_all(&self.config_dir).context("create wireguard config dir failed")?;
        let path = self.config_path();
        fs::write(&path, self.render_config(config)).context("write wireguard config failed")?;
        self.run_wireguard_command(&[
            "/installtunnelservice".to_string(),
            path.display().to_string(),
        ])
    }

    fn down(&self) -> Result<()> {
        self.run_wireguard_command(&[
            "/uninstalltunnelservice".to_string(),
            self.tunnel_name.clone(),
        ])
    }
}

#[derive(Debug, Clone, Default)]
pub struct RecordingTunnelController {
    events: Arc<Mutex<Vec<String>>>,
}

impl RecordingTunnelController {
    pub fn events(&self) -> Vec<String> {
        self.events.lock().expect("lock").clone()
    }
}

impl TunnelController for RecordingTunnelController {
    fn apply_and_up(&self, config: &WireGuardClientConfig) -> Result<()> {
        self.events
            .lock()
            .expect("lock")
            .push(format!("up:{}", config.endpoint));
        Ok(())
    }

    fn down(&self) -> Result<()> {
        self.events.lock().expect("lock").push("down".to_string());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_config_contains_required_fields() {
        let controller = WireGuardWindowsController::new("wg-test".to_string(), None, None);
        let cfg = WireGuardClientConfig {
            endpoint: "node.example:51820".to_string(),
            server_public_key: "server-key".to_string(),
            preshared_key: Some("psk".to_string()),
            assigned_ip: "10.8.0.2/24".to_string(),
            dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            persistent_keepalive_secs: 25,
            qr_payload: "qr".to_string(),
        };
        let text = controller.render_config(&cfg);
        assert!(text.contains("[Interface]"));
        assert!(text.contains("Address = 10.8.0.2/24"));
        assert!(text.contains("DNS = 1.1.1.1, 8.8.8.8"));
        assert!(text.contains("[Peer]"));
        assert!(text.contains("PublicKey = server-key"));
        assert!(text.contains("PresharedKey = psk"));
        assert!(text.contains("Endpoint = node.example:51820"));
    }
}
