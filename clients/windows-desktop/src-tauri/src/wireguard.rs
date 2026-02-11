use crate::models::WireGuardClientConfig;
use anyhow::Result;
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
