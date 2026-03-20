use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, anyhow};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use tokio::time::sleep;

use crate::catalog_fixture::write_node_catalog;
use crate::oauth_stub::OAuthStubServer;

pub struct BackendStack {
    _tempdir: tempfile::TempDir,
    _oauth_stub: OAuthStubServer,
    core: Child,
    entry: Child,
    entry_base_url: String,
}

impl BackendStack {
    pub async fn start() -> anyhow::Result<Self> {
        build_backend_binaries().await?;

        let tempdir = tempfile::tempdir().context("failed to create temp dir for backend stack")?;
        let core_port = allocate_port().await?;
        let entry_port = allocate_port().await?;
        let catalog_path = write_node_catalog(tempdir.path(), core_port)?;
        let oauth_stub = OAuthStubServer::start("test-client-id".to_string()).await?;

        let core_binary = workspace_binary_path("core");
        let entry_binary = workspace_binary_path("entry");

        let core = Command::new(&core_binary)
            .env("CORE_BIND_ADDR", format!("127.0.0.1:{core_port}"))
            .env("CORE_DATAPLANE_NOOP", "true")
            .env("CORE_REQUIRE_TLS", "false")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("failed to spawn {}", core_binary.display()))?;

        let mut entry_command = Command::new(&entry_binary);
        entry_command
            .env("ENTRY_BIND_ADDR", format!("127.0.0.1:{entry_port}"))
            .env("CORE_GRPC_URL", format!("http://127.0.0.1:{core_port}"))
            .env("GOOGLE_OIDC_CLIENT_ID", "test-client-id")
            .env("GOOGLE_OIDC_CLIENT_SECRET", "test-client-secret")
            .env("GOOGLE_OIDC_REDIRECT_URI", "http://127.0.0.1/callback")
            .env("GOOGLE_OIDC_TOKEN_URL", format!("{}/token", oauth_stub.base_url()))
            .env("GOOGLE_OIDC_JWKS_URL", format!("{}/jwks", oauth_stub.base_url()))
            .env("APP_JWT_SIGNING_KEYS", "v1:test-signing-key")
            .env("APP_JWT_ACTIVE_KID", "v1")
            .env("ADMIN_API_TOKEN", "admin-secret")
            .env("APP_ALLOW_LEGACY_CUSTOMER_HEADER", "false")
            .env("APP_NODE_CATALOG_FILE", &catalog_path)
            .env("APP_NODE_CATALOG_REFRESH_SECS", "3600")
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        if let Ok(database_url) = std::env::var("TEST_DATABASE_URL") {
            entry_command.env("DATABASE_URL", database_url);
        }

        let entry = entry_command
            .spawn()
            .with_context(|| format!("failed to spawn {}", entry_binary.display()))?;

        let mut stack = Self {
            _tempdir: tempdir,
            _oauth_stub: oauth_stub,
            core,
            entry,
            entry_base_url: format!("http://127.0.0.1:{entry_port}"),
        };

        stack.wait_for_entry_ready().await?;
        Ok(stack)
    }

    pub fn entry_base_url(&self) -> &str {
        &self.entry_base_url
    }

    async fn wait_for_entry_ready(&mut self) -> anyhow::Result<()> {
        let client = reqwest::Client::new();
        for _ in 0..50 {
            ensure_running(&mut self.core, "core")?;
            ensure_running(&mut self.entry, "entry")?;

            if let Ok(response) = client
                .get(format!("{}/healthz", self.entry_base_url))
                .send()
                .await
            {
                if response.status().is_success() {
                    return Ok(());
                }
            }

            sleep(Duration::from_millis(200)).await;
        }

        Err(anyhow!("entry healthz did not become ready in time"))
    }
}

impl Drop for BackendStack {
    fn drop(&mut self) {
        let _ = self.entry.start_kill();
        let _ = self.core.start_kill();
    }
}

fn ensure_running(child: &mut Child, name: &str) -> anyhow::Result<()> {
    match child.try_wait().context("failed to poll child process")? {
        Some(status) => Err(anyhow!("{name} exited early with status {status}")),
        None => Ok(()),
    }
}

async fn allocate_port() -> anyhow::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("failed to allocate ephemeral port")?;
    Ok(listener.local_addr()?.port())
}

async fn build_backend_binaries() -> anyhow::Result<()> {
    let status = Command::new("cargo")
        .args(["build", "-p", "entry", "-p", "core"])
        .current_dir(workspace_root())
        .status()
        .await
        .context("failed to invoke cargo build for entry/core")?;
    if !status.success() {
        return Err(anyhow!("cargo build -p entry -p core failed with status {status}"));
    }
    Ok(())
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn workspace_binary_path(name: &str) -> PathBuf {
    workspace_root().join("target").join("debug").join(name)
}
