use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, anyhow};
use chrono::{DateTime, Utc};
use control_plane::ControlPlaneClient;
use control_plane::proto::GetNodeStatusRequest;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tonic::transport::Channel;
use tracing::warn;
use uuid::Uuid;

use crate::{build_core_client, core_node_grpc_port};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCatalogRecord {
    pub id: Uuid,
    pub region: String,
    pub country_code: String,
    pub city_code: Option<String>,
    pub pool: String,
    pub provider: String,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub grpc_host: Option<String>,
    pub grpc_port: Option<u16>,
    pub capacity_peers: i64,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCatalogDocument {
    pub version: u32,
    pub nodes: Vec<NodeCatalogRecord>,
}

#[derive(Debug, Clone)]
pub struct NodeRuntimeStatus {
    pub healthy: bool,
    pub active_peer_count: i64,
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ResolvedNodeRecord {
    pub id: Uuid,
    pub region: String,
    pub country_code: String,
    pub city_code: Option<String>,
    pub pool: String,
    pub provider: String,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    #[allow(dead_code)]
    pub grpc_host: String,
    #[allow(dead_code)]
    pub grpc_port: u16,
    pub healthy: bool,
    pub active_peer_count: i64,
    pub capacity_peers: i64,
    pub updated_at: DateTime<Utc>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Default)]
pub struct NodeSelectionCriteria {
    pub region: Option<String>,
    pub country_code: Option<String>,
    pub city_code: Option<String>,
    pub pool: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum NodeCatalogError {
    #[error("node catalog unavailable")]
    Unavailable,
    #[error("node catalog load failed: {0}")]
    Load(String),
}

#[derive(Clone)]
pub struct BlobNodeCatalog {
    source: CatalogSource,
    document: Arc<RwLock<Option<NodeCatalogDocument>>>,
    health: Arc<RwLock<HashMap<Uuid, NodeRuntimeStatus>>>,
}

#[derive(Clone)]
enum CatalogSource {
    File { path: String },
    Gcs { bucket: String, object: String },
}

impl BlobNodeCatalog {
    pub fn from_env() -> Option<Self> {
        if let Ok(path) = std::env::var("APP_NODE_CATALOG_FILE") {
            let path = path.trim().to_string();
            if !path.is_empty() {
                return Some(Self::new(CatalogSource::File { path }));
            }
        }

        let bucket = std::env::var("APP_NODE_CATALOG_GCS_BUCKET").ok()?;
        let object = std::env::var("APP_NODE_CATALOG_GCS_OBJECT").ok()?;
        let bucket = bucket.trim().to_string();
        let object = object.trim().to_string();
        if bucket.is_empty() || object.is_empty() {
            return None;
        }
        Some(Self::new(CatalogSource::Gcs { bucket, object }))
    }

    pub fn from_file_path(path: impl Into<String>) -> Self {
        Self::new(CatalogSource::File { path: path.into() })
    }

    fn new(source: CatalogSource) -> Self {
        Self {
            source,
            document: Arc::new(RwLock::new(None)),
            health: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn refresh_catalog(&self, http: &reqwest::Client) -> Result<(), NodeCatalogError> {
        let document = match &self.source {
            CatalogSource::File { path } => {
                load_from_file(path).map_err(|err| NodeCatalogError::Load(err.to_string()))?
            }
            CatalogSource::Gcs { bucket, object } => load_from_gcs(http, bucket, object)
                .await
                .map_err(|err| NodeCatalogError::Load(err.to_string()))?,
        };
        let mut slot = self.document.write().await;
        *slot = Some(document);
        Ok(())
    }

    pub async fn list_nodes(&self) -> Result<Vec<ResolvedNodeRecord>, NodeCatalogError> {
        let document = self
            .document
            .read()
            .await
            .clone()
            .ok_or(NodeCatalogError::Unavailable)?;
        let health = self.health.read().await;
        Ok(document
            .nodes
            .into_iter()
            .map(|node| {
                let node_id = node.id;
                merge_node_record(node, health.get(&node_id).cloned())
            })
            .collect())
    }

    pub async fn get_node(
        &self,
        node_id: Uuid,
    ) -> Result<Option<ResolvedNodeRecord>, NodeCatalogError> {
        let document = self
            .document
            .read()
            .await
            .clone()
            .ok_or(NodeCatalogError::Unavailable)?;
        let health = self.health.read().await;
        Ok(document
            .nodes
            .into_iter()
            .find(|node| node.id == node_id)
            .map(|node| merge_node_record(node, health.get(&node_id).cloned())))
    }

    pub async fn select_node(
        &self,
        criteria: &NodeSelectionCriteria,
        freshness_seconds: i64,
    ) -> Result<Option<ResolvedNodeRecord>, NodeCatalogError> {
        let nodes = self.list_nodes().await?;
        let now = Utc::now();
        Ok(nodes
            .into_iter()
            .filter(|n| {
                n.enabled
                    && criteria
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
            .min_by(|a, b| {
                let util_a = a.active_peer_count as f64 / a.capacity_peers as f64;
                let util_b = b.active_peer_count as f64 / b.capacity_peers as f64;
                util_a
                    .partial_cmp(&util_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.active_peer_count.cmp(&b.active_peer_count))
                    .then_with(|| b.updated_at.cmp(&a.updated_at))
            }))
    }

    pub async fn refresh_health(&self, require_tls: bool) -> Result<(), NodeCatalogError> {
        let document = self
            .document
            .read()
            .await
            .clone()
            .ok_or(NodeCatalogError::Unavailable)?;
        let mut new_health = HashMap::new();
        for node in document.nodes.into_iter().filter(|n| n.enabled) {
            let target = core_target_for_catalog_node(&node, require_tls);
            let result = fetch_node_status(&target).await;
            let checked_at = Utc::now();
            match result {
                Ok((healthy, active_peer_count)) => {
                    new_health.insert(
                        node.id,
                        NodeRuntimeStatus {
                            healthy,
                            active_peer_count,
                            checked_at,
                        },
                    );
                }
                Err(err) => {
                    warn!(node_id=%node.id, target=%target, error=%err, "failed to refresh core node status");
                    new_health.insert(
                        node.id,
                        NodeRuntimeStatus {
                            healthy: false,
                            active_peer_count: i64::MAX,
                            checked_at,
                        },
                    );
                }
            }
        }
        let mut slot = self.health.write().await;
        *slot = new_health;
        Ok(())
    }

    #[cfg(test)]
    pub async fn set_health_snapshot(&self, snapshot: HashMap<Uuid, NodeRuntimeStatus>) {
        let mut slot = self.health.write().await;
        *slot = snapshot;
    }
}

fn default_true() -> bool {
    true
}

fn merge_node_record(
    node: NodeCatalogRecord,
    health: Option<NodeRuntimeStatus>,
) -> ResolvedNodeRecord {
    let grpc_host = node
        .grpc_host
        .clone()
        .unwrap_or_else(|| node.endpoint_host.clone());
    let grpc_port = node.grpc_port.unwrap_or_else(core_node_grpc_port);
    let checked_at = health
        .as_ref()
        .map(|s| s.checked_at)
        .unwrap_or_else(Utc::now);
    ResolvedNodeRecord {
        id: node.id,
        region: node.region,
        country_code: node.country_code,
        city_code: node.city_code,
        pool: node.pool,
        provider: node.provider,
        endpoint_host: node.endpoint_host,
        endpoint_port: node.endpoint_port,
        grpc_host,
        grpc_port,
        healthy: health.as_ref().map(|s| s.healthy).unwrap_or(false),
        active_peer_count: health
            .as_ref()
            .map(|s| s.active_peer_count)
            .unwrap_or(i64::MAX),
        capacity_peers: node.capacity_peers,
        updated_at: checked_at,
        enabled: node.enabled,
    }
}

fn load_from_file(path: &str) -> anyhow::Result<NodeCatalogDocument> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read node catalog file: {path}"))?;
    parse_document(&contents)
}

async fn load_from_gcs(
    http: &reqwest::Client,
    bucket: &str,
    object: &str,
) -> anyhow::Result<NodeCatalogDocument> {
    let object = object.trim_start_matches('/');
    let url = format!("https://storage.googleapis.com/{bucket}/{object}");
    let response = http
        .get(&url)
        .send()
        .await
        .with_context(|| format!("failed to fetch node catalog from gcs url: {url}"))?;
    if !response.status().is_success() {
        return Err(anyhow!(
            "gcs node catalog request failed with status {}",
            response.status()
        ));
    }
    let contents = response
        .text()
        .await
        .context("failed to read gcs node catalog response body")?;
    parse_document(&contents)
}

fn parse_document(contents: &str) -> anyhow::Result<NodeCatalogDocument> {
    let document: NodeCatalogDocument =
        serde_json::from_str(contents).context("failed to parse node catalog json")?;
    if document.version == 0 {
        return Err(anyhow!("node catalog version must be >= 1"));
    }
    if document.nodes.is_empty() {
        return Err(anyhow!("node catalog must contain at least one node"));
    }
    for node in &document.nodes {
        validate_node(node)?;
    }
    Ok(document)
}

fn validate_node(node: &NodeCatalogRecord) -> anyhow::Result<()> {
    if node.region.trim().is_empty() {
        return Err(anyhow!("node {} missing region", node.id));
    }
    if node.country_code.trim().len() != 2 {
        return Err(anyhow!("node {} invalid country_code", node.id));
    }
    if node.endpoint_host.trim().is_empty() {
        return Err(anyhow!("node {} missing endpoint_host", node.id));
    }
    if node.capacity_peers <= 0 {
        return Err(anyhow!("node {} invalid capacity_peers", node.id));
    }
    Ok(())
}

fn core_target_for_catalog_node(node: &NodeCatalogRecord, require_tls: bool) -> String {
    let scheme = if require_tls { "https" } else { "http" };
    let host = node.grpc_host.as_deref().unwrap_or(&node.endpoint_host);
    let port = node.grpc_port.unwrap_or_else(core_node_grpc_port);
    format!("{scheme}://{host}:{port}")
}

async fn fetch_node_status(target: &str) -> anyhow::Result<(bool, i64)> {
    let mut client: ControlPlaneClient<Channel> = build_core_client(target).await?;
    let response = client
        .get_node_status(GetNodeStatusRequest {
            request_id: Uuid::new_v4().to_string(),
        })
        .await
        .map_err(|err| anyhow!("GetNodeStatus failed: {err}"))?
        .into_inner();
    Ok((response.healthy, response.active_peer_count))
}

pub fn default_dev_catalog_path() -> &'static Path {
    Path::new("deploy/catalog/nodes.dev.json")
}
