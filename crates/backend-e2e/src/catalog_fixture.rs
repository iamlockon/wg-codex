use std::path::{Path, PathBuf};

use anyhow::Context;
use serde_json::json;
use uuid::Uuid;

pub fn write_node_catalog(dir: &Path, grpc_port: u16) -> anyhow::Result<PathBuf> {
    let path = dir.join("nodes.test.json");
    let document = json!({
        "version": 1,
        "nodes": [{
            "id": Uuid::new_v4(),
            "region": "us-west1",
            "country_code": "US",
            "city_code": "sea",
            "pool": "general",
            "provider": "local",
            "endpoint_host": "127.0.0.1",
            "endpoint_port": 51820,
            "grpc_host": "127.0.0.1",
            "grpc_port": grpc_port,
            "capacity_peers": 100,
            "enabled": true
        }]
    });

    std::fs::write(&path, serde_json::to_vec_pretty(&document)?)
        .with_context(|| format!("failed to write node catalog fixture to {}", path.display()))?;
    Ok(path)
}
