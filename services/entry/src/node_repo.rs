use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct NodeRecord {
    pub id: Uuid,
    pub region: String,
    pub provider: String,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub healthy: bool,
    pub active_peer_count: i64,
}

#[derive(Debug, Clone)]
pub struct UpsertNodeInput {
    pub id: Uuid,
    pub region: String,
    pub provider: String,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub healthy: bool,
    pub active_peer_count: i64,
}

#[derive(Debug, Error)]
pub enum NodeRepoError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Clone)]
pub struct PostgresNodeRepository {
    pool: PgPool,
}

impl PostgresNodeRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn select_node(&self, region: &str) -> Result<Option<Uuid>, NodeRepoError> {
        sqlx::query_scalar::<_, Uuid>(
            "SELECT id
             FROM vpn_nodes
             WHERE region = $1
               AND healthy = true
             ORDER BY active_peer_count ASC, updated_at DESC
             LIMIT 1",
        )
        .bind(region)
        .fetch_optional(&self.pool)
        .await
        .map_err(NodeRepoError::from)
    }

    pub async fn list_nodes(&self) -> Result<Vec<NodeRecord>, NodeRepoError> {
        let rows = sqlx::query_as::<_, NodeDbRow>(
            "SELECT id, region, provider, endpoint_host, endpoint_port, healthy, active_peer_count
             FROM vpn_nodes
             ORDER BY region ASC, active_peer_count ASC, updated_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn upsert_node(&self, input: UpsertNodeInput) -> Result<NodeRecord, NodeRepoError> {
        let row = sqlx::query_as::<_, NodeDbRow>(
            "INSERT INTO vpn_nodes (
                 id,
                 region,
                 provider,
                 endpoint_host,
                 endpoint_port,
                 healthy,
                 active_peer_count,
                 created_at,
                 updated_at
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now())
             ON CONFLICT (id)
             DO UPDATE SET
                 region = EXCLUDED.region,
                 provider = EXCLUDED.provider,
                 endpoint_host = EXCLUDED.endpoint_host,
                 endpoint_port = EXCLUDED.endpoint_port,
                 healthy = EXCLUDED.healthy,
                 active_peer_count = EXCLUDED.active_peer_count,
                 updated_at = now()
             RETURNING id, region, provider, endpoint_host, endpoint_port, healthy, active_peer_count",
        )
        .bind(input.id)
        .bind(input.region)
        .bind(input.provider)
        .bind(input.endpoint_host)
        .bind(i32::from(input.endpoint_port))
        .bind(input.healthy)
        .bind(input.active_peer_count)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.into())
    }

    pub async fn update_node_health(
        &self,
        node_id: Uuid,
        healthy: bool,
        active_peer_count: i64,
    ) -> Result<Option<NodeRecord>, NodeRepoError> {
        let row = sqlx::query_as::<_, NodeDbRow>(
            "UPDATE vpn_nodes
             SET healthy = $2,
                 active_peer_count = $3,
                 updated_at = now()
             WHERE id = $1
             RETURNING id, region, provider, endpoint_host, endpoint_port, healthy, active_peer_count",
        )
        .bind(node_id)
        .bind(healthy)
        .bind(active_peer_count)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Into::into))
    }
}

#[derive(sqlx::FromRow)]
struct NodeDbRow {
    id: Uuid,
    region: String,
    provider: String,
    endpoint_host: String,
    endpoint_port: i32,
    healthy: bool,
    active_peer_count: i64,
}

impl From<NodeDbRow> for NodeRecord {
    fn from(value: NodeDbRow) -> Self {
        Self {
            id: value.id,
            region: value.region,
            provider: value.provider,
            endpoint_host: value.endpoint_host,
            endpoint_port: value.endpoint_port as u16,
            healthy: value.healthy,
            active_peer_count: value.active_peer_count,
        }
    }
}
