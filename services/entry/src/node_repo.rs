use chrono::{DateTime, Utc};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct NodeRecord {
    pub id: Uuid,
    pub region: String,
    pub country_code: String,
    pub city_code: Option<String>,
    pub pool: String,
    pub provider: String,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub healthy: bool,
    pub active_peer_count: i64,
    pub capacity_peers: i64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct UpsertNodeInput {
    pub id: Uuid,
    pub region: String,
    pub country_code: String,
    pub city_code: Option<String>,
    pub pool: String,
    pub provider: String,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub healthy: bool,
    pub active_peer_count: i64,
    pub capacity_peers: i64,
}

#[derive(Debug, Clone, Default)]
pub struct NodeSelectionCriteria {
    pub region: Option<String>,
    pub country_code: Option<String>,
    pub city_code: Option<String>,
    pub pool: Option<String>,
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

    pub async fn select_node(
        &self,
        criteria: &NodeSelectionCriteria,
        freshness_seconds: i64,
    ) -> Result<Option<NodeRecord>, NodeRepoError> {
        let row = sqlx::query_as::<_, NodeDbRow>(
            "SELECT id, region, country_code, city_code, pool, provider, endpoint_host, endpoint_port, healthy, active_peer_count, capacity_peers, updated_at
             FROM vpn_nodes
             WHERE ($1::text IS NULL OR region = $1)
               AND ($2::text IS NULL OR country_code = $2)
               AND ($3::text IS NULL OR city_code = $3)
               AND ($4::text IS NULL OR pool = $4)
               AND healthy = true
               AND active_peer_count < capacity_peers
               AND updated_at > now() - ($5::bigint * interval '1 second')
             ORDER BY (active_peer_count::double precision / capacity_peers::double precision) ASC,
                      active_peer_count ASC,
                      updated_at DESC
             LIMIT 1",
        )
        .bind(criteria.region.as_deref())
        .bind(criteria.country_code.as_deref())
        .bind(criteria.city_code.as_deref())
        .bind(criteria.pool.as_deref())
        .bind(freshness_seconds)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Into::into))
    }

    pub async fn list_nodes(&self) -> Result<Vec<NodeRecord>, NodeRepoError> {
        let rows = sqlx::query_as::<_, NodeDbRow>(
            "SELECT id, region, country_code, city_code, pool, provider, endpoint_host, endpoint_port, healthy, active_peer_count, capacity_peers, updated_at
             FROM vpn_nodes
             ORDER BY country_code ASC, city_code ASC NULLS LAST, pool ASC, active_peer_count ASC, updated_at DESC",
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
                 country_code,
                 city_code,
                 pool,
                 provider,
                 endpoint_host,
                 endpoint_port,
                 healthy,
                 active_peer_count,
                 capacity_peers,
                 created_at,
                 updated_at
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now(), now())
             ON CONFLICT (id)
             DO UPDATE SET
                 region = EXCLUDED.region,
                 country_code = EXCLUDED.country_code,
                 city_code = EXCLUDED.city_code,
                 pool = EXCLUDED.pool,
                 provider = EXCLUDED.provider,
                 endpoint_host = EXCLUDED.endpoint_host,
                 endpoint_port = EXCLUDED.endpoint_port,
                 healthy = EXCLUDED.healthy,
                 active_peer_count = EXCLUDED.active_peer_count,
                 capacity_peers = EXCLUDED.capacity_peers,
                 updated_at = now()
             RETURNING id, region, country_code, city_code, pool, provider, endpoint_host, endpoint_port, healthy, active_peer_count, capacity_peers, updated_at",
        )
        .bind(input.id)
        .bind(input.region)
        .bind(input.country_code)
        .bind(input.city_code)
        .bind(input.pool)
        .bind(input.provider)
        .bind(input.endpoint_host)
        .bind(i32::from(input.endpoint_port))
        .bind(input.healthy)
        .bind(input.active_peer_count)
        .bind(input.capacity_peers)
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
             RETURNING id, region, country_code, city_code, pool, provider, endpoint_host, endpoint_port, healthy, active_peer_count, capacity_peers, updated_at",
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
    country_code: String,
    city_code: Option<String>,
    pool: String,
    provider: String,
    endpoint_host: String,
    endpoint_port: i32,
    healthy: bool,
    active_peer_count: i64,
    capacity_peers: i64,
    updated_at: DateTime<Utc>,
}

impl From<NodeDbRow> for NodeRecord {
    fn from(value: NodeDbRow) -> Self {
        Self {
            id: value.id,
            region: value.region,
            country_code: value.country_code,
            city_code: value.city_code,
            pool: value.pool,
            provider: value.provider,
            endpoint_host: value.endpoint_host,
            endpoint_port: value.endpoint_port as u16,
            healthy: value.healthy,
            active_peer_count: value.active_peer_count,
            capacity_peers: value.capacity_peers,
            updated_at: value.updated_at,
        }
    }
}
