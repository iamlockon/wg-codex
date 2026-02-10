use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

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
}
