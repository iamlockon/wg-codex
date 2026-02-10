use chrono::{DateTime, Utc};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum TokenRepoError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Clone)]
pub struct PostgresTokenRepository {
    pool: PgPool,
}

impl PostgresTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn revoke_token(
        &self,
        jti: &str,
        customer_id: Uuid,
        expires_at: DateTime<Utc>,
    ) -> Result<(), TokenRepoError> {
        sqlx::query(
            "INSERT INTO revoked_tokens (jti, customer_id, expires_at)
             VALUES ($1, $2, $3)
             ON CONFLICT (jti)
             DO UPDATE SET
                 customer_id = EXCLUDED.customer_id,
                 expires_at = EXCLUDED.expires_at",
        )
        .bind(jti)
        .bind(customer_id)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn is_revoked(&self, jti: &str) -> Result<bool, TokenRepoError> {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
                SELECT 1
                FROM revoked_tokens
                WHERE jti = $1
                  AND expires_at > now()
            )",
        )
        .bind(jti)
        .fetch_one(&self.pool)
        .await?;
        Ok(exists)
    }

    pub async fn purge_expired(&self) -> Result<u64, TokenRepoError> {
        let result = sqlx::query("DELETE FROM revoked_tokens WHERE expires_at <= now()")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}
