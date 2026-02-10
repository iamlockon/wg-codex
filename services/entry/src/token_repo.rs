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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use sqlx::postgres::PgPoolOptions;

    async fn setup_repo() -> Option<PostgresTokenRepository> {
        let url = std::env::var("TEST_DATABASE_URL").ok()?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .ok()?;
        let schema = format!("test_tok_{}", Uuid::new_v4().simple());
        let set_path = format!("SET search_path TO {schema}");
        let create_schema = format!("CREATE SCHEMA {schema}");

        sqlx::query(&create_schema).execute(&pool).await.ok()?;
        sqlx::query(&set_path).execute(&pool).await.ok()?;
        sqlx::raw_sql(include_str!(
            "../../../db/migrations/202602090001_initial_schema.sql"
        ))
        .execute(&pool)
        .await
        .ok()?;
        sqlx::raw_sql(include_str!(
            "../../../db/migrations/202602100002_revoked_tokens.sql"
        ))
        .execute(&pool)
        .await
        .ok()?;

        Some(PostgresTokenRepository::new(pool))
    }

    #[tokio::test]
    async fn revoke_and_check_respects_expiry() {
        let Some(repo) = setup_repo().await else {
            return;
        };
        let customer_id = Uuid::new_v4();
        sqlx::query("INSERT INTO customers (id) VALUES ($1)")
            .bind(customer_id)
            .execute(&repo.pool)
            .await
            .expect("insert customer");

        let jti = format!("jti-{}", Uuid::new_v4());
        repo.revoke_token(&jti, customer_id, Utc::now() + Duration::minutes(5))
            .await
            .expect("revoke");
        assert!(repo.is_revoked(&jti).await.expect("revoked"));

        repo.revoke_token(&jti, customer_id, Utc::now() - Duration::minutes(5))
            .await
            .expect("revoke expired");
        assert!(!repo.is_revoked(&jti).await.expect("not revoked"));
    }

    #[tokio::test]
    async fn purge_expired_removes_only_expired_rows() {
        let Some(repo) = setup_repo().await else {
            return;
        };
        let customer_id = Uuid::new_v4();
        sqlx::query("INSERT INTO customers (id) VALUES ($1)")
            .bind(customer_id)
            .execute(&repo.pool)
            .await
            .expect("insert customer");

        repo.revoke_token(
            &format!("expired-{}", Uuid::new_v4()),
            customer_id,
            Utc::now() - Duration::minutes(1),
        )
        .await
        .expect("expired");
        let active_jti = format!("active-{}", Uuid::new_v4());
        repo.revoke_token(&active_jti, customer_id, Utc::now() + Duration::minutes(10))
            .await
            .expect("active");

        let removed = repo.purge_expired().await.expect("purge");
        assert_eq!(removed, 1);
        assert!(repo.is_revoked(&active_jti).await.expect("active remains"));
    }
}
