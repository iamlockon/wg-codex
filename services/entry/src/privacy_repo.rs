use sqlx::PgPool;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PrivacyRepoError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Clone)]
pub struct PostgresPrivacyRepository {
    pool: PgPool,
}

impl PostgresPrivacyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn purge_expired_metadata(
        &self,
        session_retention_days: i64,
        audit_retention_days: i64,
    ) -> Result<(u64, u64), PrivacyRepoError> {
        let removed_sessions = sqlx::query(
            "DELETE FROM sessions
             WHERE state = 'terminated'
               AND terminated_at IS NOT NULL
               AND terminated_at < now() - ($1::bigint * interval '1 day')",
        )
        .bind(session_retention_days)
        .execute(&self.pool)
        .await?
        .rows_affected();

        let removed_audits = sqlx::query(
            "DELETE FROM audit_events
             WHERE created_at < now() - ($1::bigint * interval '1 day')",
        )
        .bind(audit_retention_days)
        .execute(&self.pool)
        .await?
        .rows_affected();

        Ok((removed_sessions, removed_audits))
    }
}
