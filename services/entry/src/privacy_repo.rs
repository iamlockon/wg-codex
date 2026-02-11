use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum PrivacyRepoError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Clone)]
pub struct PostgresPrivacyRepository {
    pool: PgPool,
}

#[derive(Debug, Clone)]
pub struct AuditEventRecord {
    pub id: Uuid,
    pub customer_id: Option<Uuid>,
    pub actor_type: String,
    pub actor_id: String,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow)]
struct AuditEventDbRow {
    id: Uuid,
    customer_id: Option<Uuid>,
    actor_type: String,
    actor_id: String,
    event_type: String,
    payload: serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<AuditEventDbRow> for AuditEventRecord {
    fn from(value: AuditEventDbRow) -> Self {
        Self {
            id: value.id,
            customer_id: value.customer_id,
            actor_type: value.actor_type,
            actor_id: value.actor_id,
            event_type: value.event_type,
            payload: value.payload,
            created_at: value.created_at,
        }
    }
}

impl PostgresPrivacyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn insert_audit_event(
        &self,
        customer_id: Option<Uuid>,
        actor_type: &str,
        actor_id: &str,
        event_type: &str,
        payload: serde_json::Value,
    ) -> Result<(), PrivacyRepoError> {
        sqlx::query(
            "INSERT INTO audit_events (customer_id, actor_type, actor_id, event_type, payload)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(customer_id)
        .bind(actor_type)
        .bind(actor_id)
        .bind(event_type)
        .bind(payload)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn list_audit_events(
        &self,
        limit: i64,
        offset: i64,
        event_type: Option<&str>,
        customer_id: Option<Uuid>,
    ) -> Result<Vec<AuditEventRecord>, PrivacyRepoError> {
        let rows = sqlx::query_as::<_, AuditEventDbRow>(
            "SELECT id, customer_id, actor_type, actor_id, event_type, payload, created_at
             FROM audit_events
             WHERE ($1::text IS NULL OR event_type = $1)
               AND ($2::uuid IS NULL OR customer_id = $2)
             ORDER BY created_at DESC
             LIMIT $3
             OFFSET $4",
        )
        .bind(event_type)
        .bind(customer_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
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
