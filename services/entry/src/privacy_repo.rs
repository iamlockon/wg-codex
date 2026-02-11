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

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    async fn setup_repo() -> Option<PostgresPrivacyRepository> {
        let url = std::env::var("TEST_DATABASE_URL").ok()?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .ok()?;
        let schema = format!("test_priv_{}", Uuid::new_v4().simple());
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

        Some(PostgresPrivacyRepository::new(pool))
    }

    #[tokio::test]
    async fn insert_and_list_audit_events_returns_latest_first() {
        let Some(repo) = setup_repo().await else {
            return;
        };
        let customer_id = Uuid::new_v4();
        sqlx::query("INSERT INTO customers (id) VALUES ($1)")
            .bind(customer_id)
            .execute(&repo.pool)
            .await
            .expect("insert customer");

        repo.insert_audit_event(
            Some(customer_id),
            "customer",
            &customer_id.to_string(),
            "event_a",
            serde_json::json!({"k":"a"}),
        )
        .await
        .expect("insert event_a");
        repo.insert_audit_event(
            Some(customer_id),
            "customer",
            &customer_id.to_string(),
            "event_b",
            serde_json::json!({"k":"b"}),
        )
        .await
        .expect("insert event_b");

        let all = repo
            .list_audit_events(10, 0, None, Some(customer_id))
            .await
            .expect("list all");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].event_type, "event_b");
        assert_eq!(all[1].event_type, "event_a");

        let filtered = repo
            .list_audit_events(10, 0, Some("event_a"), Some(customer_id))
            .await
            .expect("filtered");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].event_type, "event_a");
    }

    #[tokio::test]
    async fn purge_expired_metadata_removes_old_audit_rows() {
        let Some(repo) = setup_repo().await else {
            return;
        };

        sqlx::query(
            "INSERT INTO audit_events (actor_type, actor_id, event_type, payload, created_at)
             VALUES ('system', 's1', 'old_event', '{}'::jsonb, now() - interval '10 days')",
        )
        .execute(&repo.pool)
        .await
        .expect("seed old audit event");
        sqlx::query(
            "INSERT INTO audit_events (actor_type, actor_id, event_type, payload, created_at)
             VALUES ('system', 's2', 'new_event', '{}'::jsonb, now())",
        )
        .execute(&repo.pool)
        .await
        .expect("seed new audit event");

        let (_sessions, audits) = repo.purge_expired_metadata(365, 3).await.expect("purge");
        assert!(audits >= 1);

        let remaining_old = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM audit_events WHERE event_type = 'old_event'",
        )
        .fetch_one(&repo.pool)
        .await
        .expect("remaining old");
        let remaining_new = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM audit_events WHERE event_type = 'new_event'",
        )
        .fetch_one(&repo.pool)
        .await
        .expect("remaining new");

        assert_eq!(remaining_old, 0);
        assert_eq!(remaining_new, 1);
    }

    #[tokio::test]
    async fn purge_expired_metadata_removes_only_old_terminated_sessions() {
        let Some(repo) = setup_repo().await else {
            return;
        };
        let customer_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();

        sqlx::query("INSERT INTO customers (id) VALUES ($1)")
            .bind(customer_id)
            .execute(&repo.pool)
            .await
            .expect("insert customer");
        sqlx::query(
            "INSERT INTO devices (id, customer_id, name, public_key) VALUES ($1, $2, $3, $4)",
        )
        .bind(device_id)
        .bind(customer_id)
        .bind("device")
        .bind(format!("pk-{}", Uuid::new_v4()))
        .execute(&repo.pool)
        .await
        .expect("insert device");

        sqlx::query(
            "INSERT INTO sessions (session_key, customer_id, device_id, region, state, terminated_at)
             VALUES ('old_term', $1, $2, 'us-west1', 'terminated', now() - interval '10 days')",
        )
        .bind(customer_id)
        .bind(device_id)
        .execute(&repo.pool)
        .await
        .expect("seed old terminated");

        sqlx::query(
            "INSERT INTO sessions (session_key, customer_id, device_id, region, state, terminated_at)
             VALUES ('new_term', $1, $2, 'us-west1', 'terminated', now() - interval '1 day')",
        )
        .bind(customer_id)
        .bind(device_id)
        .execute(&repo.pool)
        .await
        .expect("seed new terminated");

        sqlx::query(
            "INSERT INTO sessions (session_key, customer_id, device_id, region, state, connected_at)
             VALUES ('active_one', $1, $2, 'us-west1', 'active', now())",
        )
        .bind(customer_id)
        .bind(device_id)
        .execute(&repo.pool)
        .await
        .expect("seed active");

        let (removed_sessions, _removed_audits) =
            repo.purge_expired_metadata(3, 365).await.expect("purge");
        assert_eq!(removed_sessions, 1);

        let old_count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM sessions WHERE session_key = 'old_term'",
        )
        .fetch_one(&repo.pool)
        .await
        .expect("old count");
        let new_count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM sessions WHERE session_key = 'new_term'",
        )
        .fetch_one(&repo.pool)
        .await
        .expect("new count");
        let active_count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM sessions WHERE session_key = 'active_one'",
        )
        .fetch_one(&repo.pool)
        .await
        .expect("active count");

        assert_eq!(old_count, 0);
        assert_eq!(new_count, 1);
        assert_eq!(active_count, 1);
    }
}
