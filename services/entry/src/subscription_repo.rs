use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Entitlements {
    pub max_active_sessions: i32,
    pub max_devices: i32,
    pub allowed_regions: Option<Vec<String>>,
}

impl Default for Entitlements {
    fn default() -> Self {
        Self {
            max_active_sessions: 1,
            max_devices: 3,
            allowed_regions: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum SubscriptionRepoError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Clone)]
pub struct PostgresSubscriptionRepository {
    pool: PgPool,
}

impl PostgresSubscriptionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn entitlements_for_customer(
        &self,
        customer_id: Uuid,
    ) -> Result<Entitlements, SubscriptionRepoError> {
        let row = sqlx::query_as::<_, EntitlementsDbRow>(
            "SELECT LEAST(p.max_active_sessions, 1) AS max_active_sessions, p.max_devices, p.allowed_regions
             FROM customer_subscriptions s
             JOIN plans p ON p.id = s.plan_id
             WHERE s.customer_id = $1
               AND s.status IN ('active', 'trialing')
               AND s.starts_at <= now()
               AND (s.ends_at IS NULL OR s.ends_at >= now())
             ORDER BY s.starts_at DESC
             LIMIT 1",
        )
        .bind(customer_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Into::into).unwrap_or_default())
    }
}

#[derive(sqlx::FromRow)]
struct EntitlementsDbRow {
    max_active_sessions: i32,
    max_devices: i32,
    allowed_regions: Option<Vec<String>>,
}

impl From<EntitlementsDbRow> for Entitlements {
    fn from(value: EntitlementsDbRow) -> Self {
        Self {
            max_active_sessions: value.max_active_sessions,
            max_devices: value.max_devices,
            allowed_regions: value.allowed_regions,
        }
    }
}
