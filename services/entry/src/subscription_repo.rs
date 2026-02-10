use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionStatus {
    Active,
    Trialing,
    PastDue,
    Canceled,
}

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
    #[error("plan not found")]
    PlanNotFound,
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

    pub async fn is_customer_session_eligible(
        &self,
        customer_id: Uuid,
    ) -> Result<bool, SubscriptionRepoError> {
        let row = sqlx::query_scalar::<_, i64>(
            "SELECT 1
             FROM customer_subscriptions s
             WHERE s.customer_id = $1
               AND s.status IN ('active', 'trialing')
               AND s.starts_at <= now()
               AND (s.ends_at IS NULL OR s.ends_at >= now())
             LIMIT 1",
        )
        .bind(customer_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.is_some())
    }

    pub async fn upsert_customer_subscription(
        &self,
        customer_id: Uuid,
        plan_code: &str,
        status: SubscriptionStatus,
    ) -> Result<(), SubscriptionRepoError> {
        let plan_id = sqlx::query_scalar::<_, Uuid>("SELECT id FROM plans WHERE code = $1 LIMIT 1")
            .bind(plan_code)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(SubscriptionRepoError::PlanNotFound)?;

        let status_text = status.as_str();
        sqlx::query(
            "INSERT INTO customer_subscriptions (customer_id, plan_id, status, starts_at, created_at, updated_at)
             VALUES ($1, $2, $3, now(), now(), now())
             ON CONFLICT (customer_id) WHERE status IN ('active', 'trialing')
             DO UPDATE SET
                 plan_id = EXCLUDED.plan_id,
                 status = EXCLUDED.status,
                 starts_at = now(),
                 ends_at = NULL,
                 updated_at = now()",
        )
        .bind(customer_id)
        .bind(plan_id)
        .bind(status_text)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

impl SubscriptionStatus {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "trialing" => Some(Self::Trialing),
            "past_due" => Some(Self::PastDue),
            "canceled" => Some(Self::Canceled),
            _ => None,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Trialing => "trialing",
            Self::PastDue => "past_due",
            Self::Canceled => "canceled",
        }
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
