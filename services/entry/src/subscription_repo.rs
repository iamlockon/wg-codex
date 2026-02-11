use chrono::DateTime;
use chrono::Utc;
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

#[derive(Debug, Clone)]
pub struct SubscriptionRecord {
    pub customer_id: Uuid,
    pub plan_code: String,
    pub status: String,
    pub starts_at: DateTime<Utc>,
    pub ends_at: Option<DateTime<Utc>>,
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

        let mut tx = self.pool.begin().await?;
        let status_text = status.as_str();
        sqlx::query(
            "UPDATE customer_subscriptions
             SET status = 'canceled',
                 ends_at = COALESCE(ends_at, now()),
                 updated_at = now()
             WHERE customer_id = $1
               AND status IN ('active', 'trialing')",
        )
        .bind(customer_id)
        .execute(tx.as_mut())
        .await?;

        let ends_at = if matches!(
            status,
            SubscriptionStatus::Active | SubscriptionStatus::Trialing
        ) {
            None
        } else {
            Some(Utc::now())
        };
        sqlx::query(
            "INSERT INTO customer_subscriptions (customer_id, plan_id, status, starts_at, ends_at, created_at, updated_at)
             VALUES ($1, $2, $3, now(), $4, now(), now())",
        )
        .bind(customer_id)
        .bind(plan_id)
        .bind(status_text)
        .bind(ends_at)
        .execute(tx.as_mut())
        .await?;
        tx.commit().await?;

        Ok(())
    }

    pub async fn get_customer_subscription(
        &self,
        customer_id: Uuid,
    ) -> Result<Option<SubscriptionRecord>, SubscriptionRepoError> {
        let row = sqlx::query_as::<_, SubscriptionDbRow>(
            "SELECT s.customer_id, p.code AS plan_code, s.status, s.starts_at, s.ends_at
             FROM customer_subscriptions s
             JOIN plans p ON p.id = s.plan_id
             WHERE s.customer_id = $1
             ORDER BY s.created_at DESC
             LIMIT 1",
        )
        .bind(customer_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
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

#[derive(sqlx::FromRow)]
struct SubscriptionDbRow {
    customer_id: Uuid,
    plan_code: String,
    status: String,
    starts_at: DateTime<Utc>,
    ends_at: Option<DateTime<Utc>>,
}

impl From<SubscriptionDbRow> for SubscriptionRecord {
    fn from(value: SubscriptionDbRow) -> Self {
        Self {
            customer_id: value.customer_id,
            plan_code: value.plan_code,
            status: value.status,
            starts_at: value.starts_at,
            ends_at: value.ends_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    async fn setup_repo() -> Option<PostgresSubscriptionRepository> {
        let url = std::env::var("TEST_DATABASE_URL").ok()?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .ok()?;
        let schema = format!("test_sub_{}", Uuid::new_v4().simple());
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
        sqlx::raw_sql(include_str!(
            "../../../db/migrations/202602100003_consumer_model.sql"
        ))
        .execute(&pool)
        .await
        .ok()?;

        Some(PostgresSubscriptionRepository::new(pool))
    }

    #[tokio::test]
    async fn upsert_customer_subscription_sets_eligibility_and_entitlements() {
        let Some(repo) = setup_repo().await else {
            return;
        };
        let customer_id = Uuid::new_v4();
        sqlx::query("INSERT INTO customers (id) VALUES ($1)")
            .bind(customer_id)
            .execute(&repo.pool)
            .await
            .expect("insert customer");

        repo.upsert_customer_subscription(customer_id, "plus", SubscriptionStatus::Active)
            .await
            .expect("upsert active plus");
        assert!(
            repo.is_customer_session_eligible(customer_id)
                .await
                .expect("eligibility")
        );
        let entitlements = repo
            .entitlements_for_customer(customer_id)
            .await
            .expect("entitlements");
        assert_eq!(entitlements.max_active_sessions, 1);
        assert_eq!(entitlements.max_devices, 7);
    }

    #[tokio::test]
    async fn canceling_subscription_disables_session_eligibility() {
        let Some(repo) = setup_repo().await else {
            return;
        };
        let customer_id = Uuid::new_v4();
        sqlx::query("INSERT INTO customers (id) VALUES ($1)")
            .bind(customer_id)
            .execute(&repo.pool)
            .await
            .expect("insert customer");

        repo.upsert_customer_subscription(customer_id, "free", SubscriptionStatus::Active)
            .await
            .expect("activate");
        assert!(
            repo.is_customer_session_eligible(customer_id)
                .await
                .expect("eligible")
        );

        repo.upsert_customer_subscription(customer_id, "free", SubscriptionStatus::Canceled)
            .await
            .expect("cancel");
        assert!(
            !repo
                .is_customer_session_eligible(customer_id)
                .await
                .expect("ineligible")
        );
    }
}
