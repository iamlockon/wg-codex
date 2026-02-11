use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum OAuthRepoError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Clone)]
pub struct PostgresOAuthRepository {
    pool: PgPool,
}

impl PostgresOAuthRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn resolve_or_create_customer(
        &self,
        provider: &str,
        subject: &str,
        email: Option<&str>,
    ) -> Result<Uuid, OAuthRepoError> {
        let mut tx = self.pool.begin().await?;
        let customer_id = resolve_or_create_customer_tx(&mut tx, provider, subject, email).await?;
        tx.commit().await?;
        Ok(customer_id)
    }
}

async fn resolve_or_create_customer_tx(
    tx: &mut Transaction<'_, Postgres>,
    provider: &str,
    subject: &str,
    email: Option<&str>,
) -> Result<Uuid, sqlx::Error> {
    // Serialize identity creation for a given provider+subject to avoid races.
    let lock_key = format!("{provider}:{subject}");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(lock_key)
        .execute(tx.as_mut())
        .await?;

    if let Some(existing) = sqlx::query_scalar::<_, Uuid>(
        "SELECT customer_id
         FROM oauth_identities
         WHERE provider = $1 AND subject = $2
         LIMIT 1",
    )
    .bind(provider)
    .bind(subject)
    .fetch_optional(tx.as_mut())
    .await?
    {
        if let Some(email) = email {
            sqlx::query(
                "UPDATE oauth_identities
                 SET email = $1
                 WHERE provider = $2 AND subject = $3",
            )
            .bind(email)
            .bind(provider)
            .bind(subject)
            .execute(tx.as_mut())
            .await?;
        }
        return Ok(existing);
    }

    let customer_id =
        sqlx::query_scalar::<_, Uuid>("INSERT INTO customers DEFAULT VALUES RETURNING id")
            .fetch_one(tx.as_mut())
            .await?;

    sqlx::query(
        "INSERT INTO oauth_identities (customer_id, provider, subject, email)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(customer_id)
    .bind(provider)
    .bind(subject)
    .bind(email)
    .execute(tx.as_mut())
    .await?;

    Ok(customer_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    async fn setup_repo() -> Option<PostgresOAuthRepository> {
        let url = std::env::var("TEST_DATABASE_URL").ok()?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .ok()?;
        let schema = format!("test_oauth_{}", Uuid::new_v4().simple());
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

        Some(PostgresOAuthRepository::new(pool))
    }

    #[tokio::test]
    async fn resolve_or_create_customer_creates_identity_once() {
        let Some(repo) = setup_repo().await else {
            return;
        };

        let customer_id = repo
            .resolve_or_create_customer("google", "sub-1", Some("first@example.com"))
            .await
            .expect("create");
        let customer_id_again = repo
            .resolve_or_create_customer("google", "sub-1", Some("first@example.com"))
            .await
            .expect("resolve existing");
        assert_eq!(customer_id, customer_id_again);

        let customer_count = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM customers")
            .fetch_one(&repo.pool)
            .await
            .expect("customer count");
        let identity_count = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM oauth_identities")
            .fetch_one(&repo.pool)
            .await
            .expect("identity count");

        assert_eq!(customer_count, 1);
        assert_eq!(identity_count, 1);
    }

    #[tokio::test]
    async fn resolve_or_create_customer_updates_email_when_present() {
        let Some(repo) = setup_repo().await else {
            return;
        };

        let customer_id = repo
            .resolve_or_create_customer("google", "sub-2", Some("old@example.com"))
            .await
            .expect("create");
        let customer_id_again = repo
            .resolve_or_create_customer("google", "sub-2", Some("new@example.com"))
            .await
            .expect("update");
        assert_eq!(customer_id, customer_id_again);

        let stored_email = sqlx::query_scalar::<_, Option<String>>(
            "SELECT email FROM oauth_identities WHERE provider = 'google' AND subject = 'sub-2'",
        )
        .fetch_one(&repo.pool)
        .await
        .expect("email row");
        assert_eq!(stored_email.as_deref(), Some("new@example.com"));
    }

    #[tokio::test]
    async fn resolve_or_create_customer_keeps_existing_email_when_none_provided() {
        let Some(repo) = setup_repo().await else {
            return;
        };

        let customer_id = repo
            .resolve_or_create_customer("google", "sub-3", Some("keep@example.com"))
            .await
            .expect("create");
        let customer_id_again = repo
            .resolve_or_create_customer("google", "sub-3", None)
            .await
            .expect("resolve without email");
        assert_eq!(customer_id, customer_id_again);

        let stored_email = sqlx::query_scalar::<_, Option<String>>(
            "SELECT email FROM oauth_identities WHERE provider = 'google' AND subject = 'sub-3'",
        )
        .fetch_one(&repo.pool)
        .await
        .expect("email row");
        assert_eq!(stored_email.as_deref(), Some("keep@example.com"));
    }

    #[tokio::test]
    async fn resolve_or_create_customer_is_scoped_by_provider() {
        let Some(repo) = setup_repo().await else {
            return;
        };

        let google_customer = repo
            .resolve_or_create_customer("google", "same-subject", Some("g@example.com"))
            .await
            .expect("google create");
        let apple_customer = repo
            .resolve_or_create_customer("apple", "same-subject", Some("a@example.com"))
            .await
            .expect("apple create");

        assert_ne!(google_customer, apple_customer);

        let customer_count = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM customers")
            .fetch_one(&repo.pool)
            .await
            .expect("customer count");
        let identity_count = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM oauth_identities")
            .fetch_one(&repo.pool)
            .await
            .expect("identity count");
        assert_eq!(customer_count, 2);
        assert_eq!(identity_count, 2);
    }

    #[tokio::test]
    async fn resolve_or_create_customer_is_race_safe_for_same_identity() {
        let Some(repo) = setup_repo().await else {
            return;
        };

        let mut handles = Vec::new();
        for _ in 0..12 {
            let repo = repo.clone();
            handles.push(tokio::spawn(async move {
                repo.resolve_or_create_customer("google", "race-subject", Some("race@example.com"))
                    .await
                    .expect("resolve/create")
            }));
        }

        let mut ids = Vec::new();
        for handle in handles {
            ids.push(handle.await.expect("join"));
        }
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 1);

        let customer_count = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM customers")
            .fetch_one(&repo.pool)
            .await
            .expect("customer count");
        let identity_count = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM oauth_identities")
            .fetch_one(&repo.pool)
            .await
            .expect("identity count");
        assert_eq!(customer_count, 1);
        assert_eq!(identity_count, 1);
    }

    #[tokio::test]
    async fn resolve_or_create_customer_separates_different_subjects_same_provider() {
        let Some(repo) = setup_repo().await else {
            return;
        };

        let customer_a = repo
            .resolve_or_create_customer("google", "subject-a", Some("a@example.com"))
            .await
            .expect("customer a");
        let customer_b = repo
            .resolve_or_create_customer("google", "subject-b", Some("b@example.com"))
            .await
            .expect("customer b");

        assert_ne!(customer_a, customer_b);

        let customer_count = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM customers")
            .fetch_one(&repo.pool)
            .await
            .expect("customer count");
        let identity_count = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM oauth_identities")
            .fetch_one(&repo.pool)
            .await
            .expect("identity count");
        assert_eq!(customer_count, 2);
        assert_eq!(identity_count, 2);
    }
}
