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
