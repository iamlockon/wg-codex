use crate::session_repo::{RepoError, SessionRow, StartSessionOutcome};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum PostgresRepoError {
    #[error("session not found")]
    NotFound,
    #[error("session key mismatch")]
    SessionKeyMismatch,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl From<RepoError> for PostgresRepoError {
    fn from(value: RepoError) -> Self {
        match value {
            RepoError::NotFound => Self::NotFound,
            RepoError::SessionKeyMismatch => Self::SessionKeyMismatch,
        }
    }
}

#[derive(Clone)]
pub struct PostgresSessionRepository {
    pool: PgPool,
}

impl PostgresSessionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn start_session(
        &self,
        customer_id: Uuid,
        device_id: Uuid,
        region: String,
        requested_session_key: String,
        reconnect_session_key: Option<&str>,
    ) -> Result<StartSessionOutcome, PostgresRepoError> {
        let mut tx = self.pool.begin().await?;

        if let Some(existing) = fetch_active_session_tx(&mut tx, customer_id).await? {
            if reconnect_session_key.unwrap_or_default() == existing.session_key {
                tx.commit().await?;
                return Ok(StartSessionOutcome::Reconnected(existing));
            }

            tx.commit().await?;
            return Ok(StartSessionOutcome::Conflict {
                existing_session_key: existing.session_key,
            });
        }

        let inserted = insert_active_session_tx(
            &mut tx,
            customer_id,
            device_id,
            &region,
            &requested_session_key,
        )
        .await;

        match inserted {
            Ok(row) => {
                tx.commit().await?;
                Ok(StartSessionOutcome::Created(row))
            }
            Err(err) if is_unique_violation(&err) => {
                // Another request may have won the race on uniq_active_session_per_customer.
                if let Some(existing) = fetch_active_session_tx(&mut tx, customer_id).await? {
                    tx.commit().await?;
                    if reconnect_session_key.unwrap_or_default() == existing.session_key {
                        return Ok(StartSessionOutcome::Reconnected(existing));
                    }
                    return Ok(StartSessionOutcome::Conflict {
                        existing_session_key: existing.session_key,
                    });
                }

                tx.rollback().await?;
                Err(PostgresRepoError::Database(err))
            }
            Err(err) => {
                tx.rollback().await?;
                Err(PostgresRepoError::Database(err))
            }
        }
    }

    pub async fn terminate_session(
        &self,
        customer_id: Uuid,
        session_key: &str,
    ) -> Result<(), PostgresRepoError> {
        let mut tx = self.pool.begin().await?;
        let existing = fetch_active_session_tx(&mut tx, customer_id).await?;
        let existing = existing.ok_or(PostgresRepoError::NotFound)?;

        if existing.session_key != session_key {
            tx.commit().await?;
            return Err(PostgresRepoError::SessionKeyMismatch);
        }

        sqlx::query(
            "UPDATE sessions
             SET state = 'terminated',
                 terminated_at = now(),
                 updated_at = now()
             WHERE customer_id = $1
               AND state = 'active'
               AND session_key = $2",
        )
        .bind(customer_id)
        .bind(session_key)
        .execute(tx.as_mut())
        .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn get_active_session(
        &self,
        customer_id: Uuid,
    ) -> Result<Option<SessionRow>, PostgresRepoError> {
        fetch_active_session_pool(&self.pool, customer_id)
            .await
            .map_err(PostgresRepoError::Database)
    }
}

fn is_unique_violation(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db_err) => db_err.code().as_deref() == Some("23505"),
        _ => false,
    }
}

async fn fetch_active_session_pool(
    pool: &PgPool,
    customer_id: Uuid,
) -> Result<Option<SessionRow>, sqlx::Error> {
    let row = sqlx::query_as::<_, SessionDbRow>(
        "SELECT session_key,
                customer_id,
                device_id,
                region,
                COALESCE(connected_at, created_at) AS connected_at
         FROM sessions
         WHERE customer_id = $1
           AND state = 'active'
         ORDER BY created_at DESC
         LIMIT 1",
    )
    .bind(customer_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(Into::into))
}

async fn fetch_active_session_tx(
    tx: &mut Transaction<'_, Postgres>,
    customer_id: Uuid,
) -> Result<Option<SessionRow>, sqlx::Error> {
    let row = sqlx::query_as::<_, SessionDbRow>(
        "SELECT session_key,
                customer_id,
                device_id,
                region,
                COALESCE(connected_at, created_at) AS connected_at
         FROM sessions
         WHERE customer_id = $1
           AND state = 'active'
         ORDER BY created_at DESC
         LIMIT 1
         FOR UPDATE",
    )
    .bind(customer_id)
    .fetch_optional(tx.as_mut())
    .await?;

    Ok(row.map(Into::into))
}

async fn insert_active_session_tx(
    tx: &mut Transaction<'_, Postgres>,
    customer_id: Uuid,
    device_id: Uuid,
    region: &str,
    session_key: &str,
) -> Result<SessionRow, sqlx::Error> {
    let row = sqlx::query_as::<_, SessionDbRow>(
        "INSERT INTO sessions (session_key, customer_id, device_id, region, state, connected_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'active', now(), now(), now())
         RETURNING session_key,
                   customer_id,
                   device_id,
                   region,
                   COALESCE(connected_at, created_at) AS connected_at",
    )
    .bind(session_key)
    .bind(customer_id)
    .bind(device_id)
    .bind(region)
    .fetch_one(tx.as_mut())
    .await?;

    Ok(row.into())
}

#[derive(sqlx::FromRow)]
struct SessionDbRow {
    session_key: String,
    customer_id: Uuid,
    device_id: Uuid,
    region: String,
    connected_at: DateTime<Utc>,
}

impl From<SessionDbRow> for SessionRow {
    fn from(value: SessionDbRow) -> Self {
        Self {
            session_key: value.session_key,
            customer_id: value.customer_id,
            device_id: value.device_id,
            region: value.region,
            connected_at: value.connected_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    async fn setup_repo() -> Option<PostgresSessionRepository> {
        let url = std::env::var("TEST_DATABASE_URL").ok()?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .ok()?;
        let schema = format!("test_sess_{}", Uuid::new_v4().simple());
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

        Some(PostgresSessionRepository::new(pool))
    }

    async fn insert_customer_with_device(
        repo: &PostgresSessionRepository,
    ) -> Result<(Uuid, Uuid), sqlx::Error> {
        let customer_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        sqlx::query("INSERT INTO customers (id) VALUES ($1)")
            .bind(customer_id)
            .execute(&repo.pool)
            .await?;
        sqlx::query(
            "INSERT INTO devices (id, customer_id, name, public_key) VALUES ($1, $2, $3, $4)",
        )
        .bind(device_id)
        .bind(customer_id)
        .bind("device")
        .bind(format!("pk-{}", Uuid::new_v4()))
        .execute(&repo.pool)
        .await?;
        Ok((customer_id, device_id))
    }

    #[tokio::test]
    async fn start_session_conflicts_when_active_exists() {
        let Some(repo) = setup_repo().await else {
            return;
        };
        let (customer_id, device_id) = insert_customer_with_device(&repo)
            .await
            .expect("seed customer/device");

        let first = repo
            .start_session(
                customer_id,
                device_id,
                "us-west1".to_string(),
                "sess_one".to_string(),
                None,
            )
            .await
            .expect("first start");
        assert!(matches!(first, StartSessionOutcome::Created(_)));

        let second = repo
            .start_session(
                customer_id,
                device_id,
                "us-west1".to_string(),
                "sess_two".to_string(),
                None,
            )
            .await
            .expect("second start");
        assert_eq!(
            second,
            StartSessionOutcome::Conflict {
                existing_session_key: "sess_one".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn terminate_session_requires_matching_key() {
        let Some(repo) = setup_repo().await else {
            return;
        };
        let (customer_id, device_id) = insert_customer_with_device(&repo)
            .await
            .expect("seed customer/device");

        repo.start_session(
            customer_id,
            device_id,
            "us-west1".to_string(),
            "sess_one".to_string(),
            None,
        )
        .await
        .expect("start");

        let err = repo
            .terminate_session(customer_id, "sess_wrong")
            .await
            .expect_err("mismatch should fail");
        assert!(matches!(err, PostgresRepoError::SessionKeyMismatch));
    }

    #[tokio::test]
    async fn start_session_reuses_active_session_when_reconnect_key_matches() {
        let Some(repo) = setup_repo().await else {
            return;
        };
        let (customer_id, device_id) = insert_customer_with_device(&repo)
            .await
            .expect("seed customer/device");

        let first = repo
            .start_session(
                customer_id,
                device_id,
                "us-west1".to_string(),
                "sess_one".to_string(),
                None,
            )
            .await
            .expect("first start");
        let first = match first {
            StartSessionOutcome::Created(row) => row,
            other => panic!("unexpected first start outcome: {other:?}"),
        };

        let second = repo
            .start_session(
                customer_id,
                device_id,
                "us-west1".to_string(),
                "sess_two".to_string(),
                Some(&first.session_key),
            )
            .await
            .expect("second start");
        assert_eq!(second, StartSessionOutcome::Reconnected(first.clone()));

        let active_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)
             FROM sessions
             WHERE customer_id = $1
               AND state = 'active'",
        )
        .bind(customer_id)
        .fetch_one(&repo.pool)
        .await
        .expect("count active");
        assert_eq!(active_count, 1);
    }

    #[tokio::test]
    async fn terminate_session_allows_new_active_session_afterwards() {
        let Some(repo) = setup_repo().await else {
            return;
        };
        let (customer_id, device_id) = insert_customer_with_device(&repo)
            .await
            .expect("seed customer/device");

        repo.start_session(
            customer_id,
            device_id,
            "us-west1".to_string(),
            "sess_one".to_string(),
            None,
        )
        .await
        .expect("start");

        repo.terminate_session(customer_id, "sess_one")
            .await
            .expect("terminate");

        let restarted = repo
            .start_session(
                customer_id,
                device_id,
                "us-west1".to_string(),
                "sess_two".to_string(),
                None,
            )
            .await
            .expect("restart");
        assert!(matches!(restarted, StartSessionOutcome::Created(_)));
    }
}
