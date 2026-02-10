use chrono::{DateTime, Utc};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    pub session_key: String,
    pub customer_id: Uuid,
    pub device_id: Uuid,
    pub region: String,
    pub connected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartSessionOutcome {
    Created(SessionRow),
    Reconnected(SessionRow),
    Conflict { existing_session_key: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoError {
    NotFound,
    SessionKeyMismatch,
}

pub trait SessionRepository {
    fn start_session(
        &mut self,
        customer_id: Uuid,
        device_id: Uuid,
        region: String,
        requested_session_key: String,
        reconnect_session_key: Option<&str>,
    ) -> StartSessionOutcome;

    fn terminate_session(&mut self, customer_id: Uuid, session_key: &str) -> Result<(), RepoError>;

    fn get_active_session(&self, customer_id: Uuid) -> Option<SessionRow>;
}

#[derive(Default)]
pub struct InMemorySessionRepository {
    active_sessions: HashMap<Uuid, SessionRow>,
}

impl SessionRepository for InMemorySessionRepository {
    fn start_session(
        &mut self,
        customer_id: Uuid,
        device_id: Uuid,
        region: String,
        requested_session_key: String,
        reconnect_session_key: Option<&str>,
    ) -> StartSessionOutcome {
        if let Some(existing) = self.active_sessions.get(&customer_id) {
            if reconnect_session_key.unwrap_or_default() == existing.session_key {
                return StartSessionOutcome::Reconnected(existing.clone());
            }

            return StartSessionOutcome::Conflict {
                existing_session_key: existing.session_key.clone(),
            };
        }

        let row = SessionRow {
            session_key: requested_session_key,
            customer_id,
            device_id,
            region,
            connected_at: Utc::now(),
        };
        self.active_sessions.insert(customer_id, row.clone());
        StartSessionOutcome::Created(row)
    }

    fn terminate_session(&mut self, customer_id: Uuid, session_key: &str) -> Result<(), RepoError> {
        match self.active_sessions.get(&customer_id) {
            Some(existing) if existing.session_key == session_key => {
                self.active_sessions.remove(&customer_id);
                Ok(())
            }
            Some(_) => Err(RepoError::SessionKeyMismatch),
            None => Err(RepoError::NotFound),
        }
    }

    fn get_active_session(&self, customer_id: Uuid) -> Option<SessionRow> {
        self.active_sessions.get(&customer_id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_new_session_when_customer_has_no_active_session() {
        let mut repo = InMemorySessionRepository::default();
        let customer_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();

        let outcome = repo.start_session(
            customer_id,
            device_id,
            "us-central1".to_string(),
            "sess_a".to_string(),
            None,
        );

        match outcome {
            StartSessionOutcome::Created(row) => {
                assert_eq!(row.session_key, "sess_a");
                assert_eq!(row.customer_id, customer_id);
                assert_eq!(row.device_id, device_id);
            }
            _ => panic!("expected Created outcome"),
        }
    }

    #[test]
    fn returns_conflict_when_active_session_exists_and_reconnect_key_is_missing() {
        let mut repo = InMemorySessionRepository::default();
        let customer_id = Uuid::new_v4();

        let _ = repo.start_session(
            customer_id,
            Uuid::new_v4(),
            "us-central1".to_string(),
            "sess_a".to_string(),
            None,
        );

        let outcome = repo.start_session(
            customer_id,
            Uuid::new_v4(),
            "us-east1".to_string(),
            "sess_b".to_string(),
            None,
        );

        assert_eq!(
            outcome,
            StartSessionOutcome::Conflict {
                existing_session_key: "sess_a".to_string()
            }
        );
    }

    #[test]
    fn reconnects_when_reconnect_key_matches_existing_session() {
        let mut repo = InMemorySessionRepository::default();
        let customer_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();

        let _ = repo.start_session(
            customer_id,
            device_id,
            "us-central1".to_string(),
            "sess_a".to_string(),
            None,
        );

        let outcome = repo.start_session(
            customer_id,
            Uuid::new_v4(),
            "us-east1".to_string(),
            "sess_b".to_string(),
            Some("sess_a"),
        );

        match outcome {
            StartSessionOutcome::Reconnected(row) => {
                assert_eq!(row.session_key, "sess_a");
                assert_eq!(row.region, "us-central1");
            }
            _ => panic!("expected Reconnected outcome"),
        }
    }

    #[test]
    fn terminate_enforces_session_key_match() {
        let mut repo = InMemorySessionRepository::default();
        let customer_id = Uuid::new_v4();

        let _ = repo.start_session(
            customer_id,
            Uuid::new_v4(),
            "us-central1".to_string(),
            "sess_a".to_string(),
            None,
        );

        let err = repo
            .terminate_session(customer_id, "sess_wrong")
            .expect_err("mismatched key should fail");
        assert_eq!(err, RepoError::SessionKeyMismatch);
    }

    #[test]
    fn terminate_then_create_new_session_succeeds() {
        let mut repo = InMemorySessionRepository::default();
        let customer_id = Uuid::new_v4();

        let _ = repo.start_session(
            customer_id,
            Uuid::new_v4(),
            "us-central1".to_string(),
            "sess_a".to_string(),
            None,
        );
        repo.terminate_session(customer_id, "sess_a")
            .expect("terminate should succeed");

        let outcome = repo.start_session(
            customer_id,
            Uuid::new_v4(),
            "us-east1".to_string(),
            "sess_b".to_string(),
            None,
        );

        match outcome {
            StartSessionOutcome::Created(row) => assert_eq!(row.session_key, "sess_b"),
            _ => panic!("expected Created outcome"),
        }
    }
}
