# DB Test Spec (Session Invariant)

This file defines the expected Postgres repository behavior before wiring `sqlx`.

## Invariant
- A customer can have at most one active session.
- The existing `session_key` is reusable for reconnect.
- New session requests with non-matching reconnect key return conflict with existing key.

## Contract Cases
1. `start_session` with no active row:
   - Inserts a new `active` session row.
   - Returns `Created`.
2. `start_session` with active row + matching reconnect key:
   - Does not create a second row.
   - Returns `Reconnected(existing)`.
3. `start_session` with active row + missing/mismatched reconnect key:
   - No write.
   - Returns `Conflict(existing_session_key)`.
4. `terminate_session` with matching key:
   - Marks current session terminated (or removes active state).
   - Returns success.
5. `terminate_session` with mismatched key:
   - No write.
   - Returns `SessionKeyMismatch`.

## Current Executable Spec
- Implemented as unit tests in `services/entry/src/session_repo.rs`.
- This should be treated as the behavior contract for the future Postgres-backed repository.

## Current DB-backed Implementation
- Implemented repository module: `services/entry/src/postgres_session_repo.rs`.
- Uses transaction boundaries for `start_session` and `terminate_session`.
- Uses `uniq_active_session_per_customer` to enforce single-active-session under races.
- On unique-constraint race during insert, re-reads active session and returns `Reconnected` or `Conflict` per reconnect key.
