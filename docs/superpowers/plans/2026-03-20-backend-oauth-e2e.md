# Backend OAuth E2E Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a backend end-to-end integration suite that boots `entry`, `core`, a stub OAuth/JWKS server, and Postgres-backed state, then verifies OAuth login, session lifecycle, reconnect semantics, and logout revocation locally and in CI.

**Architecture:** Create a dedicated workspace test crate that owns process orchestration, stub OAuth fixtures, temporary node-catalog setup, and HTTP assertions. Keep runtime services unchanged except for whatever small testability seams are required to start them deterministically as child processes, and expose the suite through a single local script plus a path-gated CI job.

**Tech Stack:** Rust workspace crate, `tokio`, `reqwest`, child-process orchestration, local HTTP stub server, existing `entry` and `core` binaries, GitHub Actions, Postgres via `TEST_DATABASE_URL`

---

### Task 1: Create the backend e2e workspace crate skeleton

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/backend-e2e/Cargo.toml`
- Create: `crates/backend-e2e/src/lib.rs`
- Create: `crates/backend-e2e/tests/backend_oauth_e2e.rs`

- [ ] **Step 1: Write the failing test target definition**

Add the new workspace member and a placeholder integration test that names the first target scenario:

```rust
#[tokio::test]
async fn oauth_login_session_lifecycle_and_logout_revocation_e2e() {
    panic!("backend e2e harness not implemented");
}
```

- [ ] **Step 2: Run the new test to verify it fails**

Run: `cargo test -p backend-e2e oauth_login_session_lifecycle_and_logout_revocation_e2e -- --nocapture`
Expected: FAIL with the explicit placeholder panic from the new e2e test

- [ ] **Step 3: Add the minimal crate wiring**

Create `crates/backend-e2e/Cargo.toml` with only the dependencies needed for:
- async tests
- HTTP requests
- JSON handling
- temp files/directories
- process management
- JWT/JWK generation for the stub OAuth provider

Use `src/lib.rs` for shared helpers and keep the first test in `tests/backend_oauth_e2e.rs`.

- [ ] **Step 4: Run the test again to verify the crate is wired correctly**

Run: `cargo test -p backend-e2e oauth_login_session_lifecycle_and_logout_revocation_e2e -- --nocapture`
Expected: FAIL from the same placeholder, with the crate compiling successfully

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/backend-e2e/Cargo.toml crates/backend-e2e/src/lib.rs crates/backend-e2e/tests/backend_oauth_e2e.rs
git commit -m "test: scaffold backend e2e crate"
```

### Task 2: Build the stub OAuth/JWKS fixture server

**Files:**
- Modify: `crates/backend-e2e/Cargo.toml`
- Modify: `crates/backend-e2e/src/lib.rs`
- Create: `crates/backend-e2e/src/oauth_stub.rs`
- Modify: `crates/backend-e2e/tests/backend_oauth_e2e.rs`

- [ ] **Step 1: Write the failing fixture test**

Add a focused test that starts the stub server, calls `POST /token` and `GET /jwks`, and asserts:
- token response contains `id_token`
- ID token header contains the configured `kid`
- JWKS contains the matching RSA public key

- [ ] **Step 2: Run the fixture test to verify it fails for the expected reason**

Run: `cargo test -p backend-e2e oauth_stub_serves_token_and_jwks -- --nocapture`
Expected: FAIL because `oauth_stub` module or fixture functions do not exist yet

- [ ] **Step 3: Implement the minimal stub server**

Add `oauth_stub.rs` with helpers to:
- allocate an ephemeral bind address
- generate an RSA keypair
- issue an RS256 ID token with:
  - `iss` accepted by current Google validation
  - `aud` matching the configured client ID
  - `sub`, `email`, `name`
  - optional `nonce`
- serve:
  - `POST /token`
  - `GET /jwks`

Keep the server deterministic and return fixed values for the happy path.

- [ ] **Step 4: Run the fixture test to verify it passes**

Run: `cargo test -p backend-e2e oauth_stub_serves_token_and_jwks -- --nocapture`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/backend-e2e/Cargo.toml crates/backend-e2e/src/lib.rs crates/backend-e2e/src/oauth_stub.rs crates/backend-e2e/tests/backend_oauth_e2e.rs
git commit -m "test: add oauth stub fixture for backend e2e"
```

### Task 3: Add process orchestration helpers for `entry` and `core`

**Files:**
- Modify: `crates/backend-e2e/src/lib.rs`
- Create: `crates/backend-e2e/src/process.rs`
- Create: `crates/backend-e2e/src/catalog_fixture.rs`
- Modify: `crates/backend-e2e/tests/backend_oauth_e2e.rs`

- [ ] **Step 1: Write the failing readiness test**

Add a focused test that attempts to:
- allocate ports
- write a temporary node catalog fixture
- start `core`
- start `entry`
- hit `/healthz` on `entry`

Use an assertion that fails if either process exits early or readiness times out.

- [ ] **Step 2: Run the readiness test to verify it fails**

Run: `cargo test -p backend-e2e stack_starts_and_entry_healthz_recovers -- --nocapture`
Expected: FAIL because process orchestration helpers are missing

- [ ] **Step 3: Implement the minimal orchestration layer**

Add helpers that:
- locate built binaries for `entry` and `core`
- allocate localhost ports
- create temporary directories/files
- write a node catalog JSON file referencing the local `core`
- spawn `core` with safe local env:
  - `CORE_BIND_ADDR`
  - `CORE_DATAPLANE_NOOP=true`
  - `CORE_REQUIRE_TLS=false`
- spawn `entry` with:
  - `ENTRY_BIND_ADDR`
  - `CORE_GRPC_URL`
  - `DATABASE_URL`
  - `GOOGLE_OIDC_CLIENT_ID`
  - `GOOGLE_OIDC_CLIENT_SECRET`
  - `GOOGLE_OIDC_REDIRECT_URI`
  - `GOOGLE_OIDC_TOKEN_URL`
  - `GOOGLE_OIDC_JWKS_URL`
  - `APP_JWT_SIGNING_KEYS`
  - `APP_JWT_ACTIVE_KID`
  - `ADMIN_API_TOKEN`
  - `APP_ALLOW_LEGACY_CUSTOMER_HEADER=false`
  - `APP_NODE_CATALOG_FILE`
- poll `/healthz` until ready
- capture stdout/stderr for diagnostics on failure

- [ ] **Step 4: Run the readiness test to verify it passes**

Run: `cargo test -p backend-e2e stack_starts_and_entry_healthz_recovers -- --nocapture`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/backend-e2e/src/lib.rs crates/backend-e2e/src/process.rs crates/backend-e2e/src/catalog_fixture.rs crates/backend-e2e/tests/backend_oauth_e2e.rs
git commit -m "test: add backend stack harness"
```

### Task 4: Implement the full happy-path e2e flow

**Files:**
- Modify: `crates/backend-e2e/src/lib.rs`
- Create: `crates/backend-e2e/src/http_client.rs`
- Modify: `crates/backend-e2e/tests/backend_oauth_e2e.rs`

- [ ] **Step 1: Write the failing end-to-end happy-path test**

Expand `oauth_login_session_lifecycle_and_logout_revocation_e2e` to perform:
- OAuth callback with `code`, `code_verifier`, and `nonce`
- admin subscription activation for the returned `customer_id`
- device registration
- session start
- current-session fetch
- terminate session

Assert exact response codes and the presence of:
- bearer token
- `customer_id`
- created device ID
- `session_key`

- [ ] **Step 2: Run the happy-path test to verify it fails**

Run: `cargo test -p backend-e2e oauth_login_session_lifecycle_and_logout_revocation_e2e -- --nocapture`
Expected: FAIL at the first missing client helper or response-contract mismatch

- [ ] **Step 3: Implement minimal HTTP client helpers**

Add helper functions for:
- OAuth callback
- admin subscription upsert
- device registration
- session start
- current session
- terminate session

Keep them thin wrappers around `reqwest` and return parsed JSON payloads plus useful assertion context.

- [ ] **Step 4: Run the happy-path test to verify it passes**

Run: `cargo test -p backend-e2e oauth_login_session_lifecycle_and_logout_revocation_e2e -- --nocapture`
Expected: PASS for login, subscription activation, device registration, session start, current-session lookup, and termination

- [ ] **Step 5: Commit**

```bash
git add crates/backend-e2e/src/lib.rs crates/backend-e2e/src/http_client.rs crates/backend-e2e/tests/backend_oauth_e2e.rs
git commit -m "test: cover backend oauth session happy path"
```

### Task 5: Add reconnect reuse and conflict coverage

**Files:**
- Modify: `crates/backend-e2e/tests/backend_oauth_e2e.rs`

- [ ] **Step 1: Write the failing reconnect assertions**

Extend the e2e test set with:
- one scenario where `POST /v1/sessions/start` with a matching reconnect token reuses the current session
- one scenario where a missing or mismatched reconnect token returns conflict with the existing `session_key`

- [ ] **Step 2: Run the reconnect-focused tests to verify they fail correctly**

Run: `cargo test -p backend-e2e reconnect -- --nocapture`
Expected: FAIL because the assertions reveal missing request construction or misunderstood API payloads

- [ ] **Step 3: Implement the minimal request helpers or payload fixes**

Add only the logic needed to:
- pass the reconnect token field correctly
- parse conflict payloads
- compare returned `session_key` values

Do not add extra abstraction beyond what these tests require.

- [ ] **Step 4: Run the reconnect-focused tests to verify they pass**

Run: `cargo test -p backend-e2e reconnect -- --nocapture`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/backend-e2e/tests/backend_oauth_e2e.rs
git commit -m "test: cover session reconnect invariants end to end"
```

### Task 6: Add logout revocation enforcement coverage

**Files:**
- Modify: `crates/backend-e2e/tests/backend_oauth_e2e.rs`

- [ ] **Step 1: Write the failing logout revocation assertions**

Extend the main e2e scenario so that after logout:
- `POST /v1/auth/logout` returns success
- a follow-up authenticated request such as `GET /v1/devices` returns `401`
- the JSON error code is `revoked_access_token`

- [ ] **Step 2: Run the logout-focused test to verify it fails**

Run: `cargo test -p backend-e2e logout -- --nocapture`
Expected: FAIL because logout assertions are not yet implemented or response parsing is incomplete

- [ ] **Step 3: Implement the minimal follow-up request/assertion logic**

Add the smallest helper code needed to perform the revoked-token check and report response bodies on failure.

- [ ] **Step 4: Run the logout-focused test to verify it passes**

Run: `cargo test -p backend-e2e logout -- --nocapture`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/backend-e2e/tests/backend_oauth_e2e.rs
git commit -m "test: verify logout revocation end to end"
```

### Task 7: Add the local runner script

**Files:**
- Create: `scripts/run-backend-e2e.sh`

- [ ] **Step 1: Write the failing local runner**

Create the script with the intended command and strict env validation, then run it before the backend e2e target exists in final form if needed.

- [ ] **Step 2: Run the script to verify it fails only when expected**

Run: `bash scripts/run-backend-e2e.sh`
Expected: FAIL with a clear `TEST_DATABASE_URL is not set` message if the env var is absent

- [ ] **Step 3: Implement the final runner**

The script should:
- use `set -euo pipefail`
- require `TEST_DATABASE_URL`
- print which DB target it is using
- execute `cargo test -p backend-e2e -- --nocapture`

- [ ] **Step 4: Run the script with `TEST_DATABASE_URL` set to verify it passes**

Run: `TEST_DATABASE_URL=postgres://... bash scripts/run-backend-e2e.sh`
Expected: PASS once the e2e suite is green

- [ ] **Step 5: Commit**

```bash
git add scripts/run-backend-e2e.sh
git commit -m "chore: add backend e2e runner script"
```

### Task 8: Gate and run the suite in CI

**Files:**
- Modify: `.github/workflows/ci.yaml`

- [ ] **Step 1: Write the failing CI shape**

Add a new changed-path output for backend/auth-related paths and an `e2e-backend` job wired to it.

- [ ] **Step 2: Validate the workflow shape locally**

Run: `sed -n '1,260p' .github/workflows/ci.yaml`
Expected: The workflow shows:
- explicit path filter output for backend e2e
- explicit `if` guard on the job
- explicit Postgres service and `TEST_DATABASE_URL`

- [ ] **Step 3: Implement the full CI job**

The job should:
- run on `ubuntu-latest`
- depend on `changes`
- provision Postgres as a service container
- install Rust
- cache cargo
- run `scripts/run-backend-e2e.sh`

The path filter should include:
- `services/entry/**`
- `services/core/**`
- `crates/control-plane/**`
- `crates/domain/**`
- `crates/backend-e2e/**`
- `db/**`
- `scripts/run-backend-e2e.sh`

- [ ] **Step 4: Re-read the workflow to verify correctness**

Run: `sed -n '1,320p' .github/workflows/ci.yaml`
Expected: The new job and path filter are present, explicit, and consistent with repository workflow rules

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yaml
git commit -m "ci: run backend e2e suite for backend changes"
```

### Task 9: Update architecture and handoff docs

**Files:**
- Modify: `docs/architecture-plan.md`
- Modify: `docs/next-session.md`

- [ ] **Step 1: Write the failing docs delta**

Decide the exact wording needed to reflect:
- the new backend process-level e2e suite
- its OAuth stub coverage
- the local runner and CI gate

- [ ] **Step 2: Edit the docs**

Update:
- `docs/architecture-plan.md` testing strategy section to include the new suite
- `docs/next-session.md` current status and command guidance to include the new runner

- [ ] **Step 3: Verify the docs mention the right commands and scope**

Run: `rg -n "backend e2e|run-backend-e2e|OAuth stub|process-level" docs/architecture-plan.md docs/next-session.md`
Expected: Matches in both files with the new suite described accurately

- [ ] **Step 4: Commit**

```bash
git add docs/architecture-plan.md docs/next-session.md
git commit -m "docs: describe backend oauth e2e coverage"
```

### Task 10: Run repository validation before completion

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/backend-e2e/Cargo.toml`
- Modify: `crates/backend-e2e/src/lib.rs`
- Modify: `crates/backend-e2e/src/oauth_stub.rs`
- Modify: `crates/backend-e2e/src/process.rs`
- Modify: `crates/backend-e2e/src/catalog_fixture.rs`
- Modify: `crates/backend-e2e/src/http_client.rs`
- Modify: `crates/backend-e2e/tests/backend_oauth_e2e.rs`
- Modify: `scripts/run-backend-e2e.sh`
- Modify: `.github/workflows/ci.yaml`
- Modify: `docs/architecture-plan.md`
- Modify: `docs/next-session.md`

- [ ] **Step 1: Run formatting**

Run: `cargo fmt --all`
Expected: PASS

- [ ] **Step 2: Run workspace compile validation**

Run: `cargo check --workspace --exclude wg-windows-client`
Expected: PASS

- [ ] **Step 3: Run workspace library tests**

Run: `cargo test --workspace --lib --exclude wg-windows-client`
Expected: PASS

- [ ] **Step 4: Run the backend e2e suite**

Run: `scripts/run-backend-e2e.sh`
Expected: PASS

- [ ] **Step 5: Run the existing DB-backed repository suite**

Run: `scripts/run-db-integration-tests.sh`
Expected: PASS

- [ ] **Step 6: Commit final verification-backed changes**

```bash
git add Cargo.toml crates/backend-e2e scripts/run-backend-e2e.sh .github/workflows/ci.yaml docs/architecture-plan.md docs/next-session.md
git commit -m "test: add backend oauth end-to-end integration suite"
```
