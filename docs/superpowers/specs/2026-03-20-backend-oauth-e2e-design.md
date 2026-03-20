# Backend OAuth E2E Integration Suite Design

## Goal

Create a local and CI integration test suite that validates backend end-to-end flows across `entry`, `core`, Postgres, and a stub OAuth provider. The suite must exercise the real `POST /v1/auth/oauth/google/callback` path, verify session lifecycle behavior, and confirm revoked-token enforcement after logout.

## Scope

Included in the first version:
- real `entry` process
- real `core` process
- Postgres-backed state using `TEST_DATABASE_URL`
- stub OAuth token endpoint
- stub JWKS endpoint
- real HTTP requests into `entry`
- real gRPC calls from `entry` to `core`
- session lifecycle and reconnect semantics
- logout and revoked-token enforcement
- local runner and CI job
- CI path gating for backend/auth-related changes

Explicitly excluded from the first version:
- desktop client flows
- real Google OAuth calls
- production TLS or mTLS coverage
- Terraform or VM deployment validation
- dataplane-specific assertions beyond what current local `core` can support safely

## Why This Suite Exists

Current coverage is split between:
- repository-level Postgres integration tests such as [scripts/run-db-integration-tests.sh](/home/jay/code/wg-codex/scripts/run-db-integration-tests.sh)
- in-process API tests in [services/entry/src/main.rs](/home/jay/code/wg-codex/services/entry/src/main.rs)

Those tests are useful, but they do not give a dedicated process-level end-to-end check that proves:
- runtime env wiring is correct
- `entry` can complete OAuth exchange against a configured provider
- JWT issuance and revocation behave correctly across real HTTP requests
- `entry` can discover and talk to a running `core`
- session policy invariants still hold across the full backend stack

## Recommended Approach

Use a process-level harness that starts the backend stack as real OS processes and drives the system through public HTTP endpoints.

Why this approach:
- stronger fidelity than in-process handler tests
- lower operational weight than Docker compose
- directly reusable for both local development and GitHub Actions
- validates the exact runtime configuration seams that are most likely to drift

## Architecture

### Components

The suite will stand up four components per test run:

1. Postgres
   - external dependency supplied via `TEST_DATABASE_URL`
   - reused from existing DB-backed test conventions

2. Stub OAuth server
   - local HTTP server started by the harness
   - serves:
     - `POST /token`
     - `GET /jwks`
   - signs RS256 ID tokens with a generated private key and stable `kid`

3. `core`
   - real binary process started on an ephemeral localhost port
   - configured in a safe local mode compatible with CI and non-privileged environments

4. `entry`
   - real binary process started on an ephemeral localhost port
   - configured to use:
     - Postgres from `TEST_DATABASE_URL`
     - stub OAuth token and JWKS URLs
     - local JWT signing config
     - local admin token
     - local node catalog fixture pointing at the spawned `core`

### Harness Shape

The harness should live in a dedicated Rust integration crate or test-only package under the workspace rather than expanding [services/entry/src/main.rs](/home/jay/code/wg-codex/services/entry/src/main.rs) further. Its responsibilities are:
- allocate ports
- generate temp files and fixture config
- start and stop child processes
- wait for readiness
- send HTTP requests and assert responses
- clean up temp state

This keeps production crates focused and keeps end-to-end logic separate from unit and in-process integration tests.

## Data Flow

### Login and session flow

1. Harness starts stub OAuth server and exposes `token_url` and `jwks_url`.
2. Harness starts `core`.
3. Harness writes a node catalog fixture that references the local `core` gRPC address.
4. Harness starts `entry` with Google OIDC env vars pointed at the stub server.
5. Test client calls `POST /v1/auth/oauth/google/callback`.
6. `entry` performs a real HTTP token exchange against the stub provider.
7. `entry` fetches JWKS from the stub provider and validates the RS256 ID token.
8. `entry` resolves or creates the customer in Postgres and returns a signed access token.
9. Test client uses that access token for device registration and session lifecycle requests.
10. `entry` selects the local node and calls `core` over gRPC for session provisioning.
11. Test client logs out.
12. A follow-up authenticated request must fail with revoked-token enforcement.

## Test Cases

The first version should implement one end-to-end scenario file with a small number of high-value test cases.

### Case 1: OAuth login, device registration, session start, current session, terminate

Assertions:
- OAuth callback succeeds through the stub provider
- returned token authorizes `POST /v1/devices`
- subscription setup allows session start
- `POST /v1/sessions/start` returns runtime config and `session_key`
- `GET /v1/sessions/current` returns the active session
- `POST /v1/sessions/{session_key}/terminate` succeeds

### Case 2: reconnect with matching reconnect key reuses the active session

Assertions:
- second start request with matching reconnect key succeeds
- returned `session_key` matches the original active session
- no second active session is created
- `entry` does not violate the one-customer-one-active-session policy

### Case 3: reconnect without or with mismatched reconnect key returns conflict

Assertions:
- start request without matching reconnect key returns conflict
- conflict payload includes the existing `session_key`
- active session remains unchanged

### Case 4: logout revokes token

Assertions:
- `POST /v1/auth/logout` succeeds
- a follow-up authenticated request such as `GET /v1/devices` fails with `revoked_access_token`

## Setup Strategy

### Subscription setup

The suite should use the existing admin API rather than direct DB seeding for plan activation. That keeps the test end-to-end and covers auth-sensitive setup behavior already exposed by the product.

Flow:
- login through OAuth callback
- read returned `customer_id`
- call `POST /v1/admin/subscriptions` with the configured admin token
- assign an active or trialing plan that allows the target region

### Node catalog setup

The harness should generate a temporary node catalog file containing one local node with:
- valid node UUID
- region, country, city, and pool metadata
- gRPC endpoint for the spawned `core`
- capacity metadata sufficient for selection

`entry` should consume this through its existing catalog config path, not through in-memory shortcuts.

### Process readiness

The harness should not rely on fixed sleeps. It should:
- poll `entry` public or admin endpoints until they respond
- poll `core` gRPC status through either direct gRPC or `entry` readiness if simpler
- fail fast with captured stdout and stderr if a process exits unexpectedly

## CI Design

Add a dedicated GitHub Actions job in [ci.yaml](/home/jay/code/wg-codex/.github/workflows/ci.yaml) with explicit changed-path gating.

### Path filters

The e2e job should run only when these areas change:
- `services/entry/**`
- `services/core/**`
- `crates/control-plane/**`
- `crates/domain/**`
- `db/**`
- `scripts/run-backend-e2e.sh`
- backend e2e harness files

This aligns with the requested scope: backend and auth-related changes only.

### CI job behavior

The CI job should:
- check out the repo
- install Rust
- provision Postgres as a service container
- set `TEST_DATABASE_URL`
- run the backend e2e command

The job should be explicit and auditable:
- explicit `if` condition from path-filter output
- explicit environment variable setup
- no implicit fallbacks for secrets or config

## Local Developer Experience

Provide a single command, likely a new script such as `scripts/run-backend-e2e.sh`, that:
- verifies `TEST_DATABASE_URL` is set
- runs the dedicated e2e test target

This should mirror CI so local failures are reproducible.

## Failure Handling and Diagnostics

The harness must surface useful diagnostics when a test fails:
- child process stdout and stderr
- effective local URLs and ports
- HTTP response bodies for assertion failures
- clear distinction between readiness failure, transport failure, and contract failure

This matters because process-level failures are otherwise expensive to debug in CI.

## Security and Invariant Guardrails

This suite must preserve current product constraints.

It must confirm:
- OAuth nonce and PKCE are still required where policy says they are required
- admin token enforcement remains intact
- one customer cannot create a second active session
- matching reconnect key reuses the existing session
- missing or mismatched reconnect key returns conflict
- logout revokes the bearer token

It must not:
- relax production defaults
- introduce bypass-only test code into runtime paths
- embed real secrets

## File Plan

Expected additions or modifications:
- new backend e2e harness under a dedicated workspace path
- new temporary fixture helpers for stub OAuth and node catalog setup
- new runner script under `scripts/`
- `.github/workflows/ci.yaml` changes for path filtering and e2e job
- doc updates in:
  - [docs/architecture-plan.md](/home/jay/code/wg-codex/docs/architecture-plan.md)
  - [docs/next-session.md](/home/jay/code/wg-codex/docs/next-session.md)

## Testing Strategy

Implementation should follow TDD:
- add the failing e2e harness test first
- verify it fails for the expected missing harness reason
- add only enough harness and fixture code to make the first scenario pass
- expand incrementally to reconnect and revocation coverage

Validation target after implementation:
- `cargo fmt --all`
- `cargo check --workspace --exclude wg-windows-client`
- `cargo test --workspace --lib --exclude wg-windows-client`
- backend e2e runner command
- existing DB-backed repository suite via [scripts/run-db-integration-tests.sh](/home/jay/code/wg-codex/scripts/run-db-integration-tests.sh)

## Risks

### Local `core` runtime assumptions

If `core` startup requires privileged networking or host features that are not safe in CI, the harness must use the repo’s safe local mode rather than production-like dataplane behavior. The suite is intended to validate backend orchestration, not Linux kernel integration.

### OAuth stub correctness

The stub must behave closely enough to the current Google OIDC expectations:
- RS256 token
- valid `kid`
- matching `aud`
- accepted issuer
- optional nonce included for the happy path

### Flaky startup timing

Most flake risk will come from process readiness and port coordination. The harness design should centralize startup and teardown to keep this deterministic.

## Success Criteria

The design is successful when:
- one local command runs the backend OAuth e2e suite
- CI runs the suite only for backend/auth-related changes
- the suite proves the OAuth callback, session lifecycle, reconnect semantics, and logout revocation behavior through real processes
- failures are diagnosable without reproducing them manually first
