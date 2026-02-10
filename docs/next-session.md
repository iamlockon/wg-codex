# Next Session Handoff

## Current Status
- Workspace has separate deployable services:
  - `services/entry`
  - `services/core`
  - shared crates `crates/domain`, `crates/control-plane`
- Initial architecture decisions documented in `docs/architecture-plan.md`.
- Initial Postgres schema added in `db/migrations/202602090001_initial_schema.sql`.
- `entry` has API skeletons for OAuth callback, devices, and session lifecycle.
- `core` now exposes a **gRPC** control plane (tonic) using protobuf contracts.
- `entry` now calls `core` over **gRPC** for connect/disconnect/session lookup.
- Postgres repository module implemented in `services/entry/src/postgres_session_repo.rs` using `sqlx` transactions and unique-index race handling.
- `entry` session handlers are now wired through a configurable session store:
  - Postgres backend when `DATABASE_URL` is set.
  - In-memory fallback when `DATABASE_URL` is not set.
- Google OAuth callback in `entry` now performs OIDC code exchange and ID token validation (JWKS signature + audience/issuer + optional nonce) via `services/entry/src/google_oidc.rs`.
- OAuth identity persistence is now wired:
  - `services/entry/src/oauth_repo.rs` resolves/creates `customers` + `oauth_identities` in Postgres.
  - `oauth_callback` now uses this repository when `DATABASE_URL` is set.
  - In-memory fallback store is used when Postgres is not configured.
- Node selection is now wired for `entry` start-session flow:
  - `services/entry/src/node_repo.rs` selects healthy nodes from `vpn_nodes` by region and load (`active_peer_count`).
  - `start_session` now auto-selects node in Postgres mode when `node_hint` is not provided.
  - Returns `no_nodes_available_in_region` if no healthy node exists in requested region.
- Node lifecycle and health APIs are now wired in `entry`:
  - `GET /v1/admin/nodes` lists nodes.
  - `POST /v1/admin/nodes` creates/updates node metadata.
  - `POST /v1/internal/nodes/health` updates `healthy` and `active_peer_count`.
  - These endpoints require `x-admin-token` matching `ADMIN_API_TOKEN`.
- `core` now has dataplane scaffolding with:
  - pluggable dataplane (`noop` and Linux shell-backed),
  - IPv4 pool allocation/release,
  - periodic reconciliation loop.
- `core` now supports optional node health heartbeat publishing to `entry` health endpoint.
- TLS/mTLS hooks are now present for `entry`<->`core` gRPC:
  - optional server TLS in `core`,
  - optional client TLS and client cert in `entry`.
- OAuth callback now issues signed JWT access tokens (HS256) instead of dev string placeholders.
- Customer APIs now accept `Authorization: Bearer <token>` (signed by `APP_JWT_SIGNING_KEY`) with legacy `x-customer-id` fallback.

## Not Production-Ready Yet
- No WireGuard kernel integration yet.
- No hardened authz/rate limits/audit integrity guarantees yet.
- No service-to-service mTLS yet.
- Access token in OAuth callback is still a dev placeholder.

## Priority Next Steps
1. Start `core` WireGuard integration using Linux kernel APIs (peer add/remove + reconciliation loop).
2. Move TLS materials and secrets to GCP Secret Manager + IAM policies (currently env/file based).
3. Add integration tests against real Postgres + migrations for `entry` session and OAuth/node flows.
4. Implement signing-key rotation and key-ID based verification for `entry` tokens.
5. Replace shell-command dataplane with direct netlink/WireGuard UAPI integration in Rust.

## Open Risks / Watch Items
- Reconnect semantics must remain tied to reusable `session_key` while preventing hijack/replay.
- Session transitions need idempotency keys across retries and partial failures.
- WG provisioning and DB state can diverge; reconciliation is mandatory.
- IPv4-first is selected; keep schema/config dual-stack-compatible for later IPv6 enablement.

## Fast Restart Checklist (first 10 minutes)
1. Read `docs/architecture-plan.md` and this file.
2. Inspect current code:
   - `crates/control-plane/proto/vpn_control.proto`
   - `crates/control-plane/src/lib.rs`
   - `services/core/src/main.rs`
   - `services/entry/src/main.rs`
3. Start DB repository wiring in `entry` and replace in-memory maps.

## Commands to Run Next Session
```bash
cargo fmt --all
cargo check --workspace
```
Note: dependency resolution still fails in this environment due blocked DNS/network access to crates.io.
