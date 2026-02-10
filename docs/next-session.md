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
- Node selection now requires fresh heartbeat data (`updated_at` within 60s) in addition to `healthy=true`.
- Node freshness threshold is configurable via `APP_NODE_FRESHNESS_SECS` (default `60`).
- `core` now has dataplane scaffolding with:
  - pluggable dataplane (`noop` and Linux shell-backed),
  - IPv4 pool allocation/release,
  - periodic reconciliation loop.
- Linux dataplane now uses Rust-native WireGuard UAPI socket operations for peer add/remove (host bootstrap/NAT still shell-based).
- WireGuard device bootstrap (`private_key`, `listen_port`) is now also applied via Rust UAPI, removing `wg set` shell dependency.
- Reconciliation now inspects live peers via WireGuard UAPI and removes stale peers while re-applying desired peer state.
- Linux dataplane bootstrap now uses netlink for interface address/up and direct `/proc` write for IPv4 forwarding.
- NAT backend is now configurable in `core` via `WG_NAT_BACKEND` (`iptables` default, `nft` optional).
- `core` now supports optional node health heartbeat publishing to `entry` health endpoint.
- TLS/mTLS hooks are now present for `entry`<->`core` gRPC:
  - optional server TLS in `core`,
  - optional client TLS and client cert in `entry`.
- OAuth callback now issues signed JWT access tokens (HS256) instead of dev string placeholders.
- Customer APIs now accept `Authorization: Bearer <token>` (signed by `APP_JWT_SIGNING_KEY`) with legacy `x-customer-id` fallback.
- Legacy `x-customer-id` fallback is now configurable via `APP_ALLOW_LEGACY_CUSTOMER_HEADER` (set false to require bearer token).
- JWT key rotation model added:
  - `APP_JWT_SIGNING_KEYS` as comma-separated `kid:secret` list,
  - optional `APP_JWT_ACTIVE_KID` to choose issuance key,
  - verification selects key by token header `kid`.
- Token revocation support added:
  - JWTs now include `jti`,
  - `POST /v1/auth/logout` revokes current bearer token `jti`,
  - bearer-authenticated API access rejects revoked tokens.
- Revocation persistence added:
  - `revoked_tokens` migration added,
  - Postgres-backed revocation checks/writes in `services/entry/src/token_repo.rs`,
  - in-memory revoked cache remains for fast-path checks.
- Expired revocation cleanup loop added in `entry` when Postgres token store is enabled.
- In-memory revoked cache now stores `jti -> exp` and prunes expired entries during auth checks.
- Added structured security/audit logs for OAuth login, logout, session start/reconnect/conflict/terminate.
- Added focused unit tests:
  - `entry`: stale node heartbeat filtering and expired revocation-cache eviction behavior.
  - `core`: `node_hint` UUID validation/propagation and disconnect behavior when no active session exists.
- Product direction updated: target is now **Consumer Privacy / Geo-Unblocking VPN** (not Road Warrior).

## Not Production-Ready Yet
- Plan/subscription/entitlement model is not implemented yet.
- Session policy is still effectively single-active-session per customer (not plan-driven).
- Node selection is region/load based only; no country/city/profile pool semantics yet.
- No service-to-service mTLS enforcement in active runtime path yet.
- Privacy policy enforcement is incomplete (retention/redaction/minimal logging controls need hardening).
- Remaining shell-based NAT path still exists (`iptables`/`nft` command execution).

## Priority Next Steps
1. Add subscription + entitlement schema (`plans`, `customer_subscriptions`, concurrency/device limits) and enforce in `entry` session start flow.
2. Extend node model to consumer geo semantics (country/city/pool profile) and update selection scoring accordingly.
3. Add integration tests against real Postgres + migrations for session, OAuth identity, node selection, and token revocation flows.
4. Move TLS materials and secrets to GCP Secret Manager + IAM policies; enforce mTLS by default between `entry` and `core`.
5. Replace remaining shell-based NAT rule management with Rust-native firewall handling (nftables/netlink integration).
6. Add privacy controls: bounded retention jobs, log redaction guarantees, and auditable policy toggles.

## Open Risks / Watch Items
- Reconnect semantics must remain tied to reusable `session_key` while preventing hijack/replay.
- Session transitions need idempotency keys across retries and partial failures.
- WG provisioning and DB state can diverge; reconciliation is mandatory.
- IPv4-first is selected; keep schema/config dual-stack-compatible for later IPv6 enablement.
- Consumer geo-unblocking reliability depends on pool quality and destination-specific routing behavior; selection policy must remain explicit and testable.

## Fast Restart Checklist (first 10 minutes)
1. Read `docs/architecture-plan.md` and this file.
2. Inspect current code:
   - `crates/control-plane/proto/vpn_control.proto`
   - `crates/control-plane/src/lib.rs`
   - `services/core/src/main.rs`
   - `services/entry/src/main.rs`
3. Review consumer-focused architecture targets and convert them to concrete schema/API migrations.
4. Start implementing subscription/entitlement enforcement in `entry` session start path.

## Commands to Run Next Session
```bash
cargo fmt --all
cargo check --workspace
```
Note: this environment currently fails Rust compilation with `Invalid cross-device link (os error 18)` while writing `.rmeta` files, so `cargo test/check` may fail despite valid source changes.
