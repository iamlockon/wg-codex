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
- NAT bootstrap in `core` now uses nft-based rule management path (legacy iptables branch removed), with `WG_NAT_DRIVER=cli|native` runtime selector.
- Core gRPC now includes node runtime status API:
  - `GetNodeStatus` reports health, active peers, nat driver mode, dataplane mode, and native feature support.
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
- Consumer model schema migration added:
  - `plans`, `customer_subscriptions`,
  - node geo/pool/capacity metadata on `vpn_nodes`.
- `entry` now enforces subscription entitlements:
  - device registration respects `max_devices`,
  - session start validates region against `allowed_regions`,
  - session start requires active/trialing subscription status.
- Admin subscription endpoint added:
  - `POST /v1/admin/subscriptions` updates customer plan/status.
  - `GET /v1/admin/subscriptions` lists latest subscription snapshots with filter/pagination.
  - `GET /v1/admin/subscriptions/{customer_id}` returns latest plan/status snapshot.
  - `GET /v1/admin/subscriptions/{customer_id}/history` returns customer subscription timeline.
- Subscription status transition logic in Postgres is now transactional:
  - previous active/trialing rows are closed before inserting the new status row.
- Added repository-level integration tests in `subscription_repo.rs` (gated by `TEST_DATABASE_URL`) for:
  - entitlement retrieval after plan assignment,
  - eligibility drop after cancellation.
- Added repository-level integration tests (gated by `TEST_DATABASE_URL`) for:
  - `postgres_session_repo`: conflict and terminate-key invariants,
  - `node_repo`: geo/pool/capacity-aware selection behavior,
  - `token_repo`: revocation expiry and purge behavior.
- `entry` node selection now supports consumer filters (`region`, `country_code`, `city_code`, `pool`) and capacity-aware scoring.
- Privacy metadata cleanup worker added in `entry` for terminated sessions and audit events (retention env-configurable).
- TLS enforcement toggles added:
  - `APP_REQUIRE_CORE_TLS` in `entry` client startup,
  - `CORE_REQUIRE_TLS` in `core` server startup.
- Production startup guardrails added:
  - `entry` fails fast in `APP_ENV=production` if DB/JWT/admin token/TLS/OIDC requirements are not satisfied.
  - `core` fails fast in `APP_ENV=production` if noop dataplane is enabled, TLS is not required, or server key is unset.
- Log redaction controls added in `entry`:
  - sensitive audit fields (customer/session/token identifiers) are redacted in logs,
  - `APP_LOG_REDACTION_MODE` supports `off|partial|strict` and production requires `strict`.
- Privacy policy admin endpoint added:
  - `GET /v1/admin/privacy/policy` returns effective retention/redaction config and compliance hints.
- Core status admin endpoint added:
  - `GET /v1/admin/core/status` proxies `GetNodeStatus` for control-plane observability checks.
- Readiness admin endpoint added:
  - `GET /v1/admin/readiness` aggregates production guardrails and live core status into a single deployment gate signal.
- File-backed secret loading added for sensitive runtime config:
  - `entry`: `DATABASE_URL`, `ADMIN_API_TOKEN`, `APP_JWT_SIGNING_KEYS`/`APP_JWT_SIGNING_KEY`, and Google OIDC credentials now support `*_FILE`.
  - `core`: `WG_SERVER_PUBLIC_KEY` and health-reporter `ADMIN_API_TOKEN` now support `*_FILE`.
- Deployment assets added:
  - `services/entry/Dockerfile`
  - `services/core/Dockerfile`
  - `deploy/k8s/*` manifests (namespace, configmaps, secrets examples, entry deployment, core daemonset, migration job)
  - `deploy/k8s/base` + `deploy/k8s/overlays/{dev,prod}` kustomize structure for one-command deploy per env
  - prod SealedSecret placeholders in `deploy/k8s/overlays/prod`
  - `deploy/k8s/smoke-check.sh` automated post-deploy gate using health/privacy/core/readiness endpoints
  - `docs/deployment-checklist.md`
- CI workflow added (`.github/workflows/ci.yaml`):
  - Rust format/check/test on push/PR
  - kustomize render validation for `dev`, `prod`, and `prod-native-canary` overlays
- Kubernetes manifests now mount sensitive materials from secrets:
  - `entry` reads admin/JWT/OIDC via `*_FILE` paths and mounts `core-grpc-client-tls`.
  - `core` mounts `core-tls` and `wireguard-keys`, and reads admin/WG public key via `*_FILE`.
  - prod overlay now includes sealed-secret placeholders for `core-tls`, `core-grpc-client-tls`, and `wireguard-keys`.

## Not Production-Ready Yet
- Product policy is intentionally one customer = one active session; plan/session semantics should remain aligned to that invariant.
- Subscription reporting is now present; pagination/filter semantics are basic and may need expansion for large-scale ops.
- Node pool/profile model is currently column-based (`pool`) and not yet a richer policy engine.
- mTLS enforcement exists and can be required; rollout in each environment still depends on secret/cert provisioning.
- Privacy policy enforcement is improved with runtime visibility; formal conformance checks and audit exports are still pending.
- Native NAT milestone hook added:
  - `WG_NAT_DRIVER=native` selects a feature-gated path backed by `native-nft`,
  - current native hook is intentionally fail-fast until netlink nftables programming is fully wired.
- Canary rollout assets added for native NAT:
  - `deploy/k8s/overlays/prod-native-canary` switches `WG_NAT_DRIVER=native` and canary image tag,
  - rollback path is `kubectl apply -k deploy/k8s/overlays/prod`.

## Priority Next Steps
1. Add integration tests against real Postgres + migrations for subscription entitlements, single-session lifecycle, node selection, and token revocation flows.
2. Wire GCP Secret Manager sync/CSI mounting in manifests so `*_FILE` paths are used by default; keep `APP_REQUIRE_CORE_TLS` and `CORE_REQUIRE_TLS` enforced in deployed environments.
3. Complete `native-nft` implementation (netlink nftables programming) and switch production from `WG_NAT_DRIVER=cli` to `native` after validation.
4. Add auditable privacy policy toggles and retention/redaction conformance checks.
5. Expand subscription reporting semantics (count endpoints, richer filters, and export flows) for large-scale operations.

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
