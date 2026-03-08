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
- OAuth callback provider dispatch is now explicitly parsed via provider enum in `entry` (Google implemented; extension point ready for additional providers).
- OAuth security policy hardening:
  - `entry` now requires nonce and PKCE verifier by default in production (`APP_REQUIRE_OAUTH_NONCE=true`, `APP_REQUIRE_OAUTH_PKCE=true`).
  - readiness report includes both policy checks.
- Privacy retention policy hardening:
  - production startup now fails if configured retention exceeds policy caps (`APP_TERMINATED_SESSION_RETENTION_DAYS`, `APP_AUDIT_RETENTION_DAYS`, optionally bounded by `APP_MAX_TERMINATED_SESSION_RETENTION_DAYS` and `APP_MAX_AUDIT_RETENTION_DAYS`).
  - privacy policy and readiness endpoints report against configured policy caps rather than hardcoded thresholds.
- Audit event persistence wiring added:
  - OAuth login success/logout and session lifecycle events (start/reconnect/conflict/terminate) now persist `audit_events` records in Postgres when privacy store is configured.
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
- Linux dataplane now uses Rust-native WireGuard UAPI socket operations for peer add/remove.
- WireGuard device bootstrap (`private_key`, `listen_port`) is now also applied via Rust UAPI, removing `wg set` shell dependency.
- Reconciliation now inspects live peers via WireGuard UAPI and removes stale peers while re-applying desired peer state.
- Linux dataplane bootstrap now uses netlink for interface address/up and direct `/proc` write for IPv4 forwarding.
- NAT bootstrap in `core` now uses nft-based rule management path (legacy iptables branch removed), with `WG_NAT_DRIVER=cli|native` runtime selector.
- `native-nft` now programs nftables directly over netlink (`nftnl`) instead of shelling out to the `nft` binary.
- Core gRPC now includes node runtime status API:
  - `GetNodeStatus` reports health, active peers, nat driver mode, dataplane mode, and native feature support.
- `core` now supports optional node health heartbeat publishing to `entry` health endpoint.
- `core` now performs optional node registration (`POST /v1/admin/nodes`) from the VM startup health-reporter path when registration env vars are present (instead of GitHub runner-side registration).
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
  - `token_repo`: revocation expiry and purge behavior,
  - `oauth_repo`: identity idempotency, provider scoping, email update behavior, and race-safe parallel identity resolution,
  - `privacy_repo`: audit-event insert/list filters and retention purge behavior.
- Added API-level end-to-end integration coverage in `services/entry/src/main.rs` for:
  - bearer-authenticated logout + token revocation enforcement on follow-up API requests,
  - admin subscription updates driving session-start gating (`subscription_inactive`),
  - admin readiness/privacy endpoints (auth enforcement, policy payload, and privacy-store availability behavior).
- DB-backed integration suite runner is now green end-to-end via `scripts/run-db-integration-tests.sh` (all repository suites pass with current migrations).
- Recent stability fixes landed while validating integration tests:
  - `entry` test-build fixes for async test annotation and `Debug` derivations used by `expect_err`.
  - `node_repo` `upsert_node` SQL values/column count mismatch fixed.
  - `privacy_repo` integration test now seeds `customers` before FK-bound `audit_events` inserts.
  - `subscription_repo` eligibility query now uses `SELECT EXISTS(...)` (bool) to avoid `INT4`/`INT8` decode mismatch.
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
- Privacy audit export endpoint added:
  - `GET /v1/admin/privacy/audit-events` returns paginated audit events with optional `event_type` and `customer_id` filters.
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
  - `deploy/terraform/stacks/core-vm` stack and reusable `deploy/terraform/modules/core_vm` module for VM-based rollout.
  - `docs/deployment-checklist.md`
- CI workflow added (`.github/workflows/ci.yaml`):
  - Rust format/check/test on push/PR
  - includes explicit `cargo check -p core --features native-nft` gate.
  - VM rollout automation is available via:
    - `.github/workflows/entry-vm-cicd.yml` (entry),
    - `.github/workflows/core-vm-cicd.yml` (core),
    - plus manual checklist path in `docs/deployment-checklist.md`.
- Windows desktop client MVP scaffolding added:
  - `clients/windows-desktop/ui` contains typed backend contracts, API client, and initial session state model.
  - `clients/windows-desktop/src-tauri` now includes desktop-core implementation for auth/session orchestration, persisted local state, reconnect restoration, and tunnel-control abstraction.
  - Windows adapter layer now includes:
    - DPAPI-backed secure storage (`src-tauri/src/storage_windows.rs`) for auth-token persistence,
    - WireGuard-for-Windows command controller (`src-tauri/src/wireguard.rs`) for tunnel service install/uninstall, defaulting to bundled binary path (`<app dir>/wg-tools/wireguard.exe`) instead of host-installed WireGuard.
  - Bundling automation scripts added:
    - `clients/windows-desktop/scripts/stage-wireguard-runtime.ps1` stages runtime files into `clients/windows-desktop/wg-tools`,
    - `clients/windows-desktop/scripts/verify-wireguard-runtime.ps1` validates staged runtime shape.
  - Tauri-native bundling config added:
    - `clients/windows-desktop/src-tauri/tauri.conf.json` includes `../wg-tools/**` in bundle resources for MSI/NSIS outputs.
    - runtime lookup now supports Tauri resource layout (`<app dir>/resources/wg-tools/wireguard.exe`) in addition to direct app-relative path.
  - Full Tauri desktop UI flow implemented:
    - frontend app (`clients/windows-desktop/ui/index.html`, `clients/windows-desktop/ui/src/main.ts`, `clients/windows-desktop/ui/src/styles.css`) now drives login/device/session/logout flows,
    - Rust Tauri command layer in `clients/windows-desktop/src-tauri/src/main.rs` exposes end-to-end operations for UI invoke calls.
  - WireGuard config handling now prefers backend full config from `qr_payload` when it contains full `[Interface]`/`[Peer]` content.
  - desktop-core integration tests now cover login/device/connect/disconnect, logout revocation behavior, and reconnect-after-restart behavior against a mock `entry` API.

## Not Production-Ready Yet
- Product policy is intentionally one customer = one active session; plan/session semantics should remain aligned to that invariant.
- Subscription reporting is now present; pagination/filter semantics are basic and may need expansion for large-scale ops.
- Node pool/profile model is currently column-based (`pool`) and not yet a richer policy engine.
- mTLS enforcement exists and can be required; rollout in each environment still depends on secret/cert provisioning.
- Privacy policy enforcement is improved with runtime visibility and audit export API; richer conformance automation and external export sinks are still pending.
- Native NAT milestone completed:
  - `WG_NAT_DRIVER=native` selects a feature-gated path backed by `native-nft`,
  - native path ensures nft table/chain/masquerade rule setup via netlink under the feature gate.
- Native NAT rollout still requires environment validation before promoting it as the default runtime mode.

## Priority Next Steps
1. Run VM deployment validation end-to-end with `scripts/deploy-entry-vm.sh` (entry) and `scripts/deploy-core-vm.sh` (core) and confirm readiness/admin API behavior.
2. Validate `WG_NAT_DRIVER=native` in VM environments and, once stable, switch production default from `cli` to `native`.
3. Add auditable privacy policy toggles and retention/redaction conformance checks.
4. Expand subscription reporting semantics (count endpoints, richer filters, and export flows) for large-scale operations.
5. Run end-to-end Windows host validation (real WireGuard for Windows + DPAPI behavior), then harden packaging and signing for the shipped Tauri UI.

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
3. Check the current deployment target you are continuing (`docs/deployment-checklist.md` or `deploy/terraform/README.md`).
4. If continuing desktop work, inspect `clients/windows-desktop/src-tauri/src/main.rs` and `clients/windows-desktop/ui/src/main.ts` before changing behavior.

## Commands to Run Next Session
```bash
cargo fmt --all
cargo check --workspace
scripts/run-db-integration-tests.sh
```
Note: in restricted/sandboxed environments you may hit `Invalid cross-device link (os error 18)` during Rust `.rmeta` writes; if that occurs, rerun in the dev container or a local shell where the DB-backed test suite already passes.
