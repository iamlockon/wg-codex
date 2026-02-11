# Consumer Privacy / Geo-Unblocking VPN Architecture and Delivery Plan

## Scope and Decisions Locked
- Deployment model: `entry` and `core` are separate deployable services.
- Data store: Postgres.
- Customer authentication: OAuth (Google for v1, provider-agnostic model to extend later).
- Inter-service protocol: gRPC (`entry` to `core`) for low overhead and strict contracts.
- Cloud target: GCP.
- Topology: multi-region with node selection.
- Client compatibility target: mobile and desktop from day 1.
- Security posture: high-security baseline aligned to 2026 expectations.
- Product shift: this system targets consumer privacy and geo-unblocking, not enterprise road-warrior remote access.

## Product Goals
- Privacy-first consumer VPN experience (simple connect, country/city targeting, low trust surface).
- Geo-targeted exit routing with stable regional pools.
- Scalable session orchestration across many users and nodes.
- Minimized and controlled metadata retention.

## Service Responsibilities

### `entry` service
- Public APIs for OAuth login, device management, and session lifecycle.
- Plan/entitlement enforcement (device limits, allowed regions/features).
- Node pool selection by user intent (`fastest`, `country`, `city`, `streaming profile`, manual node where allowed).
- Session orchestration with a strict one-customer-one-active-session policy and reconnect behavior.
- Privacy-aware storage of customer, device, session, and audit metadata.

### `core` service
- WireGuard control of Linux kernel interfaces/peers on VPN nodes.
- Peer provisioning and teardown for high-concurrency consumer traffic.
- Node egress management (routing, NAT/firewall, capacity gates).
- Reconciliation between desired session state and actual kernel state.
- Health and capacity reporting back to control-plane.

## Inter-service Security
- mTLS between `entry` and `core` with short-lived service identities.
- Authenticated internal health/reporting endpoints only.
- Strict admin API token handling now; migrate to workload identity + signed internal auth.

## High-level Request Flows

### Start Session (consumer)
1. Client calls `entry` `POST /v1/sessions/start` with `device_id`, selection hint (`region` and optional `node_hint`), and optional reconnect token.
2. `entry` validates bearer token, plan eligibility, and device ownership.
3. `entry` applies concurrency policy for the plan:
   - If an active session exists and reconnect token does not match, return conflict with existing `session_key`.
   - If reconnect token matches an active session, reuse session contract.
4. `entry` selects node from fresh, healthy pool in requested geo bucket.
5. `entry` calls `core.ConnectDevice` via gRPC.
6. `core` allocates tunnel IP, programs WireGuard peer via kernel UAPI, and returns connection config.
7. `entry` persists/updates session state and returns config payload.

### Terminate Session
1. Client calls `POST /v1/sessions/{session_key}/terminate`.
2. `entry` validates ownership and current state.
3. `entry` calls `core.DisconnectDevice`.
4. `core` removes peer and frees IP allocation.
5. `entry` marks session terminated and emits audit event.

## Data Model (Postgres)
Current core tables (already present):
- `customers`
- `oauth_identities`
- `devices`
- `vpn_nodes`
- `sessions`
- `audit_events`
- `revoked_tokens`

Needed additions for consumer VPN:
- `plans` and `customer_subscriptions`
- `plan_entitlements` (device limits and regional feature gates)
- `node_pools` and `node_pool_membership` (general, low-latency, streaming-optimized)
- `session_events` (connect/disconnect/reconnect/fail with bounded retention)
- optional `egress_ips` mapping for managed pool observability

Session states:
- `requested`, `provisioning`, `active`, `terminating`, `terminated`, `failed`

## Node Selection Model (Consumer)
- Selection must be user-intent aware:
  - by `country`/`city`,
  - by profile (`fastest`, `general`, `streaming`, `privacy-max`),
  - explicit node only for advanced flows.
- Candidate filtering:
  - healthy,
  - heartbeat fresh,
  - under capacity and policy thresholds.
- Scoring:
  - weighted load score (`active peers`, `cpu`, `bw budget`, optional latency signal),
  - stickiness option for reconnect quality.
- No silent cross-country failover; explicit policy-controlled fallback only.

## WireGuard + Linux Integration (`core`)
- Configure WireGuard peers through Linux kernel UAPI.
- Maintain one interface per node process initially, peers per session.
- Allocate per-session internal IPs from managed pool.
- NAT setup currently supports `WG_NAT_DRIVER=cli|native`:
  - `cli`: nft CLI rule management (current stable path),
  - `native`: feature-gated Rust-native milestone hook (`native-nft`) for phased rollout.
- Reconciliation loop removes stale peers and re-applies desired state.
- Capacity admission guard before provisioning peer.

## Privacy and Security Baseline (2026)
- OIDC-based login with short-lived access tokens and rotation-ready signing keys.
- Token revocation (`jti`) with in-memory fast path + persistent checks.
- Principle of least data:
  - do not log destination domains/IPs,
  - short retention for session metadata,
  - redact sensitive identifiers in logs.
- GCP Secret Manager for secrets and key material.
- Runtime supports `*_FILE` secret loading for key/token/OIDC values to align with mounted secret workflows.
- Strict RBAC for admin/internal endpoints.
- Security telemetry for abuse, auth anomalies, and suspicious session churn.

## API Contract Direction
Public (`entry`):
- `POST /v1/auth/oauth/{provider}/callback`
- `POST /v1/auth/logout`
- `POST /v1/devices`
- `GET /v1/devices`
- `POST /v1/sessions/start`
- `POST /v1/sessions/{session_key}/terminate`
- `GET /v1/sessions/current`

Admin/Internal (`entry`):
- `GET /v1/admin/nodes`
- `GET /v1/admin/privacy/policy`
- `GET /v1/admin/core/status`
- `GET /v1/admin/readiness`
- `POST /v1/admin/nodes`
- `POST /v1/admin/subscriptions`
- `GET /v1/admin/subscriptions`
- `GET /v1/admin/subscriptions/{customer_id}`
- `GET /v1/admin/subscriptions/{customer_id}/history`
- `POST /v1/internal/nodes/health`

Internal gRPC (`core`):
- `ConnectDevice`
- `DisconnectDevice`
- `GetSession`
- `GetNodeStatus`

## Migration From Previous Road-Warrior Framing
What can stay:
- Two-service architecture (`entry`, `core`).
- gRPC control plane.
- OAuth foundation.
- Node health and selection primitives.
- WireGuard kernel/UAPI integration direction.

What must change:
- Introduce geo/pool semantics beyond raw region.
- Add consumer subscription/entitlement checks in session start flow.
- Tighten privacy controls and retention defaults as first-class requirements.
- Add anti-abuse controls (rate limits, fraud signals, noisy-tenant isolation).

## Delivery Phases (Updated)
1. Product model migration: subscription and entitlement schema + APIs.
2. Node pool model: region/country/city and profile-based selection.
3. Session policy lock: keep strict one-customer-one-active-session semantics while applying plan device/region controls.
4. Privacy hardening: retention, redaction, and audit policy enforcement.
5. Security hardening: mTLS rollout, secret manager integration, admin auth hardening.
6. Dataplane maturity: nft-native firewall path and capacity guardrails.
7. Integration/load/failure testing and production readiness checklist.

## Testing Strategy
- Unit tests for policy enforcement (plan limits, geo eligibility, conflict behavior).
- Integration tests for `entry` to `core` session lifecycle with Postgres.
- Linux netns tests for WireGuard peer lifecycle and NAT behavior.
- Reconciliation/failure tests for `core` restarts and drift repair.
- Security tests for token revocation, auth boundaries, replay/idempotency.
