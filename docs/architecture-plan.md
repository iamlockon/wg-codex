# Road Warrior VPN Architecture and Delivery Plan

## Scope and Decisions Locked
- Deployment model: `entry` and `core` are separate deployable services.
- Data store: Postgres.
- Customer authentication: OAuth (Google for v1, provider-agnostic model to extend later).
- Session policy: one active session per customer; new connect attempts return conflict with existing `session_key`.
- Reconnect policy: `session_key` is reusable for reconnect flows.
- Topology: multi-region, with explicit node selection.
- Client compatibility target: mobile and desktop from day 1, including QR payload in API responses.
- Cloud target: GCP.
- IP strategy: IPv4 egress in v1 for lower operational complexity and broad compatibility, with dual-stack-ready schema/config so IPv6 can be added without contract breaks.
- Security posture: high-security baseline aligned to 2026 expectations.

## Service Responsibilities

### `entry` service
- Public API surface for signup/login via OAuth.
- Customer/device lifecycle management.
- Session orchestration API (`start`, `terminate`, `status`).
- Enforces the customer-level single-active-session invariant.
- Persists customer/device/session intent and audit trail in Postgres.

### `core` service
- WireGuard control of Linux kernel interfaces/peers on VPN nodes.
- Provision and tear down peer sessions.
- Maintain node-local network egress setup (routing/NAT/firewall).
- Reconcile desired state from control-plane requests to actual kernel state.
- Emit node/session health and metrics.

## Inter-service Protocol Choice
Use **gRPC** between `entry` and `core`.
- Rationale: lower payload overhead than JSON REST in this service-to-service path, strict schema contracts, and built-in streaming patterns for future state/event channels.
- Security: mTLS + short-lived service identity certificates.

## High-level Request Flows

### Start Session
1. Client calls `entry` `POST /sessions/start` with `device_id`, `region`, and optional `node_hint`.
2. `entry` validates OAuth token and ownership of device.
3. `entry` checks active session constraint:
   - If active session exists and reconnect key matches, return active config.
   - If active session exists and reconnect key does not match, return conflict + existing `session_key`.
   - Else continue.
4. `entry` selects a node in requested region (capacity/health-aware).
5. `entry` calls `core.ConnectDevice` over gRPC.
6. `core` allocates tunnel IP, configures WG peer in kernel, applies routing/NAT linkage.
7. `core` returns session material (endpoint, server pubkey, assigned IP, DNS profile, keepalive, QR payload).
8. `entry` persists session as active and returns config payload to caller.

### Terminate Session
1. Client calls `entry` `POST /sessions/{session_key}/terminate`.
2. `entry` verifies ownership and active status.
3. `entry` calls `core.DisconnectDevice`.
4. `core` removes WG peer and frees IP allocation.
5. `entry` marks session terminated.

## Data Model (Postgres)
Core tables:
- `customers`
- `oauth_identities`
- `devices`
- `vpn_nodes`
- `sessions`
- `audit_events`

Key constraints:
- Partial unique index enforcing one active session per customer.
- Unique device public key per customer.
- Session key globally unique and opaque.

Session states:
- `requested`, `provisioning`, `active`, `terminating`, `terminated`, `failed`

## WireGuard + Linux Integration (`core`)
- Configure WG via Linux kernel interfaces (netlink/UAPI).
- One WG interface per node process (initially), peers per session.
- Per-session `AllowedIPs` mapping from managed internal CIDR pool.
- Egress through iptables/nftables NAT (final backend chosen per distro baseline).
- Enable IPv4 forwarding in v1 and keep interface/addressing abstractions dual-stack ready.
- Reconciliation loop on startup and periodic interval to recover drift.

## Multi-region and Node Selection
- Regions represented by `vpn_nodes.region`.
- Initial node selection strategy:
  - filter healthy nodes in region,
  - choose lowest load score (active peers, CPU, bandwidth budget),
  - fallback within region only (no silent cross-region failover unless requested).
- Return selected node metadata in session response for observability.

## Security Baseline (2026-Oriented)
- mTLS for all service-to-service traffic.
- OAuth/OIDC with PKCE for public clients.
- Short-lived access tokens, refresh token rotation, token binding where possible.
- Secrets from GCP Secret Manager with strict IAM-scoped access.
- Encrypt sensitive columns at application layer where justified.
- Strict RBAC for admin/operator APIs.
- Tamper-evident audit logging for auth/session/admin actions.
- Rate limiting + abuse detection per customer/device/IP.
- Defense-in-depth on node hosts:
  - minimal privileges/capabilities,
  - locked-down firewall defaults,
  - hardened kernel/sysctl profile,
  - regular key rotation and revocation workflows.
- Observability with security telemetry: auth anomalies, session churn anomalies, geo-policy violations.

## API Contract Sketch
Public (`entry`):
- `POST /v1/auth/oauth/{provider}/callback`
- `POST /v1/devices`
- `GET /v1/devices`
- `POST /v1/sessions/start`
- `POST /v1/sessions/{session_key}/terminate`
- `GET /v1/sessions/current`

Internal (`core`, gRPC target contract):
- `ConnectDevice(ConnectRequest) returns (ConnectResponse)`
- `DisconnectDevice(DisconnectRequest) returns (DisconnectResponse)`
- `GetSession(GetSessionRequest) returns (GetSessionResponse)`
- `NodeHealth(NodeHealthRequest) returns (NodeHealthResponse)`

## Delivery Phases
1. Workspace restructuring and crate/service skeleton (`entry`, `core`, shared contracts crate).
2. Postgres schema + migrations + single-session invariant.
3. `entry` OAuth auth + device/session APIs (Google first, generic provider model).
4. `core` WG kernel integration + connect/disconnect gRPC.
5. End-to-end session flow and conflict/reconnect contract (`existing_session_key`).
6. Multi-region node selection + health/load scoring.
7. Security hardening pass (mTLS, GCP secret management, rate limits, audit).
8. Integration/load/failure testing and production readiness checklist.

## Testing Strategy
- Unit tests for state transitions and uniqueness constraints.
- Integration tests for `entry` to `core` workflows.
- Linux netns-based tests for WG peer lifecycle and NAT behavior.
- Chaos/failure tests for `core` restart and reconciliation.
- Security tests: authz boundaries, token misuse, replay/idempotency.
