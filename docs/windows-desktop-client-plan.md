# Windows Desktop Client MVP Plan

## Goal
Ship a Windows desktop client (internal/beta quality) that authenticates users, manages devices, starts/stops VPN sessions, and applies WireGuard tunnel config from `entry`.

## Current Backend Readiness
The backend is ready for MVP client integration on these public APIs:
- `POST /v1/auth/oauth/{provider}/callback`
- `POST /v1/auth/logout`
- `POST /v1/devices`
- `GET /v1/devices`
- `POST /v1/sessions/start`
- `POST /v1/sessions/{session_key}/terminate`
- `GET /v1/sessions/current`

Constraints to honor:
- one customer = one active session (intentional product policy),
- session conflict contract (`status=conflict`, `existing_session_key`),
- subscription gating can reject session start (`subscription_inactive`),
- bearer token revocation is enforced after logout.

## Recommended Client Stack
- App shell: `Tauri` (Rust + WebView) for Windows packaging, updater support, and native OS access.
- UI: React + TypeScript (small surface, fast iteration).
- Local secret storage:
  - token/session metadata encrypted with DPAPI (Windows user scope),
  - never persist plaintext OAuth/JWT tokens to logs/files.
- VPN control:
  - invoke WireGuard for Windows tunnel import/up/down via controlled command wrapper,
  - keep adapter naming deterministic (for reconnect/recovery).

## MVP Features
1. Login + Token Session
- Browser-based OAuth launch.
- Exchange callback code via backend and store returned access token.
- Token refresh approach for MVP: re-login on expiry (no refresh token flow yet).

2. Device Management
- Register current machine as a device (`POST /v1/devices`).
- Cache selected `device_id` locally and validate with `GET /v1/devices`.

3. Connect/Disconnect
- Connect calls `POST /v1/sessions/start` with `device_id`, `region`, optional `reconnect_session_key`.
- Handle `active` vs `conflict` response shapes.
- On `active`, apply returned WireGuard config and raise tunnel.
- Disconnect calls `POST /v1/sessions/{session_key}/terminate` then brings tunnel down.

4. Session Recovery
- On app startup, call `GET /v1/sessions/current`.
- If active session exists, offer reconnect using existing `session_key`.
- Recover from local state drift (e.g., app crash while tunnel stayed up).

5. Auth Hardening Basics
- Attach bearer token on all customer endpoints.
- On `401` with revoked/invalid token, clear local auth and force re-login.
- Logout calls `POST /v1/auth/logout`, clears local secure storage, and tears down tunnel.

## Non-MVP (defer)
- In-app admin tooling (readiness/privacy/subscriptions).
- Multi-profile routing UX (fastest/streaming/privacy presets beyond simple region).
- Auto-update channels, code-signing pipeline hardening, installer telemetry funnels.
- Background service for always-on behavior.

## API Contract Notes for Client
- `POST /v1/sessions/start`:
  - request: `device_id`, `region`, optional geo hints and reconnect key,
  - success payload is tagged by `status`:
    - `active`: includes `session_key`, `region`, `config`,
    - `conflict`: includes `existing_session_key`, `message`.
- Error cases to explicitly map in UI:
  - `missing_bearer_token`, `invalid_access_token`, `revoked_access_token`,
  - `subscription_inactive`,
  - `region_not_allowed_by_plan`,
  - `unknown_device`,
  - `active_session_exists` (from conflict response semantics).

## Desktop Architecture
- `ui/` (frontend): screens/state machine.
- `src-tauri/` (backend host):
  - `auth.rs`: login/logout/token state.
  - `api.rs`: typed HTTP client for entry endpoints.
  - `wireguard.rs`: tunnel lifecycle wrapper.
  - `storage.rs`: DPAPI-backed secret persistence.
  - `session.rs`: connect/disconnect/reconnect orchestration.

State model:
- `Unauthenticated`
- `AuthenticatedIdle`
- `Connecting`
- `Connected`
- `Disconnecting`
- `ErrorRecoverable`

## Delivery Phases
1. Skeleton App
- Create Tauri workspace, typed API client, secure storage abstraction.

2. Auth + Device
- Implement login callback handling and device registration/list.

3. Connect/Disconnect
- Implement session start/terminate and WireGuard import/up/down.

4. Recovery + Polish
- Startup session reconciliation, conflict handling UI, error mapping.

5. Internal Beta Hardening
- Logging redaction checks, crash recovery paths, installer/uninstaller verification.

## Test Plan
- Unit tests:
  - API response parser for `active`/`conflict`,
  - local state transitions,
  - secure storage read/write error handling.
- Integration tests (desktop-side):
  - mock backend for auth/session error matrix,
  - connect/disconnect orchestration with fake WireGuard executor.
- Manual Windows validation:
  - fresh install, login, connect, disconnect, logout,
  - app restart while connected,
  - token revoked server-side then next API call.

## Exit Criteria (MVP)
- User can login, register/select device, connect by region, and disconnect reliably.
- Token revocation/logout behavior is correct.
- Reconnect flow works after app restart.
- No plaintext secret/token leakage in logs or local files.
