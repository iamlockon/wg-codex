# Windows Desktop Client MVP Implementation Status

## Goal
The Windows desktop MVP is implemented: it authenticates with Google, manages a selected device, starts/stops sessions against `entry`, and applies WireGuard tunnel config through the Tauri host.

## Current Backend Integration
The desktop client is wired to these public APIs:
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

## Implemented Client Stack
- App shell: `Tauri` (Rust + WebView) for Windows packaging, updater support, and native OS access.
- UI: React + TypeScript (small surface, fast iteration).
- Local secret storage:
  - token/session metadata encrypted with DPAPI (Windows user scope),
  - never persist plaintext OAuth/JWT tokens to logs/files.
- VPN control:
  - invoke WireGuard for Windows tunnel import/up/down via controlled command wrapper,
  - keep adapter naming deterministic (for reconnect/recovery).

## Current Client Behavior
1. Login + Token Session
- Browser-based Google OAuth launch from the UI.
- PKCE + nonce are generated client-side and returned to `entry` on callback.
- Returned access token is stored through the Tauri secure storage layer.
- Token refresh is not implemented; expiry still requires re-login.

2. Device Management
- The UI auto-registers a default device when none exists.
- The Tauri host generates and persists the local WireGuard private key for that device.
- The selected `device_id` is restored from local runtime state.

3. Connect/Disconnect
- Connect calls `POST /v1/sessions/start` with `device_id`, `region`, and optional `reconnect_session_key`.
- Handle `active` vs `conflict` response shapes.
- On `active`, the host prefers full config from `qr_payload` when present and otherwise builds the client config from the response fields.
- Disconnect calls `POST /v1/sessions/{session_key}/terminate` then brings tunnel down.

4. Session Recovery
- On app startup, call `GET /v1/sessions/current`.
- If active session exists, offer reconnect using existing `session_key`.
- Recover from local state drift (e.g., app crash while tunnel stayed up).

5. Auth Hardening Basics
- Attach bearer token on all customer endpoints.
- On `401` with revoked/invalid token, clear local auth and force re-login.
- Logout calls `POST /v1/auth/logout`, clears local secure storage, and tears down tunnel.

## Current UI Scope
- Google-only sign-in flow.
- Fixed region presets in the UI (`us-west1`, `us-central1`, `us-east1`, `europe-west1`, `asia-east1`).
- Restore-and-reconnect action on startup or user request.
- Logout clears persisted auth/runtime state and tears down the tunnel.

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

The client state model remains:
- `Unauthenticated`
- `AuthenticatedIdle`
- `Connecting`
- `Connected`
- `Disconnecting`
- `ErrorRecoverable`

## Remaining Gaps
1. No in-app admin tooling yet.
2. No advanced geo/pool selector beyond the fixed region dropdown.
3. No token refresh flow.
4. Real Windows host validation, packaging, and signing still need production-level verification.

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
