# Windows Desktop Client (MVP Scaffold)

This directory contains the Windows desktop client MVP core for integration with the `entry` backend.

## Layout

- `ui/`: TypeScript frontend contracts, API client, and session state model.
- `src-tauri/`: Rust host-side desktop core with auth/session orchestration, persistence, and tunnel-controller abstractions.

## MVP Scope

- OAuth callback token handoff.
- Device registration/list.
- Session start/current/terminate.
- Logout with token revocation behavior.

## Validation
- Desktop-core integration tests are in `src-tauri/src/session.rs` and cover:
  - login + device register/select + connect + disconnect,
  - logout revocation handling and local state clearing,
  - reconnect after app restart from persisted state.
- Storage non-plaintext assertion is in `src-tauri/src/storage.rs`.

## Runtime Adapters
- On Windows (`cfg(windows)`):
  - uses `DpapiFileSecureStorage` (`src-tauri/src/storage_windows.rs`) for token-at-rest protection.
  - uses `WireGuardWindowsController` (`src-tauri/src/wireguard.rs`) to run `wireguard.exe` install/uninstall tunnel-service commands.
  - default lookup is app-bundled binary path: `<app dir>/wg-tools/wireguard.exe` (no host-level WireGuard install required).
- On non-Windows:
  - uses obfuscated file storage + noop tunnel controller for local development.

Config env vars:
- `ENTRY_API_BASE_URL`
- `WG_WINDOWS_CLIENT_STATE_FILE` (optional explicit state path)
- `WG_WINDOWS_WIREGUARD_EXE` (optional override; otherwise uses bundled `<app dir>/wg-tools/wireguard.exe`)
- `WG_WINDOWS_CONFIG_DIR` (optional config file directory)
- `WG_WINDOWS_TUNNEL_NAME` (optional tunnel service name)

Bundling expectation:
- package `wireguard.exe` and required companion files under `wg-tools/` beside your app executable.
- sign bundled binaries as required by your release pipeline.

## Notes

- This is not wired into CI yet.
- Backend contract reference: `docs/windows-desktop-client-plan.md`.
