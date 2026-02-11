# Windows Desktop Client (MVP)

This directory contains the Windows desktop client MVP core for integration with the `entry` backend.

## Layout

- `ui/`: TypeScript frontend contracts, API client, and session state model.
- `src-tauri/`: Rust host-side desktop core with auth/session orchestration, persistence, and tunnel-controller abstractions.

## MVP Scope

- OAuth callback token handoff.
- Device registration/list.
- Session start/current/terminate.
- Logout with token revocation behavior.
- Tauri desktop UI flow for all above actions.

## Validation
- Desktop-core integration tests are in `src-tauri/src/session.rs` and cover:
  - login + device register/select + connect + disconnect,
  - logout revocation handling and local state clearing,
  - reconnect after app restart from persisted state.
- Storage non-plaintext assertion is in `src-tauri/src/storage.rs`.
- Tauri UI invokes Rust commands in `src-tauri/src/main.rs` for auth/device/session lifecycle.

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

## Bundling Flow (Tauri Native)
Use the included scripts and Tauri bundle resources on your Windows packaging machine:

1. Stage runtime from installed WireGuard (default source: `C:\Program Files\WireGuard`):
```powershell
pwsh -File clients/windows-desktop/scripts/stage-wireguard-runtime.ps1 -CleanDestination
```

2. Or stage from a custom extracted/runtime folder:
```powershell
pwsh -File clients/windows-desktop/scripts/stage-wireguard-runtime.ps1 -SourcePath "D:\artifacts\WireGuard" -CleanDestination
```

3. Verify staged runtime:
```powershell
pwsh -File clients/windows-desktop/scripts/verify-wireguard-runtime.ps1
```

4. Build via Tauri (resources auto-included from `src-tauri/tauri.conf.json`):
```powershell
cd clients/windows-desktop
npm install
npm run tauri:build
```

This bundles `../wg-tools/**` into the installer artifacts.

Notes:
- `clients/windows-desktop/wg-tools` is intentionally git-ignored for binaries.
- Runtime lookup in code supports both:
  - `<app dir>/wg-tools/wireguard.exe`
  - `<app dir>/resources/wg-tools/wireguard.exe` (Tauri bundle resource layout)

## Local UI Development
1. Install desktop and UI dependencies:
```bash
cd clients/windows-desktop
npm install
npm --prefix ui install
```

2. Start Tauri desktop app in dev mode:
```bash
npm run tauri:dev
```

3. Use the in-app flow:
- paste OAuth callback code and click `Login`,
- register/select device,
- connect/disconnect,
- logout or restore+reconnect.

## Notes

- This is not wired into CI yet.
- Backend contract reference: `docs/windows-desktop-client-plan.md`.
