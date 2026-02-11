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

## Notes

- This is not wired into CI yet.
- Backend contract reference: `docs/windows-desktop-client-plan.md`.
