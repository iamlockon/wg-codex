# AGENTS.md

This file is the working contract for coding agents in this repository.

## Purpose

- Keep delivery fast without breaking product/security invariants.
- Make repo-wide changes predictable across Rust services, Terraform, and desktop client code.
- Require concrete validation before claiming a task is done.

## Architecture Snapshot

- Product: consumer privacy / geo-unblocking VPN control plane.
- Core services:
  - `services/entry`: public/admin API, OAuth, entitlement checks, session orchestration.
  - `services/core`: WireGuard peer lifecycle + dataplane/NAT + node status.
- Shared crates:
  - `crates/domain`: domain types.
  - `crates/control-plane`: protobuf + gRPC contracts (`vpn_control.proto`).
- Infra/deploy:
  - Terraform stacks under `deploy/terraform/stacks`.
  - VM deploy scripts under `scripts/`.
- Desktop client:
  - `clients/windows-desktop/ui` (Vite + TypeScript),
  - `clients/windows-desktop/src-tauri` (Rust/Tauri host).

## Non-Negotiable Invariants

- Session policy: one customer can have at most one active session.
- Reconnect contract:
  - matching reconnect key reuses the current session key;
  - non-matching/missing key returns conflict (no second active session).
- Do not weaken production guardrails in code or defaults:
  - entry/core TLS requirements,
  - OAuth nonce/PKCE requirements,
  - admin token enforcement,
  - strict log redaction and privacy retention constraints.
- Do not commit real secrets, service account keys, token values, or generated `.env` files.

## Repository Map

- Rust workspace root: `Cargo.toml` (edition 2024, workspace members declared there).
- Migrations: `db/migrations/`.
- Primary docs:
  - `docs/architecture-plan.md`
  - `docs/db-test-spec.md`
  - `docs/deployment-checklist.md`
  - `deploy/terraform/README.md`
- CI/CD workflows:
  - `.github/workflows/ci.yaml`
  - `.github/workflows/entry-vm-cicd.yml`
  - `.github/workflows/bootstrap-gcp-oidc.yml`

## Local Validation Baseline

Run these after meaningful code changes:

```bash
cargo fmt --all
cargo check --workspace
cargo test --workspace --lib --exclude wg-windows-client
```

DB-backed `entry` repository tests (requires `TEST_DATABASE_URL`):

```bash
scripts/run-db-integration-tests.sh
```

Notes:
- Devcontainer prewires `TEST_DATABASE_URL`; non-devcontainer shells must set it manually.
- CI also checks `core` with native nftables feature:
  - `cargo check -p core --features native-nft`

## Change Playbooks

### If touching `services/entry`

- Preserve auth/session/subscription/privacy semantics.
- If behavior changes, update tests near affected modules (for example `session_repo`, `postgres_session_repo`, `subscription_repo`, `token_repo`, `privacy_repo`).
- Re-run DB integration suite when SQL or repository logic changes.

### If touching `services/core`

- Keep dataplane modes (`WG_NAT_DRIVER=cli|native`) functional.
- Run:
  - `cargo check -p core`
  - `cargo check -p core --features native-nft`
- Avoid changes that silently relax TLS or production safety checks.

### If touching protobuf or shared contracts

- Edit `crates/control-plane/proto/vpn_control.proto` and propagate build/type impacts to both `entry` and `core`.
- Validate both services compile after changes.

### If touching migrations (`db/migrations`)

- Never rewrite historical migration files that may already be applied.
- Add a new migration for schema changes.
- Re-run DB-backed integration tests.

### If touching Terraform or deploy scripts

- Keep stack flow aligned with `deploy/terraform/README.md`.
- Preserve plan/apply safety model in workflows:
  - plan uploads `tfplan` artifact,
  - apply consumes a `plan_run_id` artifact.
- Use shared backend init script:
  - `scripts/terraform-init-gcs-backend.sh`

### If touching desktop client (`clients/windows-desktop`)

- Keep API contract compatibility with `entry` session/auth endpoints.
- Validate UI and host side:
  - `npm --prefix clients/windows-desktop/ui run typecheck`
  - `npm --prefix clients/windows-desktop/ui run build`
  - (when needed) `npm --prefix clients/windows-desktop run tauri:dev`
- Do not commit staged WireGuard runtime binaries under `wg-tools/` unless explicitly requested.

## Workflow Editing Rules

- Keep workflows deterministic and auditable:
  - explicit `if` conditions,
  - explicit env naming,
  - no implicit secret fallbacks that reduce security.
- Do not remove guard steps that enforce required inputs (for example `plan_run_id` checks).
- When editing `.github/workflows/*.yml`, verify YAML formatting and referenced script paths.

## Docs and Handoff Rules

- Update docs when behavior/ops contracts change (not just code):
  - API or policy behavior -> `docs/architecture-plan.md` and related docs.
  - deployment flow -> `docs/deployment-checklist.md` and/or `deploy/terraform/README.md`.
- Keep `docs/next-session.md` accurate for major architecture or workflow shifts so follow-on agents have current context.

## Practical Guardrails for Agents

- Prefer narrow, surgical changes over broad refactors unless explicitly requested.
- Do not rename services, stacks, or public env vars without updating all references and docs.
- Before finishing:
  - list what changed,
  - list what was validated,
  - explicitly call out anything not run/tested.
