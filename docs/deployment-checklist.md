# Deployment Checklist (VM-based)

## Preconditions
- Provision infra with Terraform:
  - `deploy/terraform/stacks/bootstrap-oidc` (if GitHub OIDC is not bootstrapped yet)
  - `deploy/terraform/stacks/core-vm`
- Environment templates available:
  - `deploy/env/entry.env.example`
  - `deploy/env/core.env.example`
- Google OAuth client configured for `entry`.
- TLS material available for `entry` <-> `core` gRPC.
- WireGuard private key available for `core`.

## Deploy
1. Deploy `entry` VM:
   - `scripts/deploy-entry-vm.sh --project <project-id> --vm-name <entry-vm-name> --zone <zone>`
2. For entry production settings, pass explicit flags/secrets as needed:
   - `--entry-app-env production`
   - `--entry-admin-token <token>`
   - `--entry-jwt-signing-keys <kid:secret>`
   - `--google-oidc-client-id <id>`
   - `--google-oidc-client-secret <secret>`
   - `--google-oidc-redirect-uri <uri>`
3. Deploy `core` VM on demand:
   - `scripts/deploy-core-vm.sh --project <project-id> --vm-name <core-vm-name> --zone <zone> --entry-admin-url <entry-admin-base-url> --entry-admin-token <token>`
   - For private VPC-only access, use internal DNS with scheme (example: `http://wg-entry-gha.c.<project>.internal:8080`).
4. Optional for core deploy:
   - Register node in entry control plane: `--register-node-in-entry true --entry-node-region <region>`
   - If entry should route to discovered nodes on a non-default gRPC port, set `APP_CORE_NODE_GRPC_PORT` on entry.
5. GitHub Actions paths:
   - `entry`: `.github/workflows/entry-vm-cicd.yml` deploys `entry` using `scripts/deploy-entry-vm.sh`.
   - Add VM without touching Terraform stack state: `action=apply`, `provisioner=script`, unique `vm_name`.
   - Terraform-managed VM flow: run `provisioner=terraform`, `action=plan`, then run `provisioner=terraform`, `action=apply` with `plan_run_id` from that plan run.
   - Set `region` to choose GCP region for the VM; set `zone` only when you need a specific zone (otherwise defaults to `<region>-a`).
   - `core`: `.github/workflows/core-vm-cicd.yml` deploys `core` using `scripts/deploy-core-vm.sh`.
   - For `core` registration in entry, run `action=apply` with `register_node_in_entry=true`, set `entry_admin_url`, and provide `ENTRY_ADMIN_API_TOKEN` in repository secrets.
   - Registration is performed by `core` on VM startup; the GitHub runner does not call `POST /v1/admin/nodes`.

## Required production policy
- `entry`:
  - `APP_ENV=production`
  - `APP_REQUIRE_CORE_TLS=true`
  - `APP_REQUIRE_OAUTH_NONCE=true`
  - `APP_REQUIRE_OAUTH_PKCE=true`
  - `APP_ALLOW_LEGACY_CUSTOMER_HEADER=false`
  - `APP_LOG_REDACTION_MODE=strict` (or omitted; production defaults to strict)
  - `ADMIN_API_TOKEN` set
  - `APP_JWT_SIGNING_KEYS` or `APP_JWT_SIGNING_KEY` set (non-default)
- `core`:
  - `APP_ENV=production`
  - `CORE_DATAPLANE_NOOP=false`
  - `CORE_REQUIRE_TLS=true`
  - `WG_SERVER_PUBLIC_KEY` set

## Smoke checks
1. Check service health:
   - `curl http://<entry-host>/healthz`
2. Verify admin API:
   - `GET /v1/admin/readiness` should report `production_ready=true`
   - `GET /v1/admin/core/status`
   - `GET /v1/admin/privacy/policy`
   - `GET /v1/admin/nodes` should show healthy nodes with recent `updated_at`
3. Verify logs on VM:
   - `gcloud compute ssh <entry-vm-name> --project "$PROJECT_ID" --zone "$ZONE" --command "sudo journalctl -u wg-entry -n 200 --no-pager"`
   - `gcloud compute ssh <core-vm-name> --project "$PROJECT_ID" --zone "$ZONE" --command "sudo journalctl -u wg-core -n 200 --no-pager"`
