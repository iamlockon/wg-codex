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
1. Build binaries and deploy with VM helper:
   - `scripts/deploy-core-vm.sh --project <project-id> --vm-name <name> --zone <zone>`
2. If needed, pass production flags and secrets explicitly:
   - `--app-env production`
   - `--entry-admin-token <token>`
   - `--entry-jwt-signing-keys <kid:secret>`
   - `--google-oidc-client-id <id>`
   - `--google-oidc-client-secret <secret>`
   - `--google-oidc-redirect-uri <uri>`
3. Optional: register the node in a remote entry control plane:
   - `--register-node-in-entry true --entry-admin-url <url> --entry-node-region <region>`
   - Script now keeps `CORE_NODE_ID` stable per VM seed and configures `CORE_ENTRY_HEALTH_URL` + `ADMIN_API_TOKEN` in core env so health heartbeats keep node freshness updated.
   - If entry should route to discovered nodes on a non-default gRPC port, set `APP_CORE_NODE_GRPC_PORT` on entry.
4. GitHub Actions path (`.github/workflows/core-vm-cicd.yml`):
   - Add VM without touching Terraform stack state: `action=apply`, `provisioner=script`, unique `vm_name`.
   - `register_node_in_entry` defaults to `true`; set it to `false` to skip remote node registration.
   - Set `region` to choose GCP region for core VM; set `zone` only when you need a specific zone (otherwise defaults to `<region>-a`).
   - `entry_node_region` can override node metadata region in entry; if omitted it follows `region`.

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
   - `gcloud compute ssh <vm-name> --project "$PROJECT_ID" --zone "$ZONE" --command "sudo journalctl -u wg-entry -n 200 --no-pager"`
   - `gcloud compute ssh <vm-name> --project "$PROJECT_ID" --zone "$ZONE" --command "sudo journalctl -u wg-core -n 200 --no-pager"`
