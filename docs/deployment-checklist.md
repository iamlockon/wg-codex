# Deployment Checklist (VM-based)

## Preconditions
- Provision infra with Terraform:
  - `deploy/terraform/stacks/bootstrap-infra` (if GitHub OIDC and the entry node catalog bucket are not bootstrapped yet)
  - `deploy/terraform/stacks/entry-vm` (if you want Terraform-managed entry VM lifecycle)
- Environment templates available:
  - `deploy/env/entry.env.example`
  - `deploy/env/core.env.example`
- Google OAuth client configured for `entry`.
- TLS material available for `entry` <-> `core` gRPC.
- WireGuard private key available for `core`.

## Deploy
1. Deploy `entry` VM:
   - `scripts/deploy-entry-vm.sh --project <project-id> --vm-name <entry-vm-name> --zone <zone> --entry-app-env production --entry-database-url <database-url> --entry-admin-token <token> --entry-jwt-signing-keys <kid:secret> --entry-allow-legacy-customer-header false --entry-require-core-tls true --entry-core-grpc-url <https://core-host:50051> --entry-core-tls-domain <tls-domain> --google-oidc-client-id <id> --google-oidc-client-secret <secret> --google-oidc-redirect-uri <uri> --tls-mode upload --tls-ca-file <ca.pem>`
2. For entry production settings, pass explicit flags/secrets as needed:
   - `--entry-database-url <database-url>`
   - `--entry-core-grpc-url <https://core-host:50051>`
   - `--entry-core-tls-domain <tls-domain>`
   - `--entry-node-catalog-gcs-bucket <bucket>` and `--entry-node-catalog-gcs-object <object>` when using catalog-backed discovery
3. Deploy `core` VM on demand:
   - `scripts/deploy-core-vm.sh --project <project-id> --vm-name <core-vm-name> --zone <zone>`
   - For private VPC-only entry-to-core access, prefer internal DNS in `--entry-core-grpc-url` (example: `https://wg-core-us-west.c.<project>.internal:50051`).
4. Optional for core deploy:
   - Provide a node catalog entry through the blob catalog consumed by `entry`; `core` no longer registers itself into `entry` over HTTP.
   - If entry should route to discovered nodes on a non-default gRPC port, set `grpc_port` in the catalog entry or `APP_CORE_NODE_GRPC_PORT` on entry.
5. GitHub Actions paths:
   - `bootstrap`: `.github/workflows/bootstrap-infra.yml` provisions GitHub OIDC bootstrap resources and the required node catalog bucket.
   - `entry`: `.github/workflows/entry-vm-cicd.yml` deploys `entry` using `scripts/deploy-entry-vm.sh`.
   - Required repository secrets: `ENTRY_DATABASE_URL`, `ENTRY_JWT_SIGNING_KEYS`, `ENTRY_ADMIN_API_TOKEN`, `CORE_GRPC_TLS_CA_CERT_PEM`, `GOOGLE_OIDC_CLIENT_ID`, `GOOGLE_OIDC_CLIENT_SECRET`, `GOOGLE_OIDC_REDIRECT_URI`.
   - Required workflow inputs for apply: `core_grpc_url`, `core_tls_domain`.
   - Optional workflow inputs for catalog-backed discovery: `node_catalog_gcs_bucket`, `node_catalog_gcs_object`.
   - Add VM without touching Terraform stack state: `action=apply`, `provisioner=script`, unique `vm_name`.
   - Terraform-managed VM flow: run `provisioner=terraform`, `action=plan`, then run `provisioner=terraform`, `action=apply` with `plan_run_id` from that plan run.
   - Set `region` to choose GCP region for the VM; set `zone` only when you need a specific zone (otherwise defaults to `<region>-a`).
   - `core`: `.github/workflows/core-vm-cicd.yml` deploys `core` using `scripts/deploy-core-vm.sh`.
   - Maintain node metadata in the node catalog source consumed by `entry`; the GitHub runner and `core` do not call `POST /v1/admin/nodes`.

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
   - `GET /v1/admin/nodes` should show catalog nodes with recent `updated_at` values from gRPC health refresh
3. Verify logs on VM:
   - `gcloud compute ssh <entry-vm-name> --project "$PROJECT_ID" --zone "$ZONE" --command "sudo journalctl -u wg-entry -n 200 --no-pager"`
   - `gcloud compute ssh <core-vm-name> --project "$PROJECT_ID" --zone "$ZONE" --command "sudo journalctl -u wg-core -n 200 --no-pager"`
