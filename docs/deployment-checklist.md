# Deployment Checklist (VM-based)

## Preconditions
- Provision infra with Terraform:
  - `deploy/terraform/stacks/bootstrap-infra` (if GitHub OIDC and the entry node catalog bucket are not bootstrapped yet)
  - `deploy/terraform/stacks/entry-vm`
  - `deploy/terraform/stacks/core-vm`
- Environment templates available:
  - `deploy/env/entry.env.example`
  - `deploy/env/core.env.example`
- Google OAuth client configured for `entry`.
- TLS material available for `entry` <-> `core` gRPC.
- WireGuard private key available for `core`.

## Deploy
1. Publish rollout assets and references:
   - Upload the `entry` and `core` binaries to GCS and record the `gs://...` object paths.
   - Publish rendered environment payloads from `deploy/env/entry.env.example` and `deploy/env/core.env.example` to Secret Manager or GCS.
   - Publish TLS and WireGuard key material to Secret Manager when the startup templates need to fetch them.
2. Plan `entry` with Terraform:
   - GitHub Actions path: run `.github/workflows/entry-vm-cicd.yml` with `action=plan`, `rollout_artifact_ref`, and `rollout_env_ref`.
   - Optional workflow inputs: `rollout_artifact_sha256`, `rollout_unit_ref`, `rollout_core_ca_secret_ref`, `rollout_core_client_cert_secret_ref`, `rollout_core_client_key_secret_ref`.
   - Record the emitted `plan_run_id`.
3. Apply the saved `entry` plan:
   - Run `.github/workflows/entry-vm-cicd.yml` with `action=apply` and the `plan_run_id` from the planning run.
   - Set `region` to choose the GCP region for the VM; the workflow uses `<region>-a` as the zone.
4. Plan and apply `core` with Terraform:
   - Run `.github/workflows/core-vm-cicd.yml` with `action=plan`, `rollout_artifact_ref`, and `rollout_env_ref`.
   - Optional workflow inputs: `rollout_artifact_sha256`, `rollout_unit_ref`, `rollout_private_key_secret_ref`, `rollout_tls_cert_secret_ref`, `rollout_tls_key_secret_ref`, `rollout_tls_ca_secret_ref`.
   - Apply the exact saved plan with `action=apply` and the `plan_run_id` from the plan run.
   - For private VPC-only entry-to-core access, prefer internal DNS in the `entry` env payload (example: `https://wg-core-us-west.c.<project>.internal:50051`).
5. Maintain node metadata in the node catalog source consumed by `entry`:
   - Provide a node catalog entry through the blob catalog consumed by `entry`; `core` no longer registers itself into `entry` over HTTP.
   - If entry should route to discovered nodes on a non-default gRPC port, set `grpc_port` in the catalog entry or `APP_CORE_NODE_GRPC_PORT` in the `entry` env payload.
6. Bootstrap path:
   - `.github/workflows/bootstrap-infra.yml` provisions GitHub OIDC bootstrap resources and the required node catalog bucket.
   - The bootstrap workflow exposes only `action` and `adopt_existing`; other bootstrap values come from workflow defaults and repository context.
   - VM workflows require repository secrets `GCP_PROJECT_ID`, `GCP_WORKLOAD_IDENTITY_PROVIDER`, and `GCP_TERRAFORM_SA`.
   - Terraform is the supported VM deploy path for both `entry` and `core`.

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
