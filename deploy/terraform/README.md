# Terraform Stacks

Kubernetes/GKE Terraform assets were removed. The remaining Terraform deployment paths are stack-based:

- `deploy/terraform/stacks/entry-vm`
  - Creates infrastructure and startup metadata for the `entry` VM via `modules/entry_vm`.
- `deploy/terraform/stacks/core-vm`
  - Creates infrastructure and startup metadata for the `core` VM via `modules/core_vm`.
- `deploy/terraform/stacks/bootstrap-infra`
  - Bootstraps GitHub Actions -> GCP Workload Identity Federation, writes required repository secrets, and creates the required node catalog bucket for `entry`.
- `deploy/terraform/stacks/tfstate-bucket`
  - Manages the shared GCS bucket used for Terraform remote state.

## Usage

Entry VM stack:

```bash
export PROJECT_ID=<PROJECT_ID>
./scripts/terraform-init-gcs-backend.sh "deploy/terraform/stacks/entry-vm" "$PROJECT_ID"

cd deploy/terraform/stacks/entry-vm
cp terraform.tfvars.example terraform.tfvars
terraform plan
terraform apply
```

Core VM stack:

```bash
export PROJECT_ID=<PROJECT_ID>
./scripts/terraform-init-gcs-backend.sh "deploy/terraform/stacks/core-vm" "$PROJECT_ID"

cd deploy/terraform/stacks/core-vm
cp terraform.tfvars.example terraform.tfvars
terraform plan
terraform apply
```

For both stacks, publish runtime artifacts and configuration references before planning:
- upload the service binary to GCS and set `rollout_artifact_ref` and optionally `rollout_artifact_sha256`
- publish the rendered environment payload to Secret Manager or GCS and set `rollout_env_ref`
- publish optional TLS/systemd materials as the corresponding `rollout_*_secret_ref` or `rollout_unit_ref` inputs

Bootstrap infra stack:

```bash
export PROJECT_ID=<PROJECT_ID>
./scripts/terraform-init-gcs-backend.sh "deploy/terraform/stacks/bootstrap-infra" "$PROJECT_ID"

cd deploy/terraform/stacks/bootstrap-infra
cp terraform.tfvars.example terraform.tfvars
terraform plan
terraform apply
```

## GitHub Actions automation

- `.github/workflows/entry-vm-cicd.yml`: Terraform-only workflow for the `entry` VM stack.
  - Uses shared backend initialization (`scripts/terraform-init-gcs-backend.sh`) before Terraform commands.
  - Supports `action=plan|apply|destroy`.
  - `action=plan` requires rollout references and uploads a saved plan artifact.
  - Uses the default `<region>-a` zone and auto-generated backend bucket/prefix instead of exposing those as dispatch inputs.
  - `action=apply` requires `plan_run_id` and applies the exact saved plan artifact from that workflow run.
- `.github/workflows/core-vm-cicd.yml`: Terraform-only workflow for the `core` VM stack.
  - Uses the same shared backend initialization and saved-plan safety model as `entry`.
  - Supports `action=plan|apply|destroy`.
  - `action=plan` requires rollout references and uploads a saved plan artifact.
  - Uses the default `<region>-a` zone, default CIDR policy inputs, and auto-generated backend bucket/prefix instead of exposing those as dispatch inputs.
  - `action=apply` requires `plan_run_id` and applies the exact saved plan artifact from that workflow run.
- `.github/workflows/bootstrap-infra.yml`: bootstrap workflow that provisions OIDC trust, writes `GCP_WORKLOAD_IDENTITY_PROVIDER` and `GCP_TERRAFORM_SA`, and creates the required node catalog bucket.
  - App-login Google OAuth client credentials are created manually in Google Cloud Console (see `deploy/terraform/stacks/bootstrap-infra/README.md`).
  - Uses shared backend initialization (`scripts/terraform-init-gcs-backend.sh`) before Terraform commands.
  - Exposes only `action` and `adopt_existing` as dispatch inputs; project/repository/backend/bucket defaults are resolved inside the workflow.
  - `action=apply` automatically reuses the latest non-expired saved bootstrap plan artifact for the current branch.
