# Terraform Stacks

Kubernetes/GKE Terraform assets were removed. The remaining Terraform deployment paths are stack-based:

- `deploy/terraform/stacks/entry-vm`
  - Creates infrastructure for VM-based deployment via `modules/entry_vm`.
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

- `.github/workflows/entry-vm-cicd.yml`: deploys VM infrastructure and runs `scripts/deploy-entry-vm.sh`.
  - `provisioner=script` supports `action=apply|destroy` (no Terraform state change).
  - `provisioner=terraform` uses shared backend initialization (`scripts/terraform-init-gcs-backend.sh`) before Terraform commands.
  - `provisioner=terraform` supports `action=plan|apply|destroy`; Terraform `apply` requires `plan_run_id` and uses the exact saved plan artifact.
- `.github/workflows/bootstrap-infra.yml`: bootstrap workflow that provisions OIDC trust, writes `GCP_WORKLOAD_IDENTITY_PROVIDER` and `GCP_TERRAFORM_SA`, and creates the required node catalog bucket.
  - App-login Google OAuth client credentials are created manually in Google Cloud Console (see `deploy/terraform/stacks/bootstrap-infra/README.md`).
  - Uses shared backend initialization (`scripts/terraform-init-gcs-backend.sh`) before Terraform commands.
