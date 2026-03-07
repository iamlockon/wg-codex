# Terraform Stacks

Kubernetes/GKE Terraform assets were removed. The remaining Terraform deployment paths are stack-based:

- `deploy/terraform/stacks/core-vm`
  - Creates infrastructure for VM-based deployment via `modules/core_vm`.
- `deploy/terraform/stacks/bootstrap-oidc`
  - Bootstraps GitHub Actions -> GCP Workload Identity Federation and writes required repository secrets.
- `deploy/terraform/stacks/tfstate-bucket`
  - Manages the shared GCS bucket used for Terraform remote state.

## Usage

Core VM stack:

```bash
export PROJECT_ID=<PROJECT_ID>
./scripts/terraform-init-gcs-backend.sh "deploy/terraform/stacks/core-vm" "$PROJECT_ID"

cd deploy/terraform/stacks/core-vm
cp terraform.tfvars.example terraform.tfvars
terraform plan
terraform apply
```

Bootstrap OIDC stack:

```bash
export PROJECT_ID=<PROJECT_ID>
./scripts/terraform-init-gcs-backend.sh "deploy/terraform/stacks/bootstrap-oidc" "$PROJECT_ID"

cd deploy/terraform/stacks/bootstrap-oidc
cp terraform.tfvars.example terraform.tfvars
terraform plan
terraform apply
```

## GitHub Actions automation

- `.github/workflows/infra-terraform.yml`: manual plan/apply/destroy for `deploy/terraform/stacks/core-vm` and `deploy/terraform/stacks/bootstrap-oidc`.
  - Uses shared backend initialization (`scripts/terraform-init-gcs-backend.sh`) for all stacks.
  - `action=plan` saves `tfplan` as a workflow artifact.
  - `action=apply` requires `plan_run_id` and applies that exact saved plan.
- `.github/workflows/entry-vm-cicd.yml`: deploys VM infrastructure and runs `scripts/deploy-entry-vm.sh`.
  - `provisioner=script` supports `action=apply|destroy` (no Terraform state change).
  - `provisioner=terraform` uses shared backend initialization (`scripts/terraform-init-gcs-backend.sh`) before Terraform commands.
  - `provisioner=terraform` supports `action=plan|apply|destroy`; Terraform `apply` requires `plan_run_id` and uses the exact saved plan artifact.
- `.github/workflows/bootstrap-gcp-oidc.yml`: bootstrap workflow that provisions OIDC trust and writes `GCP_WORKLOAD_IDENTITY_PROVIDER` and `GCP_TERRAFORM_SA`.
  - Uses shared backend initialization (`scripts/terraform-init-gcs-backend.sh`) before Terraform commands.
