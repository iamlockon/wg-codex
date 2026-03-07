# Core VM stack

Terraform stack that instantiates the reusable `modules/core_vm` module.

## Usage

```bash
export PROJECT_ID=<PROJECT_ID>

./scripts/terraform-init-gcs-backend.sh \
  "deploy/terraform/stacks/core-vm" \
  "$PROJECT_ID"

cd deploy/terraform/stacks/core-vm
cp terraform.tfvars.example terraform.tfvars
terraform apply
```

Use this with the `entry-vm-cicd.yml` GitHub Actions workflow for automated VM stack operations:
- all Terraform actions first run `scripts/terraform-init-gcs-backend.sh` to manage/init a shared GCS backend automatically.
- `provisioner=terraform`, `action=plan` creates and uploads a Terraform plan artifact.
- `provisioner=terraform`, `action=apply` requires `plan_run_id` and applies that exact saved plan.
- `provisioner=terraform`, `action=destroy` runs direct destroy.
