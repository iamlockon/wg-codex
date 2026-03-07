# Core VM stack

Terraform stack that instantiates the reusable `modules/core_vm` module.

## Usage

```bash
cd deploy/terraform/stacks/core-vm
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform apply
```

Use this with the `entry-vm-cicd.yml` GitHub Actions workflow for automated VM stack operations:
- `provisioner=terraform`, `action=plan` creates and uploads a Terraform plan artifact.
- `provisioner=terraform`, `action=apply` requires `plan_run_id` and applies that exact saved plan.
- `provisioner=terraform`, `action=destroy` runs direct destroy.
