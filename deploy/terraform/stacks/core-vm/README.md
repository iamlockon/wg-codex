# Core VM stack

Terraform stack that instantiates the reusable `modules/core_vm` module.

## Usage

```bash
cd deploy/terraform/stacks/core-vm
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform apply
```

Use this with the `entry-vm-cicd.yml` GitHub Actions workflow for automated apply/destroy of the VM footprint used by entry deployment.
