# Core VM stack

Terraform stack that instantiates the reusable `modules/core_vm` module.

## Usage

```bash
cd deploy/terraform/stacks/core-vm
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform apply
```

Use this with the `core-vm-cicd.yml` GitHub Actions workflow for automated apply/destroy + entry node registration.
