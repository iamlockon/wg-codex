# Terraform Stacks

Kubernetes/GKE Terraform assets were removed. The remaining Terraform deployment paths are stack-based:

- `deploy/terraform/stacks/core-vm`
  - Creates infrastructure for VM-based deployment via `modules/core_vm`.
- `deploy/terraform/stacks/bootstrap-oidc`
  - Bootstraps GitHub Actions -> GCP Workload Identity Federation and writes required repository secrets.

## Usage

Core VM stack:

```bash
cd deploy/terraform/stacks/core-vm
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform plan
terraform apply
```

Bootstrap OIDC stack:

```bash
cd deploy/terraform/stacks/bootstrap-oidc
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform plan
terraform apply
```

## GitHub Actions automation

- `.github/workflows/infra-terraform.yml`: manual plan/apply/destroy for `deploy/terraform/stacks/core-vm` and `deploy/terraform/stacks/bootstrap-oidc`.
- `.github/workflows/core-vm-cicd.yml`: creates/tears down a regional core VM stack and deploys services via `scripts/deploy-core-vm.sh`.
- `.github/workflows/bootstrap-gcp-oidc.yml`: bootstrap workflow that provisions OIDC trust and writes `GCP_WORKLOAD_IDENTITY_PROVIDER` and `GCP_TERRAFORM_SA`.
