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
terraform plan
terraform apply
```

Set rollout variables before planning so the startup template can fetch the core binary and runtime configuration:
- `rollout_artifact_ref` and optionally `rollout_artifact_sha256` for the core binary in GCS
- `rollout_env_ref` for the rendered `core` environment payload
- optional `rollout_unit_ref`, `rollout_private_key_secret_ref`, `rollout_tls_cert_secret_ref`, `rollout_tls_key_secret_ref`, and `rollout_tls_ca_secret_ref`

This stack manages the Terraform-owned core VM footprint:
- static IP, instance, tags, and firewall inputs for the core service footprint
- startup metadata that drives artifact/env/secret materialization on boot

Use this with the `core-vm-cicd.yml` GitHub Actions workflow for automated VM stack operations:
- all Terraform actions first run `scripts/terraform-init-gcs-backend.sh` to manage/init a shared GCS backend automatically
- `action=plan` creates and uploads a Terraform plan artifact
- `action=apply` requires `plan_run_id` and applies that exact saved plan
- `action=destroy` runs direct destroy

The workflow does not support SSH/scp provisioning. Terraform is the supported VM deploy path for `core`.
