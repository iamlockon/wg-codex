# Entry VM stack

Terraform stack that instantiates the reusable `modules/entry_vm` module.

## Usage

```bash
export PROJECT_ID=<PROJECT_ID>

./scripts/terraform-init-gcs-backend.sh \
  "deploy/terraform/stacks/entry-vm" \
  "$PROJECT_ID"

cd deploy/terraform/stacks/entry-vm
cp terraform.tfvars.example terraform.tfvars
terraform plan
terraform apply
```

Set rollout variables before planning so the startup template can fetch the entry binary and runtime configuration:
- `rollout_artifact_ref` and optionally `rollout_artifact_sha256` for the entry binary in GCS
- `rollout_env_ref` for the rendered `entry` environment payload
- optional `rollout_unit_ref`, `rollout_core_ca_secret_ref`, `rollout_core_client_cert_secret_ref`, and `rollout_core_client_key_secret_ref`

Use this with the `entry-vm-cicd.yml` GitHub Actions workflow for automated VM stack operations:
- all Terraform actions first run `scripts/terraform-init-gcs-backend.sh` to manage/init a shared GCS backend automatically
- `action=plan` creates and uploads a Terraform plan artifact
- the dispatch form exposes only the common rollout inputs; optional rollout overrides are read from repository variables `ENTRY_ROLLOUT_ARTIFACT_SHA256`, `ENTRY_ROLLOUT_UNIT_REF`, `ENTRY_ROLLOUT_CORE_CA_SECRET_REF`, `ENTRY_ROLLOUT_CORE_CLIENT_CERT_SECRET_REF`, and `ENTRY_ROLLOUT_CORE_CLIENT_KEY_SECRET_REF`
- `action=apply` requires `plan_run_id` and applies that exact saved plan
- `action=destroy` runs direct destroy

The workflow no longer supports direct SSH/script provisioning. Terraform is the supported VM deploy path for `entry`.
