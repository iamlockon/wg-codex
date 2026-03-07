# Bootstrap GitHub OIDC for Terraform

This stack bootstraps GitHub Actions -> GCP Workload Identity Federation and writes these repository secrets:

- `GCP_WORKLOAD_IDENTITY_PROVIDER`
- `GCP_TERRAFORM_SA`

It creates:
- a GCP Workload Identity Pool + Provider trusting GitHub OIDC tokens for one repository
- IAM binding allowing that GitHub repository to impersonate the service account
- GitHub Actions secrets with the provider name and service account email

Prerequisite:
- the Terraform service account (default `gha-terraform`) must already exist in the project before running this stack.

## Usage

```bash
export PROJECT_ID=<PROJECT_ID>

./scripts/terraform-init-gcs-backend.sh \
  "deploy/terraform/stacks/bootstrap-oidc" \
  "$PROJECT_ID"

cd deploy/terraform/stacks/bootstrap-oidc
cp terraform.tfvars.example terraform.tfvars
terraform plan
terraform apply
```

After apply, your other workflows can authenticate with:
- `workload_identity_provider: ${{ secrets.GCP_WORKLOAD_IDENTITY_PROVIDER }}`
- `service_account: ${{ secrets.GCP_TERRAFORM_SA }}`

## GitHub Actions

Use `.github/workflows/bootstrap-gcp-oidc.yml` and provide:
- `GCP_BOOTSTRAP_SA_KEY` repository secret containing JSON credentials for a bootstrap admin service account.
- `GH_ADMIN_TOKEN` repository secret for `apply`/`destroy` runs. `GITHUB_TOKEN` is not sufficient for managing repository Actions secrets.
- optional workflow inputs `tf_state_bucket`, `tf_state_prefix`, and `tf_state_bucket_location` (leave empty to auto-generate bucket and prefix).

Workflow behavior:
- `action=plan` first attempts best-effort `terraform import` for existing resources (Workload Identity Pool/Provider, required APIs, and IAM bindings) so reruns do not fail with already-exists errors.
- `action=plan` runs `terraform plan -out=tfplan` and uploads `tfplan` as artifact `bootstrap-oidc-tfplan`.
- `action=apply` requires `plan_run_id` (the workflow run id from the earlier `plan`) and applies that exact saved plan file.
- `action=destroy` runs a direct `terraform destroy -auto-approve`.

This key is only needed to create/update bootstrap resources. Once OIDC is working, keep it restricted or remove it if you no longer need bootstrap updates.

Recommended `GH_ADMIN_TOKEN` permissions:
- Classic PAT: `repo`.
- Fine-grained PAT: repository `Actions` set to `Read and write` and access to the target repository.

## Create `GCP_BOOTSTRAP_SA_KEY`

`GCP_BOOTSTRAP_SA_KEY` is the full JSON key content for a temporary/bootstrap service account.

1. Create (or select) the GCP project from CLI:

```bash
export PROJECT_ID=<PROJECT_ID>
export PROJECT_NAME=<PROJECT_NAME>
export BILLING_ACCOUNT=<BILLING_ACCOUNT_ID>
# Optional if your org requires it:
export FOLDER_ID=<FOLDER_ID>
```

If you already know the folder:

```bash
gcloud projects create "$PROJECT_ID" \
  --name "$PROJECT_NAME" \
  --folder "$FOLDER_ID"
```

If your org does not use folders, use:

```bash
gcloud projects create "$PROJECT_ID" \
  --name "$PROJECT_NAME"
```

Link billing and set default project:

```bash
gcloud beta billing projects link "$PROJECT_ID" \
  --billing-account "$BILLING_ACCOUNT"

gcloud config set project "$PROJECT_ID"
```

Enable required APIs:

```bash
gcloud services enable \
  iam.googleapis.com \
  storage.googleapis.com \
  cloudresourcemanager.googleapis.com \
  compute.googleapis.com \
  serviceusage.googleapis.com \
  --project "$PROJECT_ID"
```

2. Create the bootstrap service account:

```bash
gcloud iam service-accounts create gha-bootstrap \
  --project "$PROJECT_ID" \
  --display-name "GitHub bootstrap SA"
```

3. Grant required roles in the project:

```bash
for role in \
  roles/iam.workloadIdentityPoolAdmin \
  roles/iam.serviceAccountAdmin \
  roles/storage.admin \
  roles/resourcemanager.projectIamAdmin \
  roles/serviceusage.serviceUsageAdmin
do
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member "serviceAccount:gha-bootstrap@$PROJECT_ID.iam.gserviceaccount.com" \
    --role "$role"
done
```

4. Create a JSON key file:

```bash
gcloud iam service-accounts keys create /tmp/gcp-bootstrap-sa-key.json \
  --iam-account "gha-bootstrap@$PROJECT_ID.iam.gserviceaccount.com" \
  --project "$PROJECT_ID"
```

5. Save it in GitHub as an Actions repository secret:
- Name: `GCP_BOOTSTRAP_SA_KEY`
- Value: contents of `/tmp/gcp-bootstrap-sa-key.json`

If you use GitHub CLI:

```bash
gh secret set GCP_BOOTSTRAP_SA_KEY < /tmp/gcp-bootstrap-sa-key.json
```

After bootstrap is complete, rotate or delete this key and rely on OIDC (`GCP_WORKLOAD_IDENTITY_PROVIDER` + `GCP_TERRAFORM_SA`) for normal CI runs.
