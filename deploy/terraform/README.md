# Terraform Infra (GCP + GKE)

This stack manages the infrastructure needed by the `prod-gcp-sm` deployment path:

- Optional GKE platform creation (`manage_gke=true`):
  - VPC-native cluster with Workload Identity enabled
  - dedicated `entry` and `core` node pools
  - optional Secrets Store CSI driver + GCP provider installation via Helm
- GCP service accounts for Workload Identity:
  - `entry-secrets`
  - `core-secrets`
- Workload Identity IAM bindings from Kubernetes service accounts:
  - `wg-vpn/entry-wi`
  - `wg-vpn/core-wi`
- Secret Manager secret containers for all runtime secrets referenced by the CSI mounts.
- Secret versions managed from Terraform variables:
  - `entry-google-oidc-client-id` / `entry-google-oidc-client-secret` from standard Google Sign-In OAuth client credentials
  - `entry-database-url` generated from Cloud SQL when `manage_postgres=true`
- Optional additional secret versions from `secret_values`.
- Kubernetes `SecretProviderClass` objects:
  - `entry-gcp-secrets`
  - `core-gcp-secrets`
- Optional Cloud SQL Postgres infrastructure (`manage_postgres=true`):
  - instance
  - database
  - application user + generated password
  - private IP (default on) with optional VPC creation and private service networking peering

## Usage

```bash
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform plan
terraform apply
```

With `manage_gke=true`, this single `terraform apply` can provision:
- VPC/networking + private service networking
- GKE cluster and node pools
- Cloud SQL Postgres + DB URL secret
- OAuth client credentials secret values
- Secret Manager + Workload Identity + SecretProviderClass wiring

If you do not want to seed additional secret values in Terraform state, leave `secret_values = {}`.

## Notes

- If `manage_gke=false`, the Kubernetes and Helm providers use local kubeconfig by default (`~/.kube/config`).
- Keep `terraform.tfvars` out of source control.
- Create OAuth credentials in Google Cloud Console:
  - `APIs & Services` -> `Credentials` -> `Create Credentials` -> `OAuth client ID` (`Web application`)
  - add callback URI: `https://<entry-host>/v1/auth/oauth/google/callback`
  - set `google_oauth_client_id` and `google_oauth_client_secret` in `terraform.tfvars`
