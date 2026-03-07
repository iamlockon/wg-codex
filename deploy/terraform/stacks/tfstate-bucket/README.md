# Terraform State Bucket Stack

This stack manages the shared GCS bucket used as Terraform remote backend storage.

It is intended to be executed automatically by CI before stack initialization via `scripts/terraform-init-gcs-backend.sh`.
