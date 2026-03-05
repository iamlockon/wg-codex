# core_vm module

Reusable Terraform module for a single-region core VM footprint in GCP:
- static external IP
- Compute Engine instance
- optional firewall rules for entry HTTP (8080) + WireGuard UDP (default 51820)

This module is consumed by `deploy/terraform/stacks/core-vm` and is intended for CI/CD-driven bring-up/tear-down.


Note: the module does not force `enable-oslogin=TRUE`; this keeps `gcloud compute ssh/scp` compatible with CI service accounts that do not have OS Login IAM roles.
