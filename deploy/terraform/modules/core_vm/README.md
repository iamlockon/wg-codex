# core_vm module

Reusable Terraform module for a single-region core VM footprint in GCP:
- static external IP
- Compute Engine instance
- optional firewall rules for WireGuard UDP (default 51820) and core gRPC TCP (default 50051)

This module is consumed by `deploy/terraform/stacks/core-vm` and is intended for Terraform-managed VM lifecycle operations.

The module keeps `metadata` as a passthrough so later startup-template rollout work can attach instance startup configuration without adding SSH provisioners here.
