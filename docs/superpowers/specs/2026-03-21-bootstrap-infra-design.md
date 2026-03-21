# Bootstrap Infra Design

## Summary

Rename the current bootstrap path from `bootstrap-oidc` / `bootstrap-gcp-oidc.yml` to `bootstrap-infra` / `bootstrap-infra.yml` and expand the Terraform stack so it creates the required entry node catalog GCS bucket in addition to the existing GitHub OIDC bootstrap resources.

## Goals

- Make node catalog bucket creation part of the bootstrap flow instead of a manual step.
- Rename the workflow and Terraform stack so their names match their broader responsibility.
- Preserve the current plan/apply safety model, including saved-plan apply and adoption mode.

## Non-Goals

- Managing the node catalog object path or document contents.
- Changing `entry` runtime env var names or node catalog loading behavior.
- Refactoring unrelated Terraform stacks or deploy scripts.

## Architecture

The renamed Terraform stack at `deploy/terraform/stacks/bootstrap-infra` remains responsible for establishing foundational project automation resources. It will continue to manage the GitHub Actions Workload Identity setup and repository secrets, and it will add a required `google_storage_bucket` resource for the entry node catalog bucket.

The renamed workflow at `.github/workflows/bootstrap-infra.yml` will continue to orchestrate `plan`, `apply`, and `destroy` against the bootstrap stack using the shared backend init script. The workflow will gain required bucket-name input and optional bucket-location/storage-class inputs, and its adoption flow will import the bucket when it already exists.

## Operational Considerations

- The stack uses the `bootstrap-infra` backend prefix convention and does not preserve compatibility with the removed `bootstrap-oidc` state namespace.

## Adoption Behavior

- In `adopt_existing=true` mode, the node catalog bucket is a required import, not a best-effort one.
- The workflow must fail the adoption plan if the bucket still appears with a `create` action after imports, matching the fail-fast behavior for other required bootstrap resources.

## Testing

- Validate Terraform formatting for the renamed stack.
- Validate the renamed stack with `terraform init -backend=false` and `terraform validate`.
- Validate GitHub workflow YAML after the rename.
