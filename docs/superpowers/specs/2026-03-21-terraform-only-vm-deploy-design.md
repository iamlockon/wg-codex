# Terraform-Only VM Deploy Design

## Summary

Consolidate VM deployment onto a single Terraform-managed path for both `entry` and `core`, and retire the current script provisioners. VM lifecycle, rollout inputs, and auditability should live in Terraform and GitHub Actions plan/apply flows, while runtime artifacts and secrets are fetched on the VM during startup instead of being pushed over SSH.

## Goals

- Remove the dual-provisioner model from VM deployment workflows.
- Make both `entry` and `core` use Terraform `plan` / `apply` / `destroy`.
- Eliminate `scripts/deploy-entry-vm.sh` and `scripts/deploy-core-vm.sh` as the primary deployment mechanism.
- Improve infra visibility, drift detection, and operational auditability.
- Avoid putting raw application secrets into Terraform state.

## Non-Goals

- Reworking application runtime configuration semantics beyond how they are delivered to the VM.
- Replacing GCP as the deployment target.
- Introducing a container orchestration platform.

## Architecture

Terraform will manage the full lifecycle of both VM deployments. The existing `entry-vm` Terraform stack becomes the model for both services, and a matching Terraform stack/module is introduced for `core`. GitHub Actions workflows for `entry` and `core` become Terraform-only, using saved-plan apply semantics consistent with the bootstrap workflow.

Application rollout moves from imperative `gcloud compute scp/ssh` scripts to declarative VM startup configuration. Each VM instance receives startup metadata or cloud-init content rendered by Terraform. On boot, the VM installs prerequisites, fetches versioned service artifacts from GCS, resolves runtime secrets from Secret Manager or other referenced file-based locations, writes the service env/unit files, and starts the systemd service.

## Secrets and Artifact Delivery

- CI builds `entry` and `core` artifacts and uploads versioned binaries plus checksums to GCS.
- Terraform passes only artifact identifiers, object paths, checksums, and secret references to the VM.
- VMs use their service accounts to fetch runtime secrets from Secret Manager and artifacts from GCS at boot.
- Raw secret values should not be passed as Terraform variables unless there is no practical alternative.

## Operational Behavior

- `entry-vm-cicd.yml` removes the `provisioner` choice and becomes Terraform-only.
- `core-vm-cicd.yml` gains Terraform `plan` / `apply` / `destroy` behavior and a matching stack/backend path.
- Startup logic replaces the current remote-install script responsibilities: writing env files, installing TLS/WireGuard material, registering systemd units, and restarting services.
- For `core`, the current native-NAT fallback behavior should either be preserved in startup logic or made explicit as a deployment-time choice. It should not silently disappear.

## Risks

- Startup-script-based rollout is less interactive than SSH-based deployment, so diagnostics need to rely on serial console logs, startup-script logs, and systemd/journalctl checks.
- Artifact rollout and secret fetch permissions must be carefully scoped to VM service accounts.
- The current deploy scripts embed a substantial amount of validation logic that will need to be preserved in workflows, Terraform variable validations, or startup scripts.

## Testing

- Terraform validation for both `entry` and `core` stacks.
- Workflow YAML validation after consolidating the CI/CD paths.
- End-to-end VM rollout test for both services using the Terraform-only path.
- Verification that runtime secrets are fetched from references rather than stored directly in Terraform-managed config.
