# Scripts

## Current primary scripts

- `scripts/run-db-integration-tests.sh`
  - Runs the DB-backed integration suites against `TEST_DATABASE_URL`.

- `scripts/deploy-entry-vm.sh`
  - Deploys only the `entry` service onto a GCE VM.
  - Used by `.github/workflows/entry-vm-cicd.yml` for CI-driven entry VM rollout.

- `scripts/deploy-core-vm.sh`
  - Deploys only the `core` service onto a GCE VM.
  - Supports optional `--register-node-in-entry true` to upsert the node in a remote entry admin API and enable heartbeat updates.
  - Used by `.github/workflows/core-vm-cicd.yml` for CI-driven core VM rollout.

## Useful manual diagnostics

- View recent `core` logs on a VM:
  - `gcloud compute ssh <vm-name> --project "$PROJECT_ID" --zone "$ZONE" --command "sudo journalctl -u wg-core -n 200 --no-pager"`

- View recent `entry` logs on a VM:
  - `gcloud compute ssh <vm-name> --project "$PROJECT_ID" --zone "$ZONE" --command "sudo journalctl -u wg-entry -n 200 --no-pager"`
