# Scripts

## Current primary scripts

- `scripts/run-db-integration-tests.sh`
  - Runs the DB-backed integration suites against `TEST_DATABASE_URL`.

- `scripts/deploy-core-vm.sh`
  - VM deployment helper for a non-Kubernetes core host.
  - Supports optional `--register-node-in-entry true` to upsert the newly created core node into a remote entry admin API.
  - Used by `.github/workflows/core-vm-cicd.yml` for region-aware core rollout automation.

## Useful manual diagnostics

- View recent `core` logs on a VM:
  - `gcloud compute ssh <vm-name> --project "$PROJECT_ID" --zone "$ZONE" --command "sudo journalctl -u wg-core -n 200 --no-pager"`

- View recent `entry` logs on a VM:
  - `gcloud compute ssh <vm-name> --project "$PROJECT_ID" --zone "$ZONE" --command "sudo journalctl -u wg-entry -n 200 --no-pager"`
