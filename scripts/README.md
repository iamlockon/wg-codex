# Scripts

## Current primary scripts

- `scripts/deploy-backends-k8s.sh`
  - Preferred backend deployment path for Kubernetes.
  - Builds and pushes `entry`/`core`, runs `deploy/k8s/preflight.sh`, applies the selected overlay, waits for rollout, and refreshes DB migrations.

- `scripts/run-db-integration-tests.sh`
  - Runs the DB-backed integration suites against `TEST_DATABASE_URL`.

- `scripts/deploy-core-vm.sh`
  - Legacy VM-oriented deployment helper for a non-Kubernetes core host.
  - Keep this only for VM experiments; current production deployment docs assume the Kubernetes flow.

## Useful manual diagnostics

- View recent `core` logs on a VM:
  - `gcloud compute ssh <vm-name> --project "$PROJECT_ID" --zone "$ZONE" --command "sudo journalctl -u wg-core -n 200 --no-pager"`

- View recent `entry` logs on a VM:
  - `gcloud compute ssh <vm-name> --project "$PROJECT_ID" --zone "$ZONE" --command "sudo journalctl -u wg-entry -n 200 --no-pager"`
