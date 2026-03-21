# Scripts

## Current primary scripts

- `scripts/run-db-integration-tests.sh`
  - Runs the DB-backed integration suites against `TEST_DATABASE_URL`.

## VM deployment guidance

- VM rollout is Terraform-only.
  - Use `.github/workflows/entry-vm-cicd.yml` and `.github/workflows/core-vm-cicd.yml` for plan/apply.
  - See `docs/deployment-checklist.md` and `deploy/terraform/README.md` for the current deployment flow.

## Useful manual diagnostics

- View recent `core` logs on a VM:
  - `gcloud compute ssh <vm-name> --project "$PROJECT_ID" --zone "$ZONE" --command "sudo journalctl -u wg-core -n 200 --no-pager"`

- View recent `entry` logs on a VM:
  - `gcloud compute ssh <vm-name> --project "$PROJECT_ID" --zone "$ZONE" --command "sudo journalctl -u wg-entry -n 200 --no-pager"`
