#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${TEST_DATABASE_URL:-}" ]]; then
  echo "TEST_DATABASE_URL is not set" >&2
  echo "example: export TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/wg_test" >&2
  exit 1
fi

echo "Running backend OAuth e2e tests against ${TEST_DATABASE_URL}"
cargo test -p backend-e2e -- --nocapture --test-threads=1
