#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${TEST_DATABASE_URL:-}" ]]; then
  echo "TEST_DATABASE_URL is not set" >&2
  echo "example: export TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/wg_test" >&2
  exit 1
fi

echo "Running entry DB-backed integration tests against ${TEST_DATABASE_URL}"
cargo test -p entry postgres_session_repo::tests -- --nocapture
cargo test -p entry node_repo::tests -- --nocapture
cargo test -p entry token_repo::tests -- --nocapture
cargo test -p entry oauth_repo::tests -- --nocapture
cargo test -p entry privacy_repo::tests -- --nocapture
cargo test -p entry subscription_repo::tests -- --nocapture
