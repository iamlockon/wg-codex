#!/usr/bin/env bash
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required for scripts/run-backend-e2e-local.sh" >&2
  exit 1
fi

DB_CONTAINER_NAME="${BACKEND_E2E_DB_CONTAINER:-wg-codex-pg-e2e}"
DB_PORT="${BACKEND_E2E_DB_PORT:-55432}"
DB_NAME="${BACKEND_E2E_DB_NAME:-wg_test}"
DB_USER="${BACKEND_E2E_DB_USER:-postgres}"
DB_PASSWORD="${BACKEND_E2E_DB_PASSWORD:-postgres}"
DB_IMAGE="${BACKEND_E2E_DB_IMAGE:-postgres:16}"
TEST_DATABASE_URL="postgres://${DB_USER}:${DB_PASSWORD}@127.0.0.1:${DB_PORT}/${DB_NAME}"

cleanup() {
  docker rm -f "${DB_CONTAINER_NAME}" >/dev/null 2>&1 || true
}

if docker ps -a --format '{{.Names}}' | grep -Fxq "${DB_CONTAINER_NAME}"; then
  echo "container ${DB_CONTAINER_NAME} already exists; remove it or set BACKEND_E2E_DB_CONTAINER" >&2
  exit 1
fi

trap cleanup EXIT

echo "Starting local Postgres container ${DB_CONTAINER_NAME} on 127.0.0.1:${DB_PORT}"
docker run -d \
  --name "${DB_CONTAINER_NAME}" \
  -e POSTGRES_DB="${DB_NAME}" \
  -e POSTGRES_USER="${DB_USER}" \
  -e POSTGRES_PASSWORD="${DB_PASSWORD}" \
  -p "127.0.0.1:${DB_PORT}:5432" \
  "${DB_IMAGE}" >/dev/null

echo "Waiting for Postgres readiness"
for _ in $(seq 1 30); do
  if docker exec "${DB_CONTAINER_NAME}" pg_isready -U "${DB_USER}" -d "${DB_NAME}" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! docker exec "${DB_CONTAINER_NAME}" pg_isready -U "${DB_USER}" -d "${DB_NAME}" >/dev/null 2>&1; then
  echo "Postgres container ${DB_CONTAINER_NAME} did not become ready" >&2
  exit 1
fi

echo "Running backend e2e suite against ${TEST_DATABASE_URL}"
TEST_DATABASE_URL="${TEST_DATABASE_URL}" bash scripts/run-backend-e2e.sh
