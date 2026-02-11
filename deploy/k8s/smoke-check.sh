#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <entry_base_url> <admin_token>"
  echo "example: $0 https://entry.example.com my-admin-token"
  exit 1
fi

ENTRY_BASE_URL="${1%/}"
ADMIN_TOKEN="$2"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_cmd curl
require_cmd jq

echo "==> healthz"
curl -fsS "${ENTRY_BASE_URL}/healthz" | jq .

echo "==> admin privacy policy"
curl -fsS \
  -H "x-admin-token: ${ADMIN_TOKEN}" \
  "${ENTRY_BASE_URL}/v1/admin/privacy/policy" | jq .

echo "==> admin core status"
curl -fsS \
  -H "x-admin-token: ${ADMIN_TOKEN}" \
  "${ENTRY_BASE_URL}/v1/admin/core/status" | jq .

echo "==> admin readiness"
readiness_json="$(
  curl -fsS \
    -H "x-admin-token: ${ADMIN_TOKEN}" \
    "${ENTRY_BASE_URL}/v1/admin/readiness"
)"
echo "${readiness_json}" | jq .

if [[ "$(echo "${readiness_json}" | jq -r '.production_ready')" != "true" ]]; then
  echo "readiness check failed: production_ready=false" >&2
  exit 2
fi

echo "smoke checks passed"
