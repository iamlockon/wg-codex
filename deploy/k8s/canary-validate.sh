#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 4 ]]; then
  echo "usage: $0 <entry_base_url> <admin_token> [overlay] [namespace]" >&2
  echo "example: $0 https://entry.example.com my-admin-token prod-native-canary wg-vpn" >&2
  exit 1
fi

ENTRY_BASE_URL="${1%/}"
ADMIN_TOKEN="$2"
OVERLAY="${3:-prod-native-canary}"
NAMESPACE="${4:-wg-vpn}"
ROLLBACK_OVERLAY="${ROLLBACK_OVERLAY:-prod}"
AUTO_ROLLBACK="${AUTO_ROLLBACK:-1}"
ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT:-300s}"

case "$OVERLAY" in
  prod-native-canary|prod-gcp-sm-native-canary) ;;
  *)
    echo "invalid canary overlay: $OVERLAY (expected prod-native-canary or prod-gcp-sm-native-canary)" >&2
    exit 1
    ;;
esac

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_cmd kubectl
require_cmd curl
require_cmd jq

applied=0

rollback() {
  set +e
  echo "==> rollback: applying overlay ${ROLLBACK_OVERLAY}"
  kubectl apply -k "${SCRIPT_DIR}/overlays/${ROLLBACK_OVERLAY}"
  kubectl -n "${NAMESPACE}" rollout status deployment/entry --timeout="${ROLLOUT_TIMEOUT}"
  kubectl -n "${NAMESPACE}" rollout status daemonset/core --timeout="${ROLLOUT_TIMEOUT}"
}

on_exit() {
  local code="$1"
  if [[ "$code" -ne 0 && "$applied" -eq 1 && "$AUTO_ROLLBACK" == "1" ]]; then
    rollback
  fi
  exit "$code"
}

trap 'on_exit $?' EXIT

echo "==> preflight: ${OVERLAY}"
"${SCRIPT_DIR}/preflight.sh" "${OVERLAY}"

echo "==> apply: ${OVERLAY}"
kubectl apply -k "${SCRIPT_DIR}/overlays/${OVERLAY}"
applied=1

echo "==> rollout status: deployment/entry"
kubectl -n "${NAMESPACE}" rollout status deployment/entry --timeout="${ROLLOUT_TIMEOUT}"

echo "==> rollout status: daemonset/core"
kubectl -n "${NAMESPACE}" rollout status daemonset/core --timeout="${ROLLOUT_TIMEOUT}"

echo "==> smoke checks (expect nat_driver=native)"
"${SCRIPT_DIR}/smoke-check.sh" "${ENTRY_BASE_URL}" "${ADMIN_TOKEN}" native

echo "canary validation passed: overlay=${OVERLAY}"
