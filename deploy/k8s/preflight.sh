#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <dev|prod|prod-native-canary>" >&2
  exit 1
fi

overlay="$1"
case "$overlay" in
  dev|prod|prod-native-canary) ;;
  *)
    echo "invalid overlay: $overlay" >&2
    exit 1
    ;;
esac

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_cmd kubectl
require_cmd grep

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

kubectl kustomize "deploy/k8s/overlays/${overlay}" >"$tmp"

require_pattern() {
  local pattern="$1"
  local description="$2"
  if ! grep -qE "$pattern" "$tmp"; then
    echo "preflight failed: missing ${description}" >&2
    exit 2
  fi
}

require_pattern '^kind: Deployment$' "entry deployment"
require_pattern '^kind: DaemonSet$' "core daemonset"
require_pattern 'name: entry-secrets' "entry-secrets reference"
require_pattern 'name: core-secrets' "core-secrets reference"
require_pattern 'name: core-tls' "core-tls reference"
require_pattern 'name: core-grpc-client-tls' "core-grpc-client-tls reference"
require_pattern 'name: wireguard-keys' "wireguard-keys reference"

require_pattern 'DATABASE_URL_FILE' "DATABASE_URL_FILE env wiring"
require_pattern 'APP_JWT_SIGNING_KEYS_FILE' "APP_JWT_SIGNING_KEYS_FILE env wiring"
require_pattern 'GOOGLE_OIDC_CLIENT_SECRET_FILE' "GOOGLE_OIDC_CLIENT_SECRET_FILE env wiring"
require_pattern 'WG_SERVER_PUBLIC_KEY_FILE' "WG_SERVER_PUBLIC_KEY_FILE env wiring"
require_pattern 'seccompProfile:' "pod seccomp profile configuration"
require_pattern 'allowPrivilegeEscalation: false' "container privilege-escalation hardening"

if [[ "$overlay" != "dev" ]]; then
  if grep -q 'AgReplaceMe' "$tmp"; then
    echo "preflight failed: found placeholder sealed secret values (AgReplaceMe)" >&2
    exit 3
  fi
fi

echo "preflight ok: overlay=${overlay}"
