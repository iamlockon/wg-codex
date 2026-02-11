#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <dev|prod|prod-native-canary|prod-gcp-sm>" >&2
  exit 1
fi

overlay="$1"
case "$overlay" in
  dev|prod|prod-native-canary|prod-gcp-sm) ;;
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
if [[ "$overlay" != "prod-gcp-sm" ]]; then
  require_pattern 'name: entry-secrets' "entry-secrets reference"
fi
require_pattern 'name: core-secrets' "core-secrets reference"
require_pattern 'name: core-tls' "core-tls reference"
require_pattern 'name: core-grpc-client-tls' "core-grpc-client-tls reference"
require_pattern 'name: wireguard-keys' "wireguard-keys reference"
if [[ "$overlay" == "prod-gcp-sm" ]]; then
  require_pattern '^kind: SecretProviderClass$' "secretproviderclass resources"
  require_pattern 'secretProviderClass: entry-gcp-secrets' "entry secret provider class mount"
  require_pattern 'secretProviderClass: core-gcp-secrets' "core secret provider class mount"
fi

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

if [[ "$overlay" == "prod" || "$overlay" == "prod-gcp-sm" ]]; then
  require_pattern 'WG_NAT_DRIVER: "cli"' "prod NAT driver pin to cli"
fi

if [[ "$overlay" == "prod-native-canary" ]]; then
  require_pattern 'WG_NAT_DRIVER: "native"' "canary NAT driver set to native"
fi

if [[ "$overlay" != "dev" ]]; then
  require_pattern 'APP_ENV: "production"' "production runtime mode"
  require_pattern 'APP_REQUIRE_CORE_TLS: "true"' "entry-to-core TLS requirement"
  require_pattern 'CORE_REQUIRE_TLS: "true"' "core TLS requirement"
  require_pattern 'APP_ALLOW_LEGACY_CUSTOMER_HEADER: "false"' "legacy header disablement"
  require_pattern 'APP_LOG_REDACTION_MODE: "strict"' "strict log redaction"
  require_pattern 'APP_MAX_TERMINATED_SESSION_RETENTION_DAYS: "30"' "session retention cap policy"
  require_pattern 'APP_MAX_AUDIT_RETENTION_DAYS: "90"' "audit retention cap policy"
  require_pattern 'APP_REQUIRE_OAUTH_NONCE: "true"' "production OAuth nonce policy"
  require_pattern 'APP_REQUIRE_OAUTH_PKCE: "true"' "production OAuth PKCE policy"
fi

echo "preflight ok: overlay=${overlay}"
