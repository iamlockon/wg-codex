#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/deploy-backends-k8s.sh [options]

Builds + pushes backend images, applies k8s overlay, pins runtime images, waits rollout,
and runs DB migrations.

Options:
  --overlay <name>             Kustomize overlay (default: prod-gcp-sm)
  --namespace <name>           Kubernetes namespace (default: wg-vpn)
  --registry <path>            Image registry prefix (default: asia-east1-docker.pkg.dev/wg-codex/wg)
  --tag <tag>                  Image tag (default: utc timestamp + git short sha)
  --skip-build                 Skip docker build
  --skip-push                  Skip docker push
  --skip-migrations            Skip migration configmap/job
  --migration-timeout <dur>    Migration wait timeout (default: 300s)
  -h, --help                   Show help

Examples:
  scripts/deploy-backends-k8s.sh
  scripts/deploy-backends-k8s.sh --overlay prod-gcp-sm-native-canary --tag v20260212
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_k8s_object() {
  local namespace="$1"
  local kind="$2"
  local name="$3"
  if ! kubectl -n "$namespace" get "$kind" "$name" >/dev/null 2>&1; then
    echo "missing required ${kind}/${name} in namespace ${namespace}" >&2
    echo "run terraform apply in deploy/terraform first, then rerun this script" >&2
    exit 2
  fi
}

OVERLAY="prod-gcp-sm"
NAMESPACE="wg-vpn"
REGISTRY="asia-east1-docker.pkg.dev/wg-codex/wg"
TAG=""
SKIP_BUILD=0
SKIP_PUSH=0
SKIP_MIGRATIONS=0
MIGRATION_TIMEOUT="300s"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --overlay) OVERLAY="$2"; shift 2 ;;
    --namespace) NAMESPACE="$2"; shift 2 ;;
    --registry) REGISTRY="$2"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --skip-push) SKIP_PUSH=1; shift ;;
    --skip-migrations) SKIP_MIGRATIONS=1; shift ;;
    --migration-timeout) MIGRATION_TIMEOUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$TAG" ]]; then
  git_sha="$(git rev-parse --short HEAD 2>/dev/null || echo local)"
  TAG="$(date -u +%Y%m%d%H%M%S)-${git_sha}"
fi

ENTRY_IMAGE="${REGISTRY}/wg-entry:${TAG}"
CORE_IMAGE="${REGISTRY}/wg-core:${TAG}"

require_cmd kubectl
require_cmd docker
require_cmd git

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  echo "Building images:"
  echo "  entry -> ${ENTRY_IMAGE}"
  echo "  core  -> ${CORE_IMAGE}"
  docker build -f services/entry/Dockerfile -t "$ENTRY_IMAGE" .
  if [[ "$OVERLAY" == *"native-canary"* ]]; then
    docker build -f services/core/Dockerfile --build-arg CORE_CARGO_FEATURES=native-nft -t "$CORE_IMAGE" .
  else
    docker build -f services/core/Dockerfile -t "$CORE_IMAGE" .
  fi
fi

if [[ "$SKIP_PUSH" -eq 0 ]]; then
  echo "Pushing images..."
  docker push "$ENTRY_IMAGE"
  docker push "$CORE_IMAGE"
fi

echo "Running preflight for overlay=${OVERLAY}..."
deploy/k8s/preflight.sh "$OVERLAY"

if [[ "$OVERLAY" == "prod-gcp-sm" || "$OVERLAY" == "prod-gcp-sm-native-canary" ]]; then
  echo "Checking Terraform-managed GCP Secret Manager CSI prerequisites..."
  require_k8s_object "$NAMESPACE" serviceaccount entry-wi
  require_k8s_object "$NAMESPACE" serviceaccount core-wi
  require_k8s_object "$NAMESPACE" secretproviderclass entry-gcp-secrets
  require_k8s_object "$NAMESPACE" secretproviderclass core-gcp-secrets
fi

echo "Applying overlay deploy/k8s/overlays/${OVERLAY}..."
kubectl apply -k "deploy/k8s/overlays/${OVERLAY}"

echo "Pinning deployment images..."
kubectl -n "$NAMESPACE" set image deployment/entry "entry=${ENTRY_IMAGE}"
kubectl -n "$NAMESPACE" set image daemonset/core "core=${CORE_IMAGE}"

echo "Waiting for rollout..."
kubectl -n "$NAMESPACE" rollout status deployment/entry --timeout=300s
kubectl -n "$NAMESPACE" rollout status daemonset/core --timeout=300s

if [[ "$SKIP_MIGRATIONS" -eq 0 ]]; then
  echo "Applying migrations..."
  kubectl -n "$NAMESPACE" create configmap db-migrations \
    --from-file=db/migrations/202602090001_initial_schema.sql \
    --from-file=db/migrations/202602100002_revoked_tokens.sql \
    --from-file=db/migrations/202602100003_consumer_model.sql \
    --dry-run=client -o yaml | kubectl apply -f -

  kubectl -n "$NAMESPACE" delete job db-migrate --ignore-not-found
  kubectl apply -f deploy/k8s/migrate-job.yaml
  kubectl -n "$NAMESPACE" wait --for=condition=complete "job/db-migrate" --timeout="$MIGRATION_TIMEOUT"
fi

echo "Deployment complete."
echo "overlay:   $OVERLAY"
echo "namespace: $NAMESPACE"
echo "entry:     $ENTRY_IMAGE"
echo "core:      $CORE_IMAGE"
