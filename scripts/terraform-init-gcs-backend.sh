#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <stack_dir> <project_id> [state_bucket] [state_prefix] [state_bucket_location]" >&2
}

if [[ $# -lt 2 || $# -gt 5 ]]; then
  usage
  exit 1
fi

STACK_DIR="$1"
PROJECT_ID="$2"
STATE_BUCKET="${3:-}"
STATE_PREFIX="${4:-}"
STATE_BUCKET_LOCATION="${5:-${TF_STATE_BUCKET_LOCATION:-us-central1}}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TFSTATE_STACK_DIR="${REPO_ROOT}/deploy/terraform/stacks/tfstate-bucket"

if [[ ! -d "${REPO_ROOT}/${STACK_DIR}" ]]; then
  echo "Stack directory not found: ${STACK_DIR}" >&2
  exit 1
fi

sanitize() {
  tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9-' '-'
}

default_state_bucket() {
  local project_slug repo_slug hash full bucket
  project_slug="$(printf '%s' "${PROJECT_ID}" | sanitize)"
  repo_slug="$(printf '%s' "${GITHUB_REPOSITORY:-wg-codex}" | sanitize)"
  hash="$(printf '%s' "${PROJECT_ID}:${repo_slug}" | sha256sum | cut -c1-8)"
  full="tfstate-${project_slug}-${repo_slug}-${hash}"
  bucket="${full:0:63}"
  bucket="${bucket%-}"
  echo "${bucket}"
}

if [[ -z "${STATE_BUCKET}" ]]; then
  STATE_BUCKET="$(default_state_bucket)"
fi

STACK_NAME="$(basename "${STACK_DIR}")"

if [[ -z "${STATE_PREFIX}" ]]; then
  STATE_PREFIX="terraform/${STACK_NAME}"
fi

if [[ "${STATE_PREFIX}" != "${STACK_NAME}" && "${STATE_PREFIX}" != */"${STACK_NAME}" ]]; then
  echo "Invalid state prefix '${STATE_PREFIX}' for stack '${STACK_NAME}'." >&2
  echo "State prefix must end with '/${STACK_NAME}' to prevent cross-stack destroy/apply." >&2
  exit 1
fi

terraform -chdir="${TFSTATE_STACK_DIR}" init -backend=false -input=false

# Best-effort import so bucket can be managed whether it already exists or not.
terraform -chdir="${TFSTATE_STACK_DIR}" import -input=false google_storage_bucket.terraform_state "${STATE_BUCKET}" >/dev/null 2>&1 || true

terraform -chdir="${TFSTATE_STACK_DIR}" apply -input=false -auto-approve \
  -var="project_id=${PROJECT_ID}" \
  -var="bucket_name=${STATE_BUCKET}" \
  -var="location=${STATE_BUCKET_LOCATION}"

terraform -chdir="${REPO_ROOT}/${STACK_DIR}" init -input=false -reconfigure \
  -backend-config="bucket=${STATE_BUCKET}" \
  -backend-config="prefix=${STATE_PREFIX}"

echo "Initialized Terraform backend: gs://${STATE_BUCKET}/${STATE_PREFIX}"

if [[ -n "${GITHUB_ENV:-}" ]]; then
  {
    echo "TF_STATE_BUCKET=${STATE_BUCKET}"
    echo "TF_STATE_PREFIX=${STATE_PREFIX}"
  } >> "${GITHUB_ENV}"
fi
