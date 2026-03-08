#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/deploy-entry-vm.sh [options]

Defaults are free-tier oriented:
  vm-name=wg-entry-free
  zone=us-west1-b
  machine-type=e2-micro
  image-family=debian-12
  image-project=debian-cloud
  network-tags=wg-entry
  entry-binary=target/release/entry
  tls-server-crt-file=./secrets/server.crt
  tls-server-key-file=./secrets/server.key
  tls-ca-file=./secrets/ca.pem
  config-file=scripts/deploy-entry-vm.env (if present)

Optional options:
  --config <path>                   Optional env config file to source
  --project <id>                    GCP project id (default: gcloud config)
  --vm-name <name>                  GCE VM instance name
  --zone <zone>                     GCE zone (example: us-central1-a)
  --machine-type <type>             VM machine type (default: e2-micro)
  --image-family <name>             Image family (default: debian-12)
  --image-project <name>            Image project (default: debian-cloud)
  --network-tags <csv>              Comma-separated network tags (default: wg-entry)
  --ensure-firewall <bool>          Create ingress firewall rules for VM tags (default: true)
  --firewall-network <name|auto>    VPC network for firewall rules (default: auto from VM NIC)
  --allow-entry-cidrs <csv>         Source CIDRs for entry tcp/8080 (default: 0.0.0.0/0)
  --entry-binary <path>             Prebuilt entry binary path (default: target/release/entry)
  --skip-build                      Skip cargo build step
  --entry-app-env <env>             Entry APP_ENV (default: development)
  --entry-bind-addr <addr>          ENTRY_BIND_ADDR (default: 0.0.0.0:8080)
  --entry-admin-token <token>       ADMIN_API_TOKEN for entry admin routes
  --entry-jwt-signing-keys <value>  APP_JWT_SIGNING_KEYS for entry JWT issuance
  --google-oidc-client-id <id>      GOOGLE_OIDC_CLIENT_ID for entry OAuth
  --google-oidc-client-secret <v>   GOOGLE_OIDC_CLIENT_SECRET for entry OAuth
  --google-oidc-redirect-uri <uri>  GOOGLE_OIDC_REDIRECT_URI for entry OAuth
  --entry-allow-legacy-customer-header <bool>
                                    APP_ALLOW_LEGACY_CUSTOMER_HEADER (default: true)
  --entry-require-core-tls <bool>   APP_REQUIRE_CORE_TLS in entry (default: false)
  --entry-core-grpc-url <url>       CORE_GRPC_URL from entry to core (default: https://127.0.0.1:50051)
  --entry-core-tls-domain <name>    CORE_GRPC_TLS_DOMAIN (default: vm-name)
  --core-require-client-cert <bool> Require client cert for core gRPC (default: false)
  --tls-mode <self-signed|upload>   TLS material for entry->core client TLS (default: self-signed)
  --tls-server-crt-file <path>      Local client cert (required if --core-require-client-cert=true)
  --tls-server-key-file <path>      Local client key (required if --core-require-client-cert=true)
  --tls-ca-file <path>              Local CA cert (required if --entry-require-core-tls=true)
  --tls-common-name <name>          Default TLS domain if --entry-core-tls-domain is omitted
  --create-only                     Only create VM + cloud-init; skip upload/install

Example:
  scripts/deploy-entry-vm.sh --project my-project
USAGE
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "required file not found: $path" >&2
    exit 1
  fi
}

is_true() {
  local value="${1:-}"
  [[ "$value" == "1" || "$value" == "true" || "$value" == "TRUE" ]]
}

CONFIG_FILE="scripts/deploy-entry-vm.env"
VM_NAME="wg-entry-free"
ZONE="us-west1-b"
PROJECT=""
MACHINE_TYPE="e2-micro"
IMAGE_FAMILY="debian-12"
IMAGE_PROJECT="debian-cloud"
NETWORK_TAGS="wg-entry"
ENSURE_FIREWALL="true"
FIREWALL_NETWORK="auto"
ALLOW_ENTRY_CIDRS="0.0.0.0/0"
ENTRY_BINARY_PATH="target/release/entry"
SKIP_BUILD=0
CREATE_ONLY=0

ENTRY_APP_ENV="development"
ENTRY_BIND_ADDR="0.0.0.0:8080"
ENTRY_ADMIN_API_TOKEN="dev-admin-token"
ENTRY_JWT_SIGNING_KEYS="v1:dev-only-signing-key-change-me"
ENTRY_ALLOW_LEGACY_CUSTOMER_HEADER="true"
ENTRY_REQUIRE_CORE_TLS="false"
ENTRY_CORE_GRPC_URL="https://127.0.0.1:50051"
ENTRY_CORE_TLS_DOMAIN=""
CORE_REQUIRE_CLIENT_CERT="false"
GOOGLE_OIDC_CLIENT_ID=""
GOOGLE_OIDC_CLIENT_SECRET=""
GOOGLE_OIDC_REDIRECT_URI=""
TLS_MODE="self-signed"
TLS_COMMON_NAME=""

TLS_SERVER_CRT_FILE="./secrets/server.crt"
TLS_SERVER_KEY_FILE="./secrets/server.key"
TLS_CA_FILE="./secrets/ca.pem"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CONFIG_FILE="$2"; shift 2 ;;
    *) break ;;
  esac
done

if [[ -f "$CONFIG_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm-name) VM_NAME="$2"; shift 2 ;;
    --zone) ZONE="$2"; shift 2 ;;
    --project) PROJECT="$2"; shift 2 ;;
    --machine-type) MACHINE_TYPE="$2"; shift 2 ;;
    --image-family) IMAGE_FAMILY="$2"; shift 2 ;;
    --image-project) IMAGE_PROJECT="$2"; shift 2 ;;
    --network-tags) NETWORK_TAGS="$2"; shift 2 ;;
    --ensure-firewall) ENSURE_FIREWALL="$2"; shift 2 ;;
    --firewall-network) FIREWALL_NETWORK="$2"; shift 2 ;;
    --allow-entry-cidrs) ALLOW_ENTRY_CIDRS="$2"; shift 2 ;;
    --entry-binary) ENTRY_BINARY_PATH="$2"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --create-only) CREATE_ONLY=1; shift ;;
    --entry-app-env) ENTRY_APP_ENV="$2"; shift 2 ;;
    --entry-bind-addr) ENTRY_BIND_ADDR="$2"; shift 2 ;;
    --entry-admin-token) ENTRY_ADMIN_API_TOKEN="$2"; shift 2 ;;
    --entry-jwt-signing-keys) ENTRY_JWT_SIGNING_KEYS="$2"; shift 2 ;;
    --google-oidc-client-id) GOOGLE_OIDC_CLIENT_ID="$2"; shift 2 ;;
    --google-oidc-client-secret) GOOGLE_OIDC_CLIENT_SECRET="$2"; shift 2 ;;
    --google-oidc-redirect-uri) GOOGLE_OIDC_REDIRECT_URI="$2"; shift 2 ;;
    --entry-allow-legacy-customer-header) ENTRY_ALLOW_LEGACY_CUSTOMER_HEADER="$2"; shift 2 ;;
    --entry-require-core-tls) ENTRY_REQUIRE_CORE_TLS="$2"; shift 2 ;;
    --entry-core-grpc-url) ENTRY_CORE_GRPC_URL="$2"; shift 2 ;;
    --entry-core-tls-domain) ENTRY_CORE_TLS_DOMAIN="$2"; shift 2 ;;
    --core-require-client-cert) CORE_REQUIRE_CLIENT_CERT="$2"; shift 2 ;;
    --tls-mode) TLS_MODE="$2"; shift 2 ;;
    --tls-common-name) TLS_COMMON_NAME="$2"; shift 2 ;;
    --tls-server-crt-file) TLS_SERVER_CRT_FILE="$2"; shift 2 ;;
    --tls-server-key-file) TLS_SERVER_KEY_FILE="$2"; shift 2 ;;
    --tls-ca-file) TLS_CA_FILE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

case "$ENSURE_FIREWALL" in
  1|0|true|false|TRUE|FALSE) ;;
  *)
    echo "invalid --ensure-firewall: $ENSURE_FIREWALL (expected true/false)" >&2
    exit 1
    ;;
esac

case "$TLS_MODE" in
  self-signed|upload) ;;
  *)
    echo "invalid --tls-mode: $TLS_MODE (expected self-signed or upload)" >&2
    exit 1
    ;;
esac

case "$ENTRY_REQUIRE_CORE_TLS" in
  1|0|true|false|TRUE|FALSE) ;;
  *)
    echo "invalid --entry-require-core-tls: $ENTRY_REQUIRE_CORE_TLS (expected true/false)" >&2
    exit 1
    ;;
esac

case "$CORE_REQUIRE_CLIENT_CERT" in
  1|0|true|false|TRUE|FALSE) ;;
  *)
    echo "invalid --core-require-client-cert: $CORE_REQUIRE_CLIENT_CERT (expected true/false)" >&2
    exit 1
    ;;
esac

if [[ -n "$GOOGLE_OIDC_CLIENT_ID" || -n "$GOOGLE_OIDC_CLIENT_SECRET" || -n "$GOOGLE_OIDC_REDIRECT_URI" ]]; then
  if [[ -z "$GOOGLE_OIDC_CLIENT_ID" || -z "$GOOGLE_OIDC_CLIENT_SECRET" || -z "$GOOGLE_OIDC_REDIRECT_URI" ]]; then
    echo "when configuring Google OIDC, provide all of: --google-oidc-client-id, --google-oidc-client-secret, --google-oidc-redirect-uri" >&2
    exit 1
  fi
fi

if [[ -z "$TLS_COMMON_NAME" ]]; then
  TLS_COMMON_NAME="$VM_NAME"
fi
if [[ -z "$ENTRY_CORE_TLS_DOMAIN" ]]; then
  ENTRY_CORE_TLS_DOMAIN="$TLS_COMMON_NAME"
fi

if [[ -z "$PROJECT" ]]; then
  PROJECT="$(gcloud config get-value project 2>/dev/null || true)"
fi
if [[ -z "$PROJECT" ]]; then
  echo "project is required (use --project or configure gcloud default project)" >&2
  exit 1
fi

require_core_tls="false"
require_client_cert="false"
if is_true "$ENTRY_REQUIRE_CORE_TLS"; then
  require_core_tls="true"
fi
if is_true "$CORE_REQUIRE_CLIENT_CERT"; then
  require_client_cert="true"
fi

if [[ "$require_client_cert" == "true" && "$require_core_tls" != "true" ]]; then
  echo "--core-require-client-cert=true requires --entry-require-core-tls=true" >&2
  exit 1
fi
if [[ "$require_core_tls" == "true" && "$TLS_MODE" != "upload" ]]; then
  echo "--entry-require-core-tls=true requires --tls-mode upload" >&2
  exit 1
fi
if [[ "$require_client_cert" == "true" && "$TLS_MODE" != "upload" ]]; then
  echo "--core-require-client-cert=true requires --tls-mode upload" >&2
  exit 1
fi

if [[ "$CREATE_ONLY" -eq 0 ]]; then
  if [[ "$require_core_tls" == "true" ]]; then
    require_file "$TLS_CA_FILE"
  fi
  if [[ "$require_client_cert" == "true" ]]; then
    require_file "$TLS_SERVER_CRT_FILE"
    require_file "$TLS_SERVER_KEY_FILE"
  fi
fi

require_cmd gcloud
if [[ "$SKIP_BUILD" -eq 0 ]]; then
  require_cmd cargo
  echo "Building entry binary..."
  cargo build --release -p entry
fi

if [[ "$CREATE_ONLY" -eq 0 ]]; then
  require_file "$ENTRY_BINARY_PATH"
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

upload_ca=0
upload_client_cert=0
if [[ "$CREATE_ONLY" -eq 0 ]]; then
  if [[ "$require_core_tls" == "true" ]]; then
    cp "$TLS_CA_FILE" "${tmpdir}/ca.pem"
    upload_ca=1
  fi
  if [[ "$require_client_cert" == "true" ]]; then
    cp "$TLS_SERVER_CRT_FILE" "${tmpdir}/client.crt"
    cp "$TLS_SERVER_KEY_FILE" "${tmpdir}/client.key"
    upload_client_cert=1
  fi
fi

cloud_init_file="${tmpdir}/cloud-init.yaml"
cat >"$cloud_init_file" <<'EOF_CLOUD'
#cloud-config
package_update: true
package_upgrade: false

packages:
  - ca-certificates

write_files:
  - path: /etc/systemd/system/wg-entry.service
    permissions: "0644"
    owner: root:root
    content: |
      [Unit]
      Description=WG Entry Service
      After=network-online.target
      Wants=network-online.target

      [Service]
      Type=simple
      EnvironmentFile=/etc/default/wg-entry
      ExecStart=/usr/local/bin/entry
      Restart=always
      RestartSec=2
      User=root

      [Install]
      WantedBy=multi-user.target

runcmd:
  - touch /etc/default/wg-entry
  - chmod 600 /etc/default/wg-entry
  - systemctl daemon-reload
EOF_CLOUD

entry_env_file="${tmpdir}/wg-entry.env"
cat >"$entry_env_file" <<EOF_ENV
APP_ENV=${ENTRY_APP_ENV}
ENTRY_BIND_ADDR=${ENTRY_BIND_ADDR}
CORE_GRPC_URL=${ENTRY_CORE_GRPC_URL}
CORE_GRPC_TLS_DOMAIN=${ENTRY_CORE_TLS_DOMAIN}
APP_REQUIRE_CORE_TLS=${ENTRY_REQUIRE_CORE_TLS}
APP_ALLOW_LEGACY_CUSTOMER_HEADER=${ENTRY_ALLOW_LEGACY_CUSTOMER_HEADER}
APP_JWT_SIGNING_KEYS=${ENTRY_JWT_SIGNING_KEYS}
APP_JWT_ACTIVE_KID=v1
ADMIN_API_TOKEN=${ENTRY_ADMIN_API_TOKEN}
EOF_ENV

if [[ "$require_core_tls" == "true" ]]; then
  echo "CORE_GRPC_TLS_CA_CERT_PATH=/etc/core-tls/ca.pem" >>"$entry_env_file"
fi
if [[ "$require_client_cert" == "true" ]]; then
  cat >>"$entry_env_file" <<'EOF_MTLS'
CORE_GRPC_TLS_CLIENT_CERT_PATH=/etc/core-tls/client.crt
CORE_GRPC_TLS_CLIENT_KEY_PATH=/etc/core-tls/client.key
EOF_MTLS
fi
if [[ -n "$GOOGLE_OIDC_CLIENT_ID" ]]; then
  cat >>"$entry_env_file" <<EOF_OIDC
GOOGLE_OIDC_CLIENT_ID=${GOOGLE_OIDC_CLIENT_ID}
GOOGLE_OIDC_CLIENT_SECRET=${GOOGLE_OIDC_CLIENT_SECRET}
GOOGLE_OIDC_REDIRECT_URI=${GOOGLE_OIDC_REDIRECT_URI}
EOF_OIDC
fi

GCLOUD_BASE=(gcloud --project "$PROJECT")

ensure_firewall_rule() {
  local name="$1"
  local rules="$2"
  local source_ranges="$3"
  local network="$4"
  local target_tags="$5"

  if "${GCLOUD_BASE[@]}" compute firewall-rules describe "$name" >/dev/null 2>&1; then
    echo "Firewall rule ${name} already exists; skipping."
    return 0
  fi

  echo "Creating firewall rule ${name} (${rules}, source=${source_ranges}, tags=${target_tags})..."
  "${GCLOUD_BASE[@]}" compute firewall-rules create "$name" \
    --network "$network" \
    --direction INGRESS \
    --priority 1000 \
    --action ALLOW \
    --rules "$rules" \
    --source-ranges "$source_ranges" \
    --target-tags "$target_tags"
}

if ! "${GCLOUD_BASE[@]}" compute instances describe "$VM_NAME" --zone "$ZONE" >/dev/null 2>&1; then
  echo "Creating VM ${VM_NAME}..."
  "${GCLOUD_BASE[@]}" compute instances create "$VM_NAME" \
    --zone "$ZONE" \
    --machine-type "$MACHINE_TYPE" \
    --image-family "$IMAGE_FAMILY" \
    --image-project "$IMAGE_PROJECT" \
    --tags "$NETWORK_TAGS" \
    --metadata-from-file "user-data=${cloud_init_file}"
else
  echo "VM ${VM_NAME} already exists; skipping create."
fi

if is_true "$ENSURE_FIREWALL"; then
  firewall_network_value="$FIREWALL_NETWORK"
  if [[ "$firewall_network_value" == "auto" ]]; then
    network_uri="$("${GCLOUD_BASE[@]}" compute instances describe "$VM_NAME" --zone "$ZONE" --format='get(networkInterfaces[0].network)')"
    firewall_network_value="${network_uri##*/}"
  fi
  if [[ -z "$firewall_network_value" ]]; then
    echo "failed to determine firewall network (set --firewall-network explicitly)" >&2
    exit 1
  fi

  rule_prefix="$(echo "$VM_NAME" | tr '[:upper:]_' '[:lower:]-' | tr -cd 'a-z0-9-')"
  if [[ -z "$rule_prefix" ]]; then
    rule_prefix="wg-entry"
  fi
  ensure_firewall_rule "${rule_prefix}-entry-8080" "tcp:8080" "$ALLOW_ENTRY_CIDRS" "$firewall_network_value" "$NETWORK_TAGS"
fi

if [[ "$CREATE_ONLY" -eq 1 ]]; then
  echo "Create-only mode complete."
  exit 0
fi

echo "Uploading entry binary and runtime files..."
scp_inputs=("$ENTRY_BINARY_PATH" "$entry_env_file")
if [[ "$upload_ca" -eq 1 ]]; then
  scp_inputs+=("${tmpdir}/ca.pem")
fi
if [[ "$upload_client_cert" -eq 1 ]]; then
  scp_inputs+=("${tmpdir}/client.crt" "${tmpdir}/client.key")
fi
"${GCLOUD_BASE[@]}" compute scp --zone "$ZONE" "${scp_inputs[@]}" "${VM_NAME}:/tmp/"

remote_install_script="${tmpdir}/remote-install.sh"
cat >"$remote_install_script" <<EOF_REMOTE
#!/usr/bin/env bash
set -euo pipefail

ENTRY_REQUIRE_CORE_TLS="${require_core_tls}"
CORE_REQUIRE_CLIENT_CERT="${require_client_cert}"

sudo install -m 0755 /tmp/entry /usr/local/bin/entry
sudo install -m 0600 /tmp/wg-entry.env /etc/default/wg-entry
cat <<'UNIT' | sudo tee /etc/systemd/system/wg-entry.service >/dev/null
[Unit]
Description=WG Entry Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/default/wg-entry
ExecStart=/usr/local/bin/entry
Restart=always
RestartSec=2
User=root

[Install]
WantedBy=multi-user.target
UNIT

need_apt=0
if ! command -v curl >/dev/null 2>&1; then
  need_apt=1
fi
if ! command -v jq >/dev/null 2>&1; then
  need_apt=1
fi
if [[ "\$need_apt" -eq 1 ]]; then
  sudo apt-get update
  sudo apt-get install -y curl jq
fi

if [[ "\$ENTRY_REQUIRE_CORE_TLS" == "true" || "\$CORE_REQUIRE_CLIENT_CERT" == "true" ]]; then
  sudo mkdir -p /etc/core-tls
  sudo chmod 700 /etc/core-tls
fi
if [[ "\$ENTRY_REQUIRE_CORE_TLS" == "true" ]]; then
  sudo install -m 0644 /tmp/ca.pem /etc/core-tls/ca.pem
fi
if [[ "\$CORE_REQUIRE_CLIENT_CERT" == "true" ]]; then
  sudo install -m 0644 /tmp/client.crt /etc/core-tls/client.crt
  sudo install -m 0600 /tmp/client.key /etc/core-tls/client.key
fi

sudo systemctl daemon-reload
sudo systemctl enable wg-entry
sudo systemctl reset-failed wg-entry || true
sudo systemctl restart wg-entry

wait_for_active() {
  local unit="\$1"
  local timeout_secs="\$2"
  local waited=0
  while ! sudo systemctl is-active --quiet "\$unit"; do
    sleep 1
    waited=\$((waited + 1))
    if [[ "\$waited" -ge "\$timeout_secs" ]]; then
      echo "Timed out waiting for \$unit to become active" >&2
      sudo systemctl --no-pager --full status "\$unit" || true
      sudo journalctl -u "\$unit" -n 120 --no-pager || true
      return 1
    fi
  done
}

wait_for_active wg-entry 120
if ! curl -fsS http://127.0.0.1:8080/healthz >/dev/null; then
  echo "entry healthz check failed" >&2
  sudo systemctl --no-pager --full status wg-entry || true
  sudo journalctl -u wg-entry -n 120 --no-pager || true
  exit 1
fi

sudo systemctl --no-pager --full status wg-entry
echo "Smoke test hint: curl -fsS http://127.0.0.1:8080/healthz"
EOF_REMOTE

"${GCLOUD_BASE[@]}" compute scp --zone "$ZONE" "$remote_install_script" "${VM_NAME}:/tmp/remote-install.sh"
"${GCLOUD_BASE[@]}" compute ssh "$VM_NAME" --zone "$ZONE" --command "bash /tmp/remote-install.sh"

VM_IP="$("${GCLOUD_BASE[@]}" compute instances describe "$VM_NAME" --zone "$ZONE" --format='get(networkInterfaces[0].accessConfigs[0].natIP)' || true)"
VM_INTERNAL_DNS="${VM_NAME}.c.${PROJECT}.internal"

echo "Done. Check live logs with:"
echo "  gcloud --project ${PROJECT} compute ssh ${VM_NAME} --zone ${ZONE} --command 'sudo journalctl -u wg-entry -f'"
if [[ -n "$GOOGLE_OIDC_CLIENT_ID" ]]; then
  echo "Google OIDC configured for entry (client id provided)."
fi
echo
echo "Quick on-VM smoke checks:"
echo "  gcloud --project ${PROJECT} compute ssh ${VM_NAME} --zone ${ZONE} --command 'curl -fsS http://127.0.0.1:8080/healthz'"

if [[ -n "$VM_IP" ]]; then
  echo
  echo "If firewall allows tcp:8080, you can test from your machine:"
  echo "  curl -fsS http://${VM_IP}:8080/healthz"
  echo "Client app base URL:"
  echo "  ENTRY_API_BASE_URL=http://${VM_IP}:8080"
fi

echo "Internal DNS name (for core VM):"
echo "  ENTRY_ADMIN_URL=http://${VM_INTERNAL_DNS}:8080"
