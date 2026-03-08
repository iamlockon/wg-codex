#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/deploy-core-vm.sh [options]

Defaults are free-tier oriented:
  vm-name=wg-core-free
  zone=us-west1-b
  machine-type=e2-micro
  image-family=debian-12
  image-project=debian-cloud
  network-tags=wg-core
  core-binary=target/release/core
  wg-private-key-file=./secrets/private.key
  tls-server-crt-file=./secrets/server.crt
  tls-server-key-file=./secrets/server.key
  tls-ca-file=./secrets/ca.pem
  config-file=scripts/deploy-core-vm.env (if present)

Optional options:
  --config <path>                   Optional env config file to source
  --project <id>                    GCP project id (default: gcloud config)
  --vm-name <name>                  GCE VM instance name
  --zone <zone>                     GCE zone (example: us-central1-a)
  --machine-type <type>             VM machine type (default: e2-micro)
  --image-family <name>             Image family (default: debian-12)
  --image-project <name>            Image project (default: debian-cloud)
  --network-tags <csv>              Comma-separated network tags (default: wg-core)
  --ensure-firewall <bool>          Create ingress firewall rules for VM tags (default: true)
  --firewall-network <name|auto>    VPC network for firewall rules (default: auto from VM NIC)
  --allow-wg-cidrs <csv>            Source CIDRs for wireguard udp/51820 (default: 0.0.0.0/0)
  --allow-core-grpc-cidrs <csv>     Optional source CIDRs for core grpc tcp/50051 (default: disabled)
  --wg-key-mode <generate|upload>   WG key handling (default: generate)
  --wg-server-public-key <key>      Optional override for WG server public key
  --wg-private-key-file <path>      Local WG private key (required if --wg-key-mode upload)
  --tls-mode <self-signed|upload>   TLS material handling (default: self-signed)
  --tls-server-crt-file <path>      Local server cert (required if --tls-mode upload)
  --tls-server-key-file <path>      Local server key (required if --tls-mode upload)
  --tls-ca-file <path>              Local CA cert (required if --tls-mode upload)
  --tls-common-name <name>          CN for self-signed cert (default: vm-name)
  --core-binary <path>              Prebuilt core binary path (default: target/release/core)
  --binary <path>                   Alias for --core-binary (backward-compatible)
  --core-cargo-features <csv>       Cargo features for core build (default: none)
  --wg-nat-driver <cli|native>      WG_NAT_DRIVER runtime mode (default: cli)
  --native-nft                      Convenience: --core-cargo-features native-nft + --wg-nat-driver native
  --skip-build                      Skip cargo build step
  --create-only                     Only create VM + cloud-init; skip upload/install
  --app-env <env>                   APP_ENV (default: production)
  --core-bind-addr <addr>           CORE_BIND_ADDR (default: 0.0.0.0:50051)
  --core-require-tls <bool>         CORE_REQUIRE_TLS (default: true)
  --core-require-client-cert <bool> Require client cert for core gRPC (default: false)
  --entry-admin-token <token>       Admin token used for node health/report registration in entry
  --register-node-in-entry <bool>   Upsert this core node into remote entry admin API (default: true)
  --entry-admin-url <url>           Entry admin base URL used for health + node registration
  --entry-node-region <region>      Region stored in entry node registry (default: derived from zone)
  --entry-node-country-code <code>  Optional country code metadata for node selection
  --entry-node-city-code <code>     Optional city code metadata for node selection
  --entry-node-pool <name>          Node pool metadata (default: standard)
  --entry-node-provider <name>      Node provider metadata (default: gcp-vm)
  --core-node-id <uuid>             Stable CORE_NODE_ID used for entry health reporting
  --wg-interface <name>             WG_INTERFACE (default: wg0)
  --wg-interface-cidr <cidr>        WG_INTERFACE_CIDR (default: 10.90.0.1/24)
  --wg-listen-port <port>           WG_LISTEN_PORT (default: 51820)
  --wg-endpoint-template <v|auto>   WG_ENDPOINT_TEMPLATE (default: auto -> <vm-public-ip>:wg-listen-port)
  --wg-egress-iface <name|auto>     WG_EGRESS_IFACE (default: auto)

Example:
  scripts/deploy-core-vm.sh --project my-project --entry-admin-url https://entry.example.com
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

require_pkg_config_lib() {
  local lib_name="$1"
  if ! pkg-config --exists "$lib_name"; then
    echo "missing build dependency for native nft: $lib_name (pkg-config lookup failed)" >&2
    echo "install locally (Debian/Ubuntu): sudo apt-get update && sudo apt-get install -y pkg-config libmnl-dev libnftnl-dev" >&2
    exit 1
  fi
}

is_true() {
  local value="${1:-}"
  [[ "$value" == "1" || "$value" == "true" || "$value" == "TRUE" ]]
}

endpoint_host_from_template() {
  local template="${1:-}"
  local host="$template"
  if [[ "$host" =~ ^\[(.+)\](:[0-9]+)?$ ]]; then
    printf '[%s]' "${BASH_REMATCH[1]}"
    return
  fi
  if [[ "$host" == *:* ]]; then
    host="${host%:*}"
  fi
  printf '%s' "$host"
}

CONFIG_FILE="scripts/deploy-core-vm.env"
VM_NAME="wg-core-free"
ZONE="us-west1-b"
PROJECT=""
MACHINE_TYPE="e2-micro"
IMAGE_FAMILY="debian-12"
IMAGE_PROJECT="debian-cloud"
NETWORK_TAGS="wg-core"
ENSURE_FIREWALL="true"
FIREWALL_NETWORK="auto"
ALLOW_WG_CIDRS="0.0.0.0/0"
ALLOW_CORE_GRPC_CIDRS=""
CORE_BINARY_PATH="target/release/core"
CORE_CARGO_FEATURES=""
WG_NAT_DRIVER="cli"
SKIP_BUILD=0
CREATE_ONLY=0

APP_ENV="production"
CORE_BIND_ADDR="0.0.0.0:50051"
CORE_REQUIRE_TLS="true"
CORE_REQUIRE_CLIENT_CERT="false"
WG_INTERFACE="wg0"
WG_INTERFACE_CIDR="10.90.0.1/24"
WG_LISTEN_PORT="51820"
WG_ENDPOINT_TEMPLATE="auto"
WG_EGRESS_IFACE="auto"
WG_SERVER_PUBLIC_KEY=""
WG_KEY_MODE="generate"
TLS_MODE="self-signed"
TLS_COMMON_NAME=""

ENTRY_ADMIN_API_TOKEN=""
REGISTER_NODE_IN_ENTRY="true"
ENTRY_ADMIN_URL=""
ENTRY_NODE_REGION=""
ENTRY_NODE_COUNTRY_CODE=""
ENTRY_NODE_CITY_CODE=""
ENTRY_NODE_POOL="standard"
ENTRY_NODE_PROVIDER="gcp-vm"
CORE_NODE_ID=""
CORE_ENTRY_HEALTH_URL=""
CORE_ENTRY_NODE_UPSERT_URL=""

WG_PRIVATE_KEY_FILE="./secrets/private.key"
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
    --allow-wg-cidrs) ALLOW_WG_CIDRS="$2"; shift 2 ;;
    --allow-core-grpc-cidrs) ALLOW_CORE_GRPC_CIDRS="$2"; shift 2 ;;
    --wg-key-mode) WG_KEY_MODE="$2"; shift 2 ;;
    --core-binary|--binary) CORE_BINARY_PATH="$2"; shift 2 ;;
    --core-cargo-features) CORE_CARGO_FEATURES="$2"; shift 2 ;;
    --wg-nat-driver) WG_NAT_DRIVER="$2"; shift 2 ;;
    --native-nft)
      if [[ -z "$CORE_CARGO_FEATURES" ]]; then
        CORE_CARGO_FEATURES="native-nft"
      elif [[ ",$CORE_CARGO_FEATURES," != *",native-nft,"* ]]; then
        CORE_CARGO_FEATURES="${CORE_CARGO_FEATURES},native-nft"
      fi
      WG_NAT_DRIVER="native"
      shift
      ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --create-only) CREATE_ONLY=1; shift ;;
    --app-env) APP_ENV="$2"; shift 2 ;;
    --core-bind-addr) CORE_BIND_ADDR="$2"; shift 2 ;;
    --core-require-tls) CORE_REQUIRE_TLS="$2"; shift 2 ;;
    --core-require-client-cert) CORE_REQUIRE_CLIENT_CERT="$2"; shift 2 ;;
    --entry-admin-token) ENTRY_ADMIN_API_TOKEN="$2"; shift 2 ;;
    --register-node-in-entry) REGISTER_NODE_IN_ENTRY="$2"; shift 2 ;;
    --entry-admin-url) ENTRY_ADMIN_URL="$2"; shift 2 ;;
    --entry-node-region) ENTRY_NODE_REGION="$2"; shift 2 ;;
    --entry-node-country-code) ENTRY_NODE_COUNTRY_CODE="$2"; shift 2 ;;
    --entry-node-city-code) ENTRY_NODE_CITY_CODE="$2"; shift 2 ;;
    --entry-node-pool) ENTRY_NODE_POOL="$2"; shift 2 ;;
    --entry-node-provider) ENTRY_NODE_PROVIDER="$2"; shift 2 ;;
    --core-node-id) CORE_NODE_ID="$2"; shift 2 ;;
    --wg-interface) WG_INTERFACE="$2"; shift 2 ;;
    --wg-interface-cidr) WG_INTERFACE_CIDR="$2"; shift 2 ;;
    --wg-listen-port) WG_LISTEN_PORT="$2"; shift 2 ;;
    --wg-endpoint-template) WG_ENDPOINT_TEMPLATE="$2"; shift 2 ;;
    --wg-egress-iface) WG_EGRESS_IFACE="$2"; shift 2 ;;
    --wg-server-public-key) WG_SERVER_PUBLIC_KEY="$2"; shift 2 ;;
    --tls-mode) TLS_MODE="$2"; shift 2 ;;
    --tls-common-name) TLS_COMMON_NAME="$2"; shift 2 ;;
    --wg-private-key-file) WG_PRIVATE_KEY_FILE="$2"; shift 2 ;;
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

if [[ "$WG_KEY_MODE" == "upload" && -z "$WG_SERVER_PUBLIC_KEY" && -f "./secrets/server_public.key" ]]; then
  WG_SERVER_PUBLIC_KEY="$(tr -d '\r\n' < ./secrets/server_public.key)"
fi

case "$WG_KEY_MODE" in
  generate|upload) ;;
  *)
    echo "invalid --wg-key-mode: $WG_KEY_MODE (expected generate or upload)" >&2
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

case "$WG_NAT_DRIVER" in
  cli|native) ;;
  *)
    echo "invalid --wg-nat-driver: $WG_NAT_DRIVER (expected cli or native)" >&2
    exit 1
    ;;
esac

case "$ENSURE_FIREWALL" in
  1|0|true|false|TRUE|FALSE) ;;
  *)
    echo "invalid --ensure-firewall: $ENSURE_FIREWALL (expected true/false)" >&2
    exit 1
    ;;
esac

case "$REGISTER_NODE_IN_ENTRY" in
  1|0|true|false|TRUE|FALSE) ;;
  *)
    echo "invalid --register-node-in-entry: $REGISTER_NODE_IN_ENTRY (expected true/false)" >&2
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

if [[ -z "$TLS_COMMON_NAME" ]]; then
  TLS_COMMON_NAME="$VM_NAME"
fi

if [[ -z "$PROJECT" ]]; then
  PROJECT="$(gcloud config get-value project 2>/dev/null || true)"
fi
if [[ -z "$PROJECT" ]]; then
  echo "project is required (use --project or configure gcloud default project)" >&2
  exit 1
fi

if [[ -n "$ENTRY_ADMIN_URL" ]]; then
  if [[ "$ENTRY_ADMIN_URL" != *"://"* ]]; then
    ENTRY_ADMIN_URL="http://${ENTRY_ADMIN_URL}"
  elif [[ "$ENTRY_ADMIN_URL" != http://* && "$ENTRY_ADMIN_URL" != https://* ]]; then
    echo "invalid --entry-admin-url: $ENTRY_ADMIN_URL (expected http:// or https://)" >&2
    exit 1
  fi
fi

health_reporting_enabled="false"
if [[ -n "$ENTRY_ADMIN_URL" && -n "$ENTRY_ADMIN_API_TOKEN" ]]; then
  health_reporting_enabled="true"
  CORE_ENTRY_HEALTH_URL="${ENTRY_ADMIN_URL%/}/v1/internal/nodes/health"
fi

if is_true "$REGISTER_NODE_IN_ENTRY"; then
  if [[ -z "$ENTRY_ADMIN_URL" ]]; then
    echo "--entry-admin-url is required when --register-node-in-entry=true" >&2
    exit 1
  fi
  if [[ -z "$ENTRY_ADMIN_API_TOKEN" ]]; then
    echo "--entry-admin-token is required when --register-node-in-entry=true" >&2
    exit 1
  fi
  health_reporting_enabled="true"
  CORE_ENTRY_HEALTH_URL="${ENTRY_ADMIN_URL%/}/v1/internal/nodes/health"
  CORE_ENTRY_NODE_UPSERT_URL="${ENTRY_ADMIN_URL%/}/v1/admin/nodes"
  if [[ -z "$ENTRY_NODE_REGION" ]]; then
    ENTRY_NODE_REGION="${ZONE%-*}"
  fi
fi

if [[ -z "$CORE_NODE_ID" && "$health_reporting_enabled" == "true" ]]; then
  if command -v sha256sum >/dev/null 2>&1; then
    node_seed="${PROJECT}:${ZONE}:${VM_NAME}"
    node_hash="$(printf '%s' "$node_seed" | sha256sum | awk '{print $1}')"
    CORE_NODE_ID="${node_hash:0:8}-${node_hash:8:4}-${node_hash:12:4}-${node_hash:16:4}-${node_hash:20:12}"
  else
    CORE_NODE_ID="$(cat /proc/sys/kernel/random/uuid)"
  fi
fi
if [[ -n "$CORE_NODE_ID" && ! "$CORE_NODE_ID" =~ ^[0-9a-fA-F-]{36}$ ]]; then
  echo "invalid --core-node-id: $CORE_NODE_ID (expected UUID format)" >&2
  exit 1
fi

require_cmd gcloud
if [[ "$SKIP_BUILD" -eq 0 ]]; then
  require_cmd cargo
  if [[ "$WG_NAT_DRIVER" == "native" || ",$CORE_CARGO_FEATURES," == *",native-nft,"* ]]; then
    require_cmd pkg-config
    require_pkg_config_lib libmnl
    require_pkg_config_lib libnftnl
  fi
fi

if [[ "$CREATE_ONLY" -eq 0 ]]; then
  if [[ "$WG_KEY_MODE" == "upload" ]]; then
    require_file "$WG_PRIVATE_KEY_FILE"
  fi
  if [[ "$TLS_MODE" == "upload" ]]; then
    require_file "$TLS_SERVER_CRT_FILE"
    require_file "$TLS_SERVER_KEY_FILE"
    require_file "$TLS_CA_FILE"
  fi
fi

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  echo "Building core binary..."
  core_build_cmd=(cargo build --release -p core)
  if [[ -n "$CORE_CARGO_FEATURES" ]]; then
    core_build_cmd+=(--features "$CORE_CARGO_FEATURES")
  fi
  "${core_build_cmd[@]}"
fi

if [[ "$CREATE_ONLY" -eq 0 ]]; then
  require_file "$CORE_BINARY_PATH"
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

if [[ "$WG_KEY_MODE" == "upload" ]]; then
  cp "$WG_PRIVATE_KEY_FILE" "${tmpdir}/private.key"
fi
if [[ "$TLS_MODE" == "upload" ]]; then
  cp "$TLS_SERVER_CRT_FILE" "${tmpdir}/server.crt"
  cp "$TLS_SERVER_KEY_FILE" "${tmpdir}/server.key"
  cp "$TLS_CA_FILE" "${tmpdir}/ca.pem"
fi

cloud_init_file="${tmpdir}/cloud-init.yaml"
cat >"$cloud_init_file" <<'EOF_CLOUD'
#cloud-config
package_update: true
package_upgrade: false

packages:
  - ca-certificates
  - iproute2
  - nftables
  - openssl
  - wireguard-tools

write_files:
  - path: /etc/systemd/system/wg-core.service
    permissions: "0644"
    owner: root:root
    content: |
      [Unit]
      Description=WG Core Service
      After=network-online.target
      Wants=network-online.target

      [Service]
      Type=simple
      EnvironmentFile=/etc/default/wg-core
      ExecStart=/usr/local/bin/core
      Restart=always
      RestartSec=2
      User=root

      [Install]
      WantedBy=multi-user.target

runcmd:
  - modprobe wireguard
  - mkdir -p /etc/wireguard /etc/core-tls
  - chmod 700 /etc/wireguard /etc/core-tls
  - touch /etc/default/wg-core
  - chmod 600 /etc/default/wg-core
  - systemctl daemon-reload
EOF_CLOUD

env_file="${tmpdir}/wg-core.env"
wg_server_public_key_value="$WG_SERVER_PUBLIC_KEY"
if [[ -z "$wg_server_public_key_value" ]]; then
  wg_server_public_key_value="__AUTO_WG_SERVER_PUBLIC_KEY__"
fi

cat >"$env_file" <<EOF_ENV
APP_ENV=${APP_ENV}
CORE_BIND_ADDR=${CORE_BIND_ADDR}
CORE_DATAPLANE_NOOP=false
CORE_REQUIRE_TLS=${CORE_REQUIRE_TLS}

WG_INTERFACE=${WG_INTERFACE}
WG_INTERFACE_CIDR=${WG_INTERFACE_CIDR}
WG_PRIVATE_KEY_PATH=/etc/wireguard/private.key
WG_LISTEN_PORT=${WG_LISTEN_PORT}
WG_ENDPOINT_TEMPLATE=__AUTO_WG_ENDPOINT_TEMPLATE__
WG_EGRESS_IFACE=${WG_EGRESS_IFACE}
WG_NAT_DRIVER=${WG_NAT_DRIVER}
WG_SERVER_PUBLIC_KEY=${wg_server_public_key_value}

CORE_TLS_CERT_PATH=/etc/core-tls/server.crt
CORE_TLS_KEY_PATH=/etc/core-tls/server.key
EOF_ENV

if is_true "$CORE_REQUIRE_CLIENT_CERT"; then
  echo "CORE_TLS_CLIENT_CA_CERT_PATH=/etc/core-tls/ca.pem" >>"$env_file"
fi
if [[ "$health_reporting_enabled" == "true" ]]; then
  cat >>"$env_file" <<EOF_HEALTH
CORE_NODE_ID=${CORE_NODE_ID}
CORE_ENTRY_HEALTH_URL=${CORE_ENTRY_HEALTH_URL}
ADMIN_API_TOKEN=${ENTRY_ADMIN_API_TOKEN}
EOF_HEALTH
  if is_true "$REGISTER_NODE_IN_ENTRY"; then
    cat >>"$env_file" <<EOF_REGISTER
CORE_ENTRY_NODE_UPSERT_URL=${CORE_ENTRY_NODE_UPSERT_URL}
CORE_ENTRY_NODE_REGION=${ENTRY_NODE_REGION}
CORE_ENTRY_NODE_COUNTRY_CODE=${ENTRY_NODE_COUNTRY_CODE}
CORE_ENTRY_NODE_CITY_CODE=${ENTRY_NODE_CITY_CODE}
CORE_ENTRY_NODE_POOL=${ENTRY_NODE_POOL}
CORE_ENTRY_NODE_PROVIDER=${ENTRY_NODE_PROVIDER}
CORE_ENTRY_NODE_ENDPOINT_HOST=__AUTO_ENTRY_NODE_ENDPOINT_HOST__
CORE_ENTRY_NODE_ENDPOINT_PORT=${WG_LISTEN_PORT}
CORE_ENTRY_NODE_CAPACITY_PEERS=200
EOF_REGISTER
  fi
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
    rule_prefix="wg-core"
  fi

  ensure_firewall_rule "${rule_prefix}-wg-51820-udp" "udp:51820" "$ALLOW_WG_CIDRS" "$firewall_network_value" "$NETWORK_TAGS"
  if [[ -n "$ALLOW_CORE_GRPC_CIDRS" ]]; then
    ensure_firewall_rule "${rule_prefix}-core-50051" "tcp:50051" "$ALLOW_CORE_GRPC_CIDRS" "$firewall_network_value" "$NETWORK_TAGS"
  fi
fi

VM_IP="$("${GCLOUD_BASE[@]}" compute instances describe "$VM_NAME" --zone "$ZONE" --format='get(networkInterfaces[0].accessConfigs[0].natIP)' || true)"
effective_wg_endpoint_template="$WG_ENDPOINT_TEMPLATE"
if [[ "$WG_ENDPOINT_TEMPLATE" == "auto" ]]; then
  if [[ -z "$VM_IP" ]]; then
    echo "failed to resolve VM public IP for --wg-endpoint-template auto; pass --wg-endpoint-template explicitly" >&2
    exit 1
  fi
  effective_wg_endpoint_template="${VM_IP}:${WG_LISTEN_PORT}"
fi

entry_node_endpoint_host="$VM_IP"
if [[ -z "$entry_node_endpoint_host" ]]; then
  entry_node_endpoint_host="$(endpoint_host_from_template "$effective_wg_endpoint_template")"
fi
if is_true "$REGISTER_NODE_IN_ENTRY" && [[ -z "$entry_node_endpoint_host" ]]; then
  echo "failed to determine node endpoint host for entry registration" >&2
  exit 1
fi

awk -v tmpl="$effective_wg_endpoint_template" '
  BEGIN { updated = 0 }
  /^WG_ENDPOINT_TEMPLATE=/ {
    print "WG_ENDPOINT_TEMPLATE=" tmpl
    updated = 1
    next
  }
  { print }
  END {
    if (!updated) {
      print "WG_ENDPOINT_TEMPLATE=" tmpl
    }
  }
' "$env_file" >"${env_file}.tmp"
mv "${env_file}.tmp" "$env_file"

if [[ "$health_reporting_enabled" == "true" ]] && is_true "$REGISTER_NODE_IN_ENTRY"; then
  awk -v host="$entry_node_endpoint_host" '
    BEGIN { updated = 0 }
    /^CORE_ENTRY_NODE_ENDPOINT_HOST=/ {
      print "CORE_ENTRY_NODE_ENDPOINT_HOST=" host
      updated = 1
      next
    }
    { print }
    END {
      if (!updated) {
        print "CORE_ENTRY_NODE_ENDPOINT_HOST=" host
      }
    }
  ' "$env_file" >"${env_file}.tmp"
  mv "${env_file}.tmp" "$env_file"
fi

if [[ "$CREATE_ONLY" -eq 1 ]]; then
  echo "Create-only mode complete."
  exit 0
fi

echo "Uploading core binary and runtime files..."
scp_inputs=("$CORE_BINARY_PATH" "$env_file")
if [[ "$WG_KEY_MODE" == "upload" ]]; then
  scp_inputs+=("${tmpdir}/private.key")
fi
if [[ "$TLS_MODE" == "upload" ]]; then
  scp_inputs+=("${tmpdir}/server.crt" "${tmpdir}/server.key" "${tmpdir}/ca.pem")
fi
"${GCLOUD_BASE[@]}" compute scp --zone "$ZONE" "${scp_inputs[@]}" "${VM_NAME}:/tmp/"

remote_install_script="${tmpdir}/remote-install.sh"
cat >"$remote_install_script" <<EOF_REMOTE
#!/usr/bin/env bash
set -euo pipefail

WG_KEY_MODE="${WG_KEY_MODE}"
TLS_MODE="${TLS_MODE}"
TLS_COMMON_NAME="${TLS_COMMON_NAME}"
WG_SERVER_PUBLIC_KEY_VALUE="${wg_server_public_key_value}"

sudo install -m 0755 /tmp/core /usr/local/bin/core
sudo install -m 0600 /tmp/wg-core.env /etc/default/wg-core
cat <<'UNIT' | sudo tee /etc/systemd/system/wg-core.service >/dev/null
[Unit]
Description=WG Core Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/default/wg-core
ExecStart=/usr/local/bin/core
Restart=always
RestartSec=2
User=root

[Install]
WantedBy=multi-user.target
UNIT

sudo mkdir -p /etc/wireguard /etc/core-tls
sudo chmod 700 /etc/wireguard /etc/core-tls

need_apt=0
if ! command -v wg >/dev/null 2>&1; then
  need_apt=1
fi
if [[ "\$TLS_MODE" == "self-signed" ]] && ! command -v openssl >/dev/null 2>&1; then
  need_apt=1
fi
if ! command -v nft >/dev/null 2>&1; then
  need_apt=1
fi
if ! command -v ip >/dev/null 2>&1; then
  need_apt=1
fi
if ! command -v uuidgen >/dev/null 2>&1; then
  need_apt=1
fi
if [[ "\$need_apt" -eq 1 ]]; then
  sudo apt-get update
  sudo apt-get install -y wireguard-tools openssl nftables iproute2 uuid-runtime
fi

if [[ "\$WG_KEY_MODE" == "upload" ]]; then
  sudo install -m 0600 /tmp/private.key /etc/wireguard/private.key
elif [[ ! -s /etc/wireguard/private.key ]]; then
  sudo sh -c 'umask 077; wg genkey > /etc/wireguard/private.key'
fi

if [[ "\$WG_SERVER_PUBLIC_KEY_VALUE" == "__AUTO_WG_SERVER_PUBLIC_KEY__" ]]; then
  wg_pub="\$(sudo sh -c 'wg pubkey < /etc/wireguard/private.key')"
else
  wg_pub="\$WG_SERVER_PUBLIC_KEY_VALUE"
fi
wg_pub_escaped="\${wg_pub//&/\\&}"
sudo sed -i "s|^WG_SERVER_PUBLIC_KEY=.*$|WG_SERVER_PUBLIC_KEY=\${wg_pub_escaped}|" /etc/default/wg-core

egress_iface_value="\$(sudo awk -F= '/^WG_EGRESS_IFACE=/{print \$2}' /etc/default/wg-core | tr -d '\r\n')"
if [[ -z "\$egress_iface_value" || "\$egress_iface_value" == "auto" ]]; then
  detected_iface="\$(ip -4 route list default 2>/dev/null | awk '{print \$5; exit}')"
  if [[ -z "\$detected_iface" ]]; then
    detected_iface="\$(ip route list default 2>/dev/null | awk '{print \$5; exit}')"
  fi
  if [[ -z "\$detected_iface" ]]; then
    echo "failed to detect default egress interface; set --wg-egress-iface explicitly" >&2
    exit 1
  fi
  egress_iface_value="\$detected_iface"
fi
sudo awk -v iface="\$egress_iface_value" '
  BEGIN { updated = 0 }
  /^WG_EGRESS_IFACE=/ {
    print "WG_EGRESS_IFACE=" iface
    updated = 1
    next
  }
  { print }
  END {
    if (!updated) {
      print "WG_EGRESS_IFACE=" iface
    }
  }
' /etc/default/wg-core | sudo tee /etc/default/wg-core.tmp >/dev/null
sudo mv /etc/default/wg-core.tmp /etc/default/wg-core

if [[ "\$TLS_MODE" == "upload" ]]; then
  sudo install -m 0644 /tmp/server.crt /etc/core-tls/server.crt
  sudo install -m 0600 /tmp/server.key /etc/core-tls/server.key
  sudo install -m 0644 /tmp/ca.pem /etc/core-tls/ca.pem
elif [[ ! -s /etc/core-tls/server.crt || ! -s /etc/core-tls/server.key || ! -s /etc/core-tls/ca.pem ]]; then
  tmp_tls_dir="\$(mktemp -d)"
  cleanup_tls() {
    rm -rf "\$tmp_tls_dir"
  }
  trap cleanup_tls EXIT

  cat >"\$tmp_tls_dir/ca.cnf" <<CFG
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[dn]
CN = ${TLS_COMMON_NAME}-ca

[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
CFG

  cat >"\$tmp_tls_dir/server.cnf" <<CFG
[req]
distinguished_name = dn
prompt = no

[dn]
CN = ${TLS_COMMON_NAME}

[v3_server]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${TLS_COMMON_NAME}
DNS.2 = localhost
IP.1 = 127.0.0.1
CFG

  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
    -keyout "\$tmp_tls_dir/ca.key" \
    -out "\$tmp_tls_dir/ca.pem" \
    -config "\$tmp_tls_dir/ca.cnf"

  openssl req -new -newkey rsa:2048 -sha256 -nodes \
    -keyout "\$tmp_tls_dir/server.key" \
    -out "\$tmp_tls_dir/server.csr" \
    -config "\$tmp_tls_dir/server.cnf"

  openssl x509 -req -in "\$tmp_tls_dir/server.csr" \
    -CA "\$tmp_tls_dir/ca.pem" \
    -CAkey "\$tmp_tls_dir/ca.key" \
    -CAcreateserial \
    -out "\$tmp_tls_dir/server.crt" \
    -days 825 -sha256 \
    -extfile "\$tmp_tls_dir/server.cnf" -extensions v3_server

  sudo install -m 0600 "\$tmp_tls_dir/server.key" /etc/core-tls/server.key
  sudo install -m 0644 "\$tmp_tls_dir/server.crt" /etc/core-tls/server.crt
  sudo install -m 0644 "\$tmp_tls_dir/ca.pem" /etc/core-tls/ca.pem

  trap - EXIT
  cleanup_tls
fi

sudo modprobe wireguard
sudo systemctl daemon-reload
sudo systemctl enable wg-core
sudo systemctl reset-failed wg-core || true
sudo systemctl restart wg-core

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

wait_for_port() {
  local port="\$1"
  local timeout_secs="\$2"
  local waited=0
  while ! sudo ss -ltn | grep -Eq "LISTEN.+(:|\.)\${port}[[:space:]]"; do
    sleep 1
    waited=\$((waited + 1))
    if [[ "\$waited" -ge "\$timeout_secs" ]]; then
      echo "Timed out waiting for port \$port" >&2
      sudo ss -ltn || true
      return 1
    fi
  done
}

set_core_nat_driver() {
  local nat_driver="\$1"
  sudo awk -v drv="\$nat_driver" '
    BEGIN { updated = 0 }
    /^WG_NAT_DRIVER=/ {
      print "WG_NAT_DRIVER=" drv
      updated = 1
      next
    }
    { print }
    END {
      if (!updated) {
        print "WG_NAT_DRIVER=" drv
      }
    }
  ' /etc/default/wg-core | sudo tee /etc/default/wg-core.tmp >/dev/null
  sudo mv /etc/default/wg-core.tmp /etc/default/wg-core
}

wait_for_active wg-core 120
core_bind_addr="\$(sudo awk -F= '/^CORE_BIND_ADDR=/{print \$2}' /etc/default/wg-core | tr -d '\r\n')"
core_bind_port="\${core_bind_addr##*:}"
if [[ ! "\$core_bind_port" =~ ^[0-9]+$ ]]; then
  core_bind_port="50051"
fi
core_nat_driver="\$(sudo awk -F= '/^WG_NAT_DRIVER=/{print \$2}' /etc/default/wg-core | tr -d '\r\n')"
if [[ -z "\$core_nat_driver" ]]; then
  core_nat_driver="cli"
fi

if ! wait_for_port "\$core_bind_port" 120; then
  if [[ "\$core_nat_driver" == "native" ]]; then
    echo "core did not open gRPC port with WG_NAT_DRIVER=native; falling back to WG_NAT_DRIVER=cli"
    set_core_nat_driver cli
    sudo systemctl reset-failed wg-core || true
    sudo systemctl restart wg-core
    wait_for_active wg-core 120
    wait_for_port "\$core_bind_port" 120 || {
      sudo systemctl --no-pager --full status wg-core || true
      sudo journalctl -u wg-core -n 200 --no-pager || true
      exit 1
    }
  else
    sudo systemctl --no-pager --full status wg-core || true
    sudo journalctl -u wg-core -n 200 --no-pager || true
    exit 1
  fi
fi

sudo systemctl --no-pager --full status wg-core
echo "Smoke test hint: sudo ss -ltn | grep :\$core_bind_port"
EOF_REMOTE

"${GCLOUD_BASE[@]}" compute scp --zone "$ZONE" "$remote_install_script" "${VM_NAME}:/tmp/remote-install.sh"
"${GCLOUD_BASE[@]}" compute ssh "$VM_NAME" --zone "$ZONE" --command "bash /tmp/remote-install.sh"

if [[ -z "$VM_IP" ]]; then
  VM_IP="$("${GCLOUD_BASE[@]}" compute instances describe "$VM_NAME" --zone "$ZONE" --format='get(networkInterfaces[0].accessConfigs[0].natIP)' || true)"
fi
EFFECTIVE_NAT_DRIVER="$("${GCLOUD_BASE[@]}" compute ssh "$VM_NAME" --zone "$ZONE" --command "sudo awk -F= '/^WG_NAT_DRIVER=/{print \$2}' /etc/default/wg-core | tr -d '\r\n'" 2>/dev/null || true)"
EFFECTIVE_WG_ENDPOINT_TEMPLATE="$("${GCLOUD_BASE[@]}" compute ssh "$VM_NAME" --zone "$ZONE" --command "sudo awk -F= '/^WG_ENDPOINT_TEMPLATE=/{print \$2}' /etc/default/wg-core | tr -d '\r\n'" 2>/dev/null || true)"

echo "Done. Check live logs with:"
echo "  gcloud --project ${PROJECT} compute ssh ${VM_NAME} --zone ${ZONE} --command 'sudo journalctl -u wg-core -f'"
if [[ -n "$EFFECTIVE_NAT_DRIVER" ]]; then
  echo "Effective WG_NAT_DRIVER=${EFFECTIVE_NAT_DRIVER}"
fi
if [[ -n "$EFFECTIVE_WG_ENDPOINT_TEMPLATE" ]]; then
  echo "Effective WG_ENDPOINT_TEMPLATE=${EFFECTIVE_WG_ENDPOINT_TEMPLATE}"
fi
if [[ "$health_reporting_enabled" == "true" ]]; then
  echo "CORE_NODE_ID=${CORE_NODE_ID}"
  echo "CORE_ENTRY_HEALTH_URL=${CORE_ENTRY_HEALTH_URL}"
fi

echo
echo "Quick on-VM checks:"
echo "  gcloud --project ${PROJECT} compute ssh ${VM_NAME} --zone ${ZONE} --command 'sudo systemctl status wg-core --no-pager'"

if is_true "$REGISTER_NODE_IN_ENTRY"; then
  echo "Core node registration is configured in /etc/default/wg-core and performed by core at startup."
fi
