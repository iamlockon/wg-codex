#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
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
  entry-binary=target/release/entry
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
  --allow-entry-cidrs <csv>         Source CIDRs for entry tcp/8080 (default: 0.0.0.0/0)
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
  --entry-binary <path>             Prebuilt entry binary path (default: target/release/entry)
  --binary <path>                   Alias for --core-binary (backward-compatible)
  --core-cargo-features <csv>       Cargo features for core build (default: none)
  --wg-nat-driver <cli|native>      WG_NAT_DRIVER runtime mode (default: cli)
  --native-nft                       Convenience: --core-cargo-features native-nft + --wg-nat-driver native
  --skip-build                       Skip cargo build step
  --entry-app-env <env>             Entry APP_ENV (default: development)
  --entry-bind-addr <addr>          ENTRY_BIND_ADDR (default: 0.0.0.0:8080)
  --entry-admin-token <token>       ADMIN_API_TOKEN for entry admin routes
  --entry-jwt-signing-keys <value>  APP_JWT_SIGNING_KEYS for entry JWT issuance
  --google-oidc-client-id <id>      GOOGLE_OIDC_CLIENT_ID for entry OAuth
  --google-oidc-client-secret <v>   GOOGLE_OIDC_CLIENT_SECRET for entry OAuth
  --google-oidc-redirect-uri <uri>  GOOGLE_OIDC_REDIRECT_URI for entry OAuth
  --entry-allow-legacy-customer-header <bool>
                                    APP_ALLOW_LEGACY_CUSTOMER_HEADER (default: true)
  --entry-require-core-tls <bool>   APP_REQUIRE_CORE_TLS in entry (default: true)
  --entry-core-grpc-url <url>       CORE_GRPC_URL from entry to core (default: https://127.0.0.1:50051)
  --entry-core-tls-domain <name>    CORE_GRPC_TLS_DOMAIN (default: tls-common-name)
  --core-bind-addr <addr>           CORE_BIND_ADDR (default: 0.0.0.0:50051)
  --core-require-client-cert <bool> Require client cert for core gRPC (default: false)
  --wg-interface <name>             WG_INTERFACE (default: wg0)
  --wg-interface-cidr <cidr>        WG_INTERFACE_CIDR (default: 10.90.0.1/24)
  --wg-listen-port <port>           WG_LISTEN_PORT (default: 51820)
  --wg-endpoint-template <v|auto>   WG_ENDPOINT_TEMPLATE for client endpoint (default: auto -> <vm-public-ip>:wg-listen-port)
  --wg-egress-iface <name|auto>     WG_EGRESS_IFACE (default: auto)
  --app-env <env>                   APP_ENV (default: production)
  --core-require-tls <bool>         CORE_REQUIRE_TLS (default: true)
  --create-only                      Only create VM + cloud-init; skip upload/install

Example:
  scripts/deploy-core-vm.sh \
    --project my-project
EOF
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
ALLOW_ENTRY_CIDRS="0.0.0.0/0"
ALLOW_WG_CIDRS="0.0.0.0/0"
ALLOW_CORE_GRPC_CIDRS=""
CORE_BINARY_PATH="target/release/core"
ENTRY_BINARY_PATH="target/release/entry"
CORE_CARGO_FEATURES=""
WG_NAT_DRIVER="cli"
SKIP_BUILD=0
CREATE_ONLY=0

APP_ENV="production"
CORE_BIND_ADDR="0.0.0.0:50051"
CORE_REQUIRE_TLS="true"
CORE_REQUIRE_CLIENT_CERT="false"
ENTRY_APP_ENV="development"
ENTRY_BIND_ADDR="0.0.0.0:8080"
ENTRY_ADMIN_API_TOKEN="dev-admin-token"
ENTRY_JWT_SIGNING_KEYS="v1:dev-only-signing-key-change-me"
ENTRY_ALLOW_LEGACY_CUSTOMER_HEADER="true"
ENTRY_REQUIRE_CORE_TLS="true"
ENTRY_CORE_GRPC_URL="https://127.0.0.1:50051"
ENTRY_CORE_TLS_DOMAIN=""
WG_INTERFACE="wg0"
WG_INTERFACE_CIDR="10.90.0.1/24"
WG_LISTEN_PORT="51820"
WG_ENDPOINT_TEMPLATE="auto"
WG_EGRESS_IFACE="auto"
WG_SERVER_PUBLIC_KEY=""
WG_KEY_MODE="generate"
TLS_MODE="self-signed"
TLS_COMMON_NAME=""
GOOGLE_OIDC_CLIENT_ID=""
GOOGLE_OIDC_CLIENT_SECRET=""
GOOGLE_OIDC_REDIRECT_URI=""
VM_IP=""

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
    --allow-entry-cidrs) ALLOW_ENTRY_CIDRS="$2"; shift 2 ;;
    --allow-wg-cidrs) ALLOW_WG_CIDRS="$2"; shift 2 ;;
    --allow-core-grpc-cidrs) ALLOW_CORE_GRPC_CIDRS="$2"; shift 2 ;;
    --wg-key-mode) WG_KEY_MODE="$2"; shift 2 ;;
    --core-binary|--binary) CORE_BINARY_PATH="$2"; shift 2 ;;
    --entry-binary) ENTRY_BINARY_PATH="$2"; shift 2 ;;
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
    --core-bind-addr) CORE_BIND_ADDR="$2"; shift 2 ;;
    --core-require-tls) CORE_REQUIRE_TLS="$2"; shift 2 ;;
    --core-require-client-cert) CORE_REQUIRE_CLIENT_CERT="$2"; shift 2 ;;
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
  echo "Building core and entry binaries..."
  core_build_cmd=(cargo build --release -p core)
  if [[ -n "$CORE_CARGO_FEATURES" ]]; then
    core_build_cmd+=(--features "$CORE_CARGO_FEATURES")
  fi
  "${core_build_cmd[@]}"
  cargo build --release -p entry
fi

if [[ "$CREATE_ONLY" -eq 0 ]]; then
  require_file "$CORE_BINARY_PATH"
  require_file "$ENTRY_BINARY_PATH"
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
cat >"$cloud_init_file" <<'EOF'
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
  - path: /etc/systemd/system/wg-entry.service
    permissions: "0644"
    owner: root:root
    content: |
      [Unit]
      Description=WG Entry Service
      After=network-online.target wg-core.service
      Requires=wg-core.service
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
  - modprobe wireguard
  - mkdir -p /etc/wireguard /etc/core-tls
  - chmod 700 /etc/wireguard /etc/core-tls
  - touch /etc/default/wg-core
  - touch /etc/default/wg-entry
  - chmod 600 /etc/default/wg-core
  - chmod 600 /etc/default/wg-entry
  - systemctl daemon-reload
EOF

env_file="${tmpdir}/wg-core.env"
wg_server_public_key_value="$WG_SERVER_PUBLIC_KEY"
if [[ -z "$wg_server_public_key_value" ]]; then
  wg_server_public_key_value="__AUTO_WG_SERVER_PUBLIC_KEY__"
fi
cat >"$env_file" <<EOF
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
EOF
if [[ "$CORE_REQUIRE_CLIENT_CERT" == "1" || "$CORE_REQUIRE_CLIENT_CERT" == "true" || "$CORE_REQUIRE_CLIENT_CERT" == "TRUE" ]]; then
  echo "CORE_TLS_CLIENT_CA_CERT_PATH=/etc/core-tls/ca.pem" >>"$env_file"
fi

entry_env_file="${tmpdir}/wg-entry.env"
cat >"$entry_env_file" <<EOF
APP_ENV=${ENTRY_APP_ENV}
ENTRY_BIND_ADDR=${ENTRY_BIND_ADDR}
CORE_GRPC_URL=${ENTRY_CORE_GRPC_URL}
CORE_GRPC_TLS_DOMAIN=${ENTRY_CORE_TLS_DOMAIN}
CORE_GRPC_TLS_CA_CERT_PATH=/etc/core-tls/ca.pem

APP_REQUIRE_CORE_TLS=${ENTRY_REQUIRE_CORE_TLS}
APP_ALLOW_LEGACY_CUSTOMER_HEADER=${ENTRY_ALLOW_LEGACY_CUSTOMER_HEADER}
APP_JWT_SIGNING_KEYS=${ENTRY_JWT_SIGNING_KEYS}
APP_JWT_ACTIVE_KID=v1
ADMIN_API_TOKEN=${ENTRY_ADMIN_API_TOKEN}
EOF
if [[ -n "$GOOGLE_OIDC_CLIENT_ID" ]]; then
  cat >>"$entry_env_file" <<EOF
GOOGLE_OIDC_CLIENT_ID=${GOOGLE_OIDC_CLIENT_ID}
GOOGLE_OIDC_CLIENT_SECRET=${GOOGLE_OIDC_CLIENT_SECRET}
GOOGLE_OIDC_REDIRECT_URI=${GOOGLE_OIDC_REDIRECT_URI}
EOF
fi
if [[ "$CORE_REQUIRE_CLIENT_CERT" == "1" || "$CORE_REQUIRE_CLIENT_CERT" == "true" || "$CORE_REQUIRE_CLIENT_CERT" == "TRUE" ]]; then
  cat >>"$entry_env_file" <<EOF
CORE_GRPC_TLS_CLIENT_CERT_PATH=/etc/core-tls/server.crt
CORE_GRPC_TLS_CLIENT_KEY_PATH=/etc/core-tls/server.key
EOF
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

if [[ "$ENSURE_FIREWALL" == "1" || "$ENSURE_FIREWALL" == "true" || "$ENSURE_FIREWALL" == "TRUE" ]]; then
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

  ensure_firewall_rule "${rule_prefix}-entry-8080" "tcp:8080" "$ALLOW_ENTRY_CIDRS" "$firewall_network_value" "$NETWORK_TAGS"
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

if [[ "$CREATE_ONLY" -eq 1 ]]; then
  echo "Create-only mode complete."
  exit 0
fi

echo "Uploading core+entry binaries and runtime files..."
scp_inputs=("$CORE_BINARY_PATH" "$ENTRY_BINARY_PATH" "$env_file" "$entry_env_file")
if [[ "$WG_KEY_MODE" == "upload" ]]; then
  scp_inputs+=("${tmpdir}/private.key")
fi
if [[ "$TLS_MODE" == "upload" ]]; then
  scp_inputs+=("${tmpdir}/server.crt" "${tmpdir}/server.key" "${tmpdir}/ca.pem")
fi
"${GCLOUD_BASE[@]}" compute scp --zone "$ZONE" "${scp_inputs[@]}" "${VM_NAME}:/tmp/"

remote_install_script="${tmpdir}/remote-install.sh"
cat >"$remote_install_script" <<EOF
#!/usr/bin/env bash
set -euo pipefail

WG_KEY_MODE="${WG_KEY_MODE}"
TLS_MODE="${TLS_MODE}"
TLS_COMMON_NAME="${TLS_COMMON_NAME}"
WG_SERVER_PUBLIC_KEY_VALUE="${wg_server_public_key_value}"
ENTRY_ADMIN_API_TOKEN="${ENTRY_ADMIN_API_TOKEN}"

sudo install -m 0755 /tmp/core /usr/local/bin/core
sudo install -m 0755 /tmp/entry /usr/local/bin/entry
sudo install -m 0600 /tmp/wg-core.env /etc/default/wg-core
sudo install -m 0600 /tmp/wg-entry.env /etc/default/wg-entry
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
cat <<'UNIT' | sudo tee /etc/systemd/system/wg-entry.service >/dev/null
[Unit]
Description=WG Entry Service
After=network-online.target wg-core.service
Requires=wg-core.service
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
if ! command -v curl >/dev/null 2>&1; then
  need_apt=1
fi
if ! command -v jq >/dev/null 2>&1; then
  need_apt=1
fi
if ! command -v uuidgen >/dev/null 2>&1; then
  need_apt=1
fi
if [[ "\$need_apt" -eq 1 ]]; then
  sudo apt-get update
  sudo apt-get install -y wireguard-tools openssl nftables iproute2 curl jq uuid-runtime
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
wg_pub_escaped="\${wg_pub//&/\\\\&}"
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
  echo "Detected egress interface: \$detected_iface"
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
final_egress_iface="\$(sudo awk -F= '/^WG_EGRESS_IFACE=/{print \$2}' /etc/default/wg-core | tr -d '\r\n')"
echo "Using WG_EGRESS_IFACE=\$final_egress_iface"
if [[ -z "\$final_egress_iface" || "\$final_egress_iface" == "auto" ]]; then
  echo "failed to persist WG_EGRESS_IFACE in /etc/default/wg-core" >&2
  sudo cat /etc/default/wg-core >&2
  exit 1
fi

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
sudo systemctl enable wg-entry
sudo systemctl reset-failed wg-core || true
sudo systemctl reset-failed wg-entry || true

wait_for_active() {
  local unit="\$1"
  local timeout_secs="\$2"
  local waited=0
  echo "Waiting for \$unit to become active (timeout: \${timeout_secs}s)..."
  while ! sudo systemctl is-active --quiet "\$unit"; do
    sleep 1
    waited=\$((waited + 1))
    if (( waited % 10 == 0 )); then
      echo "  still waiting for \$unit... \${waited}s"
    fi
    if [[ "\$waited" -ge "\$timeout_secs" ]]; then
      echo "Timed out waiting for \$unit to become active" >&2
      sudo systemctl --no-pager --full status "\$unit" || true
      sudo journalctl -u "\$unit" -n 120 --no-pager || true
      return 1
    fi
  done
}

wait_for_port() {
  local host="\$1"
  local port="\$2"
  local timeout_secs="\$3"
  local waited=0
  echo "Waiting for TCP listener on \${host}:\${port} (timeout: \${timeout_secs}s)..."
  while ! sudo ss -ltn | grep -Eq "LISTEN.+(:|\.)\${port}[[:space:]]"; do
    sleep 1
    waited=\$((waited + 1))
    if (( waited % 10 == 0 )); then
      echo "  still waiting for \${host}:\${port}... \${waited}s"
    fi
    if [[ "\$waited" -ge "\$timeout_secs" ]]; then
      echo "Timed out waiting for \$host:\$port to accept TCP connections" >&2
      sudo ss -ltn || true
      return 1
    fi
  done
}

# Confirm core remains active for a short period after startup.
wait_for_stable_active() {
  local unit="\$1"
  local stable_secs="\$2"
  local i=0
  echo "Verifying \$unit remains active for \${stable_secs}s..."
  while [[ "\$i" -lt "\$stable_secs" ]]; do
    if ! sudo systemctl is-active --quiet "\$unit"; then
      echo "\$unit became inactive during stability check" >&2
      return 1
    fi
    sleep 1
    i=\$((i + 1))
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

# Start core first and wait until it is healthy before starting entry.
sudo systemctl restart wg-core
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
echo "Waiting for core listener on configured port: \$core_bind_port"
if ! wait_for_port 127.0.0.1 "\$core_bind_port" 120; then
  if [[ "\$core_nat_driver" == "native" ]]; then
    echo "core did not open gRPC port with WG_NAT_DRIVER=native; falling back to WG_NAT_DRIVER=cli"
    set_core_nat_driver cli
    sudo systemctl reset-failed wg-core || true
    sudo systemctl restart wg-core
    wait_for_active wg-core 120
    wait_for_port 127.0.0.1 "\$core_bind_port" 120 || {
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
wait_for_stable_active wg-core 5 || {
  sudo systemctl --no-pager --full status wg-core || true
  sudo journalctl -u wg-core -n 160 --no-pager || true
  exit 1
}

sudo systemctl restart wg-entry
wait_for_active wg-entry 120

if ! curl -fsS http://127.0.0.1:8080/healthz >/dev/null; then
  echo "entry healthz check failed" >&2
  sudo systemctl --no-pager --full status wg-core || true
  sudo journalctl -u wg-core -n 120 --no-pager || true
  sudo systemctl --no-pager --full status wg-entry || true
  sudo journalctl -u wg-entry -n 120 --no-pager || true
  exit 1
fi

wait_for_core_bridge() {
  local timeout_secs="\$1"
  local waited=0
  while ! curl -fsS -H "x-admin-token: \$ENTRY_ADMIN_API_TOKEN" \
    http://127.0.0.1:8080/v1/admin/core/status >/dev/null; do
    sleep 1
    waited=\$((waited + 1))
    if [[ "\$waited" -ge "\$timeout_secs" ]]; then
      echo "Timed out waiting for entry->core bridge (/v1/admin/core/status)" >&2
      sudo systemctl --no-pager --full status wg-core || true
      sudo systemctl --no-pager --full status wg-entry || true
      sudo journalctl -u wg-core -u wg-entry -n 160 --no-pager || true
      return 1
    fi
  done
}

wait_for_core_bridge 60

sudo systemctl --no-pager --full status wg-core
sudo systemctl --no-pager --full status wg-entry

echo "Smoke test hints:"
echo "  curl -fsS http://127.0.0.1:8080/healthz"
echo "  curl -fsS -H 'x-admin-token: \$ENTRY_ADMIN_API_TOKEN' http://127.0.0.1:8080/v1/admin/core/status | jq ."
EOF

"${GCLOUD_BASE[@]}" compute scp --zone "$ZONE" "$remote_install_script" "${VM_NAME}:/tmp/remote-install.sh"
"${GCLOUD_BASE[@]}" compute ssh "$VM_NAME" --zone "$ZONE" --command "bash /tmp/remote-install.sh"

if [[ -z "$VM_IP" ]]; then
  VM_IP="$("${GCLOUD_BASE[@]}" compute instances describe "$VM_NAME" --zone "$ZONE" --format='get(networkInterfaces[0].accessConfigs[0].natIP)' || true)"
fi
EFFECTIVE_NAT_DRIVER="$("${GCLOUD_BASE[@]}" compute ssh "$VM_NAME" --zone "$ZONE" --command "sudo awk -F= '/^WG_NAT_DRIVER=/{print \$2}' /etc/default/wg-core | tr -d '\r\n'" 2>/dev/null || true)"
EFFECTIVE_WG_ENDPOINT_TEMPLATE="$("${GCLOUD_BASE[@]}" compute ssh "$VM_NAME" --zone "$ZONE" --command "sudo awk -F= '/^WG_ENDPOINT_TEMPLATE=/{print \$2}' /etc/default/wg-core | tr -d '\r\n'" 2>/dev/null || true)"

echo "Done. Check live logs with:"
echo "  gcloud --project ${PROJECT} compute ssh ${VM_NAME} --zone ${ZONE} --command 'sudo journalctl -u wg-core -u wg-entry -f'"
if [[ -n "$EFFECTIVE_NAT_DRIVER" ]]; then
  echo "Effective WG_NAT_DRIVER=${EFFECTIVE_NAT_DRIVER}"
fi
if [[ -n "$EFFECTIVE_WG_ENDPOINT_TEMPLATE" ]]; then
  echo "Effective WG_ENDPOINT_TEMPLATE=${EFFECTIVE_WG_ENDPOINT_TEMPLATE}"
fi
if [[ -n "$GOOGLE_OIDC_CLIENT_ID" ]]; then
  echo "Google OIDC configured for entry (client id provided)."
fi
echo
echo "Quick on-VM smoke checks:"
echo "  gcloud --project ${PROJECT} compute ssh ${VM_NAME} --zone ${ZONE} --command 'curl -fsS http://127.0.0.1:8080/healthz'"
echo "  gcloud --project ${PROJECT} compute ssh ${VM_NAME} --zone ${ZONE} --command \"curl -fsS -H 'x-admin-token: ${ENTRY_ADMIN_API_TOKEN}' http://127.0.0.1:8080/v1/admin/core/status | jq .\""
echo "  gcloud --project ${PROJECT} compute ssh ${VM_NAME} --zone ${ZONE} --command 'set -e; C=\$(uuidgen | tr \"[:upper:]\" \"[:lower:]\"); N=\$(uuidgen | tr \"[:upper:]\" \"[:lower:]\"); K=\$(wg genkey); P=\$(printf \"%s\" \"\$K\" | wg pubkey); D=\$(curl -fsS -X POST http://127.0.0.1:8080/v1/devices -H \"content-type: application/json\" -H \"x-customer-id: \$C\" -d \"{\\\"name\\\":\\\"vm-test\\\",\\\"public_key\\\":\\\"\$P\\\"}\" | jq -r .id); for i in 1 2 3 4 5; do if RES=\$(curl -fsS -X POST http://127.0.0.1:8080/v1/sessions/start -H \"content-type: application/json\" -H \"x-customer-id: \$C\" -d \"{\\\"device_id\\\":\\\"\$D\\\",\\\"region\\\":\\\"us-west\\\",\\\"node_hint\\\":\\\"\$N\\\"}\" 2>/dev/null); then echo \"\$RES\" | jq .; exit 0; fi; sleep 1; done; echo \"session start failed after retries\" >&2; exit 1'"
echo
if [[ -n "$VM_IP" ]]; then
  echo "If firewall allows tcp:8080, you can test from your machine:"
  echo "  curl -fsS http://${VM_IP}:8080/healthz"
  echo "Client app base URL:"
  echo "  ENTRY_API_BASE_URL=http://${VM_IP}:8080"
fi
