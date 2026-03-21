# Terraform-Only VM Deploy Responsibilities

This note inventories the imperative work that was embedded in the now-retired `scripts/deploy-entry-vm.sh` and `scripts/deploy-core-vm.sh`. Each item below is grouped by the declarative deployment unit it needed to move into for the Terraform-only VM deploy path.

## Shared Responsibilities That Must Leave the Scripts

| Current shell responsibility | Evidence in scripts | Declarative home |
| --- | --- | --- |
| Create or skip-create the VM with `gcloud compute instances create` | `--metadata-from-file user-data=...` in both scripts | Terraform variables and stack resources |
| Create firewall rules imperatively | `ensure_firewall_rule` + `compute firewall-rules create` | Terraform variables and firewall resources |
| Detect the target network by inspecting the VM NIC | `compute instances describe ... networkInterfaces[0].network` | Terraform variables |
| Upload files with `gcloud compute scp` | both scripts scp binaries, env files, and certs/keys | Runtime fetch logic |
| Build the service binary locally with `cargo build` | `cargo build --release -p entry/core` and binary existence checks | Workflow validation / CI artifact build |
| Run remote install with `gcloud compute ssh` | both scripts execute `/tmp/remote-install.sh` | Startup templates |
| Poll service status with `systemctl`/`journalctl` | `wait_for_active`, `systemctl status`, `journalctl -u ...` | Startup templates and workflow checks |
| Gate command-line combinations and required inputs | mode checks, pairing checks, `require_file` checks | Workflow validation and Terraform variable validation |

## Declarative Inputs To Add

The scripts currently read these values from CLI flags or local files; the Terraform-only flow needs them as declared stack/workflow inputs instead:

- `ENTRY_APP_ENV`
- `ENTRY_BIND_ADDR`
- `ENTRY_CORE_GRPC_URL`
- `ENTRY_CORE_TLS_DOMAIN`
- `ENTRY_ALLOW_LEGACY_CUSTOMER_HEADER`
- `CORE_BIND_ADDR`
- `entry` artifact metadata: binary object path, checksum, and runtime references for `DATABASE_URL`, admin token, JWT signing keys, Google OIDC, and node-catalog settings
- `core` artifact metadata: binary object path, checksum, and runtime references for WireGuard private key, TLS cert/key/CA material, server public key handling, and `CORE_NODE_ID` generation when absent
- VM/runtime policy inputs: machine type, image family/project, tags, allowed CIDRs, core TLS requirement, client-cert requirement, WireGuard mode, NAT driver, interface name, interface CIDR, listen port, endpoint template, egress interface, and `CORE_NODE_ID`

## `deploy-entry-vm.sh`: Responsibilities To Re-home

### 1. Startup bootstrap

The script currently writes cloud-init inline, then separately writes a remote install script that:

- creates `/etc/systemd/system/wg-entry.service`,
- creates and locks down `/etc/default/wg-entry`,
- installs the `entry` binary into `/usr/local/bin/entry`,
- installs CA and client TLS material into `/etc/core-tls`,
- installs missing runtime packages (`curl`, `jq`),
- reloads systemd, enables the unit, restarts it, and waits for health.

These steps belong in a startup template that Terraform renders into instance metadata, with runtime fetch logic supplying the binary and any secret-backed files.
The local `cargo build` and post-build file checks that precede this step belong in CI, where the artifact can be uploaded once and fetched by the VM.

### 2. Production-mode workflow validation

The script still owns validation for these production-mode entry requirements:

- `DATABASE_URL` required when `ENTRY_APP_ENV=production`
- `ADMIN_API_TOKEN` required when `ENTRY_APP_ENV=production`
- non-default `APP_JWT_SIGNING_KEYS` required when `ENTRY_APP_ENV=production`
- `ENTRY_ALLOW_LEGACY_CUSTOMER_HEADER=false` required when `ENTRY_APP_ENV=production`
- Google OIDC client ID/secret/redirect URI required when `ENTRY_APP_ENV=production`, with all-or-none validation for the three inputs
- non-localhost `ENTRY_CORE_GRPC_URL` required when `ENTRY_APP_ENV=production`
- `ENTRY_REQUIRE_CORE_TLS=true` required when `ENTRY_APP_ENV=production`
- entry node-catalog bucket/object required when the entry core target is not localhost, with bucket/object pairing validation

The script also still enforces:

- `--entry-require-core-tls` requiring `--tls-mode upload`,
- `--core-require-client-cert` requiring `--entry-require-core-tls`,
- defaulting `ENTRY_CORE_TLS_DOMAIN` from `TLS_COMMON_NAME`,
- defaulting `TLS_COMMON_NAME` from `VM_NAME`.

These are workflow validation rules, not deployment-time shell behavior.

### 3. Runtime delivery of secrets and config

The current script still pushes local artifacts for:

- the prebuilt `entry` binary,
- the generated `wg-entry.env`,
- optional CA and client certificate files.

That delivery path has to become runtime fetch logic. The VM should obtain artifacts and secret material from declared sources instead of receiving pushed files over SSH.

## `deploy-core-vm.sh`: Responsibilities To Re-home

### 1. Startup bootstrap

The current remote install script is responsible for all of the following:

- creating `/etc/systemd/system/wg-core.service`,
- creating `/etc/default/wg-core`,
- installing the `core` binary into `/usr/local/bin/core`,
- creating `/etc/wireguard` and `/etc/core-tls`,
- installing runtime packages (`wireguard-tools`, `openssl`, `nftables`, `iproute2`, `uuid-runtime`),
- loading the WireGuard kernel module,
- enabling and restarting `wg-core`,
- waiting for both service readiness and the gRPC port.

These actions need to move into startup template logic so the VM can bootstrap itself on first boot.
The local `cargo build` and post-build file checks that precede this step also move to CI artifact production.

### 2. Runtime behavior that should be explicit, not scripted ad hoc

The script currently performs runtime decisions that should become startup logic or declared inputs:

- `WG_KEY_MODE=generate|upload` and `WG_SERVER_PUBLIC_KEY` handling,
- `TLS_MODE=self-signed|upload` and certificate generation,
- `WG_ENDPOINT_TEMPLATE=auto` resolution from the VM public IP,
- `WG_EGRESS_IFACE=auto` resolution from the VM default route,
- `WG_NAT_DRIVER=cli|native` fallback from native to cli when the port does not open.

Those behaviors belong in startup templates or runtime fetch logic, with explicit workflow/Terraform inputs for the values they depend on.

### 3. Workflow validation

The core script still validates and normalizes:

- `--wg-key-mode`,
- `--tls-mode`,
- `--wg-nat-driver`,
- `--ensure-firewall`,
- `--core-require-client-cert`,
- `--native-nft`,
- `--wg-listen-port`,
- `--tls-common-name`,
- `--core-node-id`,
- `--app-env`,
- `--core-bind-addr`.

These checks should move into Terraform variable validation and GitHub Actions workflow validation so bad combinations fail before the VM is created.

The current `CORE_NODE_ID` default-generation behavior also belongs here: if `CORE_NODE_ID` is absent, the script synthesizes a value before deployment. In the Terraform-only path, that generation must become either an explicit workflow input default or startup/runtime generation logic, not hidden in the legacy shell script.

### 4. Runtime delivery of secrets and config

The script still pushes or synthesizes:

- the prebuilt `core` binary,
- `wg-core.env`,
- optional WireGuard private key material,
- optional TLS cert/key/CA material,
- `WG_SERVER_PUBLIC_KEY` mutation after the VM boots.

That whole flow needs to be replaced by startup logic that fetches declared artifacts and secret references, then writes the env file from those references on the VM.

## Practical Cut Lines For The Next Tasks

- Terraform should own instance, firewall, and input plumbing.
- Startup templates should own package installation, unit files, env file creation, and service boot.
- Workflow validation should own cross-field option checks and artifact existence checks.
- Runtime fetch logic should own GCS downloads, Secret Manager reads, key generation, and VM-local runtime mutations.
