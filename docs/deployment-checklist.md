# Deployment Checklist (GCP/GKE)

## Preconditions
- GKE cluster created with node pools for control-plane (`entry`) and dataplane (`core`).
- Managed Postgres reachable from cluster (Cloud SQL or equivalent).
- TLS assets issued for mTLS between `entry` and `core`.
- Google OAuth client configured.
- Secret objects provisioned:
  - `entry-secrets`
  - `core-secrets`
  - `core-tls`
  - `core-grpc-client-tls`
  - `wireguard-keys`
- Optional alternative for `entry-secrets` and `core-secrets`:
  - GCP Secret Manager CSI via `deploy/k8s/overlays/prod-gcp-sm` (requires Workload Identity and CSI driver).
  - Preflight for GCP overlays fails if placeholders (`PROJECT_NUMBER`, `replace-me`) are not replaced.
- Environment templates available:
  - `deploy/env/entry.env.example`
  - `deploy/env/core.env.example`

## Build and publish
1. Build images:
   - `docker build -f services/entry/Dockerfile -t <registry>/wg-entry:<tag> .`
   - `docker build -f services/core/Dockerfile -t <registry>/wg-core:<tag> .`
2. Push both images to registry.
3. Update image tags in Kubernetes manifests.

## Cluster apply order
0. Validate manifests:
   - `deploy/k8s/preflight.sh dev`
   - `deploy/k8s/preflight.sh prod`
   - `deploy/k8s/preflight.sh prod-gcp-sm`
   - `deploy/k8s/preflight.sh prod-gcp-sm-native-canary`
1. Dev: `kubectl apply -k deploy/k8s/overlays/dev`
2. Prod: `kubectl apply -k deploy/k8s/overlays/prod`
3. Prod with GCP Secret Manager CSI (optional): `kubectl apply -k deploy/k8s/overlays/prod-gcp-sm`
4. Native canary (optional): `kubectl apply -k deploy/k8s/overlays/prod-native-canary`
5. Native canary + GCP Secret Manager CSI (optional): `kubectl apply -k deploy/k8s/overlays/prod-gcp-sm-native-canary`
6. Apply migration ConfigMap and run `deploy/k8s/migrate-job.yaml` (one-time per environment).
7. Prefer automated canary gate for native rollout:
   - `deploy/k8s/canary-validate.sh https://<entry-host> <admin-token> prod-native-canary`
   - `deploy/k8s/canary-validate.sh https://<entry-host> <admin-token> prod-gcp-sm-native-canary`
   - For GCP Secret Manager environments, set `ROLLBACK_OVERLAY=prod-gcp-sm` so rollback keeps CSI wiring.

## Required production env policy
- `APP_ENV=production`
- `entry`:
  - `DATABASE_URL` (or `DATABASE_URL_FILE`) present
  - `APP_REQUIRE_CORE_TLS=true`
  - `APP_REQUIRE_OAUTH_NONCE=true`
  - `APP_REQUIRE_OAUTH_PKCE=true`
  - `APP_MAX_TERMINATED_SESSION_RETENTION_DAYS` and `APP_MAX_AUDIT_RETENTION_DAYS` configured to policy limits
  - `APP_ALLOW_LEGACY_CUSTOMER_HEADER=false`
  - `APP_LOG_REDACTION_MODE=strict` (or omitted; production defaults to strict)
  - `APP_JWT_SIGNING_KEYS` or `APP_JWT_SIGNING_KEY` set (non-default)
  - `ADMIN_API_TOKEN` set
  - File-backed secret paths mounted and readable (`ADMIN_API_TOKEN_FILE`, `APP_JWT_SIGNING_KEYS_FILE`, OIDC `*_FILE`)
  - Pod/container security context enforces `RuntimeDefault` seccomp and `allowPrivilegeEscalation=false`
- `core`:
  - `CORE_DATAPLANE_NOOP=false`
  - `CORE_REQUIRE_TLS=true`
  - `WG_SERVER_PUBLIC_KEY` set (non-placeholder)
  - File-backed secret paths mounted and readable (`WG_SERVER_PUBLIC_KEY_FILE`, `ADMIN_API_TOKEN_FILE`)
  - `/etc/wireguard/private.key` exists via `wireguard-keys` secret
  - `/etc/core-tls/{server.crt,server.key,ca.pem}` exists via `core-tls` secret
  - Pod/container security context enforces `RuntimeDefault` seccomp and `allowPrivilegeEscalation=false`

## Smoke checks
Preferred:
- `deploy/k8s/smoke-check.sh https://<entry-host> <admin-token> cli`
- Native canary: `deploy/k8s/smoke-check.sh https://<entry-host> <admin-token> native`
- Automated canary gate with rollback:
  - `deploy/k8s/canary-validate.sh https://<entry-host> <admin-token> prod-native-canary`

Manual fallback:
1. `kubectl -n wg-vpn get pods`
2. `kubectl -n wg-vpn logs deploy/entry --tail=100`
3. `kubectl -n wg-vpn logs ds/core --tail=100`
4. `curl http://<entry-service>/healthz`
5. Verify admin API:
   - `POST /v1/admin/nodes`
   - `GET /v1/admin/privacy/policy`
   - `GET /v1/admin/privacy/audit-events`
   - `GET /v1/admin/core/status`
   - `GET /v1/admin/readiness` should report `production_ready=true`
   - `POST /v1/admin/subscriptions`
   - `GET /v1/admin/subscriptions`
   - `GET /v1/admin/subscriptions/{customer_id}`
   - `GET /v1/admin/subscriptions/{customer_id}/history`
6. Verify core gRPC status:
   - `GetNodeStatus` returns expected `nat_driver`, `dataplane_mode`, and health metadata.

## Known non-blocking follow-ups
- Complete production canary/rollout validation for `WG_NAT_DRIVER=native` and then promote native mode as default.
- Tune redaction policy by environment (`APP_LOG_REDACTION_MODE`) once production observability needs are finalized.
