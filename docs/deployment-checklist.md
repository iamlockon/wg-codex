# Deployment Checklist (GCP/GKE)

## Preconditions
- GKE cluster created with node pools for control-plane (`entry`) and dataplane (`core`).
- Managed Postgres reachable from cluster (Cloud SQL or equivalent).
- TLS assets issued for mTLS between `entry` and `core`.
- Google OAuth client configured.
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
1. Dev: `kubectl apply -k deploy/k8s/overlays/dev`
2. Prod: `kubectl apply -k deploy/k8s/overlays/prod`
3. Native canary (optional): `kubectl apply -k deploy/k8s/overlays/prod-native-canary`
4. Apply migration ConfigMap and run `deploy/k8s/migrate-job.yaml` (one-time per environment).

## Required production env policy
- `APP_ENV=production`
- `entry`:
  - `DATABASE_URL` present
  - `APP_REQUIRE_CORE_TLS=true`
  - `APP_ALLOW_LEGACY_CUSTOMER_HEADER=false`
  - `APP_LOG_REDACTION_MODE=strict` (or omitted; production defaults to strict)
  - `APP_JWT_SIGNING_KEYS` or `APP_JWT_SIGNING_KEY` set (non-default)
  - `ADMIN_API_TOKEN` set
- `core`:
  - `CORE_DATAPLANE_NOOP=false`
  - `CORE_REQUIRE_TLS=true`
  - `WG_SERVER_PUBLIC_KEY` set (non-placeholder)

## Smoke checks
1. `kubectl -n wg-vpn get pods`
2. `kubectl -n wg-vpn logs deploy/entry --tail=100`
3. `kubectl -n wg-vpn logs ds/core --tail=100`
4. `curl http://<entry-service>/healthz`
5. Verify admin API:
   - `POST /v1/admin/nodes`
   - `GET /v1/admin/privacy/policy`
   - `POST /v1/admin/subscriptions`
   - `GET /v1/admin/subscriptions`
   - `GET /v1/admin/subscriptions/{customer_id}`
   - `GET /v1/admin/subscriptions/{customer_id}/history`
6. Verify core gRPC status:
   - `GetNodeStatus` returns expected `nat_driver`, `dataplane_mode`, and health metadata.

## Known non-blocking follow-ups
- Implement netlink-native nftables programming under `native-nft` feature and switch `WG_NAT_DRIVER=native` after validation.
- Tune redaction policy by environment (`APP_LOG_REDACTION_MODE`) once production observability needs are finalized.
