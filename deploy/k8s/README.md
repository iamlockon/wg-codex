# Kubernetes Deployment (GKE)

## 1. Build and push images
```bash
docker build -f services/entry/Dockerfile -t ghcr.io/<org>/wg-entry:<tag> .
docker build -f services/core/Dockerfile -t ghcr.io/<org>/wg-core:<tag> .
docker push ghcr.io/<org>/wg-entry:<tag>
docker push ghcr.io/<org>/wg-core:<tag>
```

Native NAT canary core image (feature-enabled):
```bash
docker build -f services/core/Dockerfile \
  --build-arg CORE_CARGO_FEATURES=native-nft \
  -t ghcr.io/<org>/wg-core:stable-native-canary .
docker push ghcr.io/<org>/wg-core:stable-native-canary
```

Update image tags in overlays:
- `deploy/k8s/overlays/dev/kustomization.yaml`
- `deploy/k8s/overlays/prod/kustomization.yaml`

## 2. One-command deploy per environment
Run preflight validation before apply:
```bash
deploy/k8s/preflight.sh dev
deploy/k8s/preflight.sh prod
```
The preflight gate enforces NAT rollout safety:
- `prod` must render `WG_NAT_DRIVER=cli`
- `prod-native-canary` must render `WG_NAT_DRIVER=native`

Development:
```bash
kubectl apply -k deploy/k8s/overlays/dev
```

Production:
```bash
kubectl apply -k deploy/k8s/overlays/prod
```

Production native canary:
```bash
kubectl apply -k deploy/k8s/overlays/prod-native-canary
```

## 3. SealedSecret flow for production
Prereq: Sealed Secrets controller and `kubeseal` installed.

Generate SealedSecrets and replace:
- `deploy/k8s/overlays/prod/sealedsecret-entry.yaml`
- `deploy/k8s/overlays/prod/sealedsecret-core.yaml`
- `deploy/k8s/overlays/prod/sealedsecret-core-tls.yaml`
- `deploy/k8s/overlays/prod/sealedsecret-core-grpc-client-tls.yaml`
- `deploy/k8s/overlays/prod/sealedsecret-wireguard-keys.yaml`

Example:
```bash
kubectl -n wg-vpn create secret generic entry-secrets \
  --from-literal=DATABASE_URL='postgres://...' \
  --from-literal=ADMIN_API_TOKEN='...' \
  --from-literal=APP_JWT_SIGNING_KEYS='v1:...' \
  --from-literal=GOOGLE_OIDC_CLIENT_ID='...' \
  --from-literal=GOOGLE_OIDC_CLIENT_SECRET='...' \
  --dry-run=client -o yaml \
| kubeseal --format yaml > deploy/k8s/overlays/prod/sealedsecret-entry.yaml

kubectl -n wg-vpn create secret generic core-secrets \
  --from-literal=CORE_NODE_ID='...' \
  --from-literal=ADMIN_API_TOKEN='...' \
  --from-literal=WG_SERVER_PUBLIC_KEY='...' \
  --dry-run=client -o yaml \
| kubeseal --format yaml > deploy/k8s/overlays/prod/sealedsecret-core.yaml

kubectl -n wg-vpn create secret generic core-tls \
  --from-file=server.crt=./server.crt \
  --from-file=server.key=./server.key \
  --from-file=ca.pem=./ca.pem \
  --dry-run=client -o yaml \
| kubeseal --format yaml > deploy/k8s/overlays/prod/sealedsecret-core-tls.yaml

kubectl -n wg-vpn create secret generic core-grpc-client-tls \
  --from-file=ca.pem=./ca.pem \
  --from-file=client.crt=./entry-client.crt \
  --from-file=client.key=./entry-client.key \
  --dry-run=client -o yaml \
| kubeseal --format yaml > deploy/k8s/overlays/prod/sealedsecret-core-grpc-client-tls.yaml

kubectl -n wg-vpn create secret generic wireguard-keys \
  --from-file=private.key=./wireguard-private.key \
  --dry-run=client -o yaml \
| kubeseal --format yaml > deploy/k8s/overlays/prod/sealedsecret-wireguard-keys.yaml
```

Keep `ADMIN_API_TOKEN` identical between entry and core.
The manifests now use file-backed sensitive settings by default:
`DATABASE_URL_FILE`, `ADMIN_API_TOKEN_FILE`, `APP_JWT_SIGNING_KEYS_FILE`,
`GOOGLE_OIDC_CLIENT_ID_FILE`, `GOOGLE_OIDC_CLIENT_SECRET_FILE`, and `WG_SERVER_PUBLIC_KEY_FILE`.

## 3.1 Canary rollback
If canary shows errors, immediately roll back:
```bash
kubectl apply -k deploy/k8s/overlays/prod
```
This resets `WG_NAT_DRIVER=cli` and stable core image tag.

## 4. Run DB migrations (one-time per environment)
Create a migration ConfigMap from SQL files:
```bash
kubectl -n wg-vpn create configmap db-migrations \
  --from-file=db/migrations/202602090001_initial_schema.sql \
  --from-file=db/migrations/202602100002_revoked_tokens.sql \
  --from-file=db/migrations/202602100003_consumer_model.sql
```

Run migration job:
```bash
kubectl apply -f deploy/k8s/migrate-job.yaml
kubectl -n wg-vpn logs -f job/db-migrate
```
Notes:
- Migration job uses bounded retries (`backoffLimit=2`) and auto-cleanup (`ttlSecondsAfterFinished=86400`).
- Workload manifests use `RuntimeDefault` seccomp and `allowPrivilegeEscalation=false`.

## 5. Production hard requirements enforced by binaries
- `APP_ENV=production`
- `entry`:
  - `DATABASE_URL` or `DATABASE_URL_FILE` required
  - `APP_REQUIRE_CORE_TLS=true`
  - `APP_REQUIRE_OAUTH_NONCE=true`
  - `APP_REQUIRE_OAUTH_PKCE=true`
  - `APP_ALLOW_LEGACY_CUSTOMER_HEADER=false`
  - non-default JWT signing keys required
  - `ADMIN_API_TOKEN` required
- `core`:
  - `CORE_DATAPLANE_NOOP=false`
  - `CORE_REQUIRE_TLS=true`
  - `WG_SERVER_PUBLIC_KEY` required

## 6. Post-deploy smoke check
```bash
deploy/k8s/smoke-check.sh https://<entry-host> <admin-token> cli
deploy/k8s/smoke-check.sh https://<entry-host> <admin-token> native  # for native canary
```
