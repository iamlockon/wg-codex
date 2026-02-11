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
  --from-literal=WG_PRIVATE_KEY_PATH='/etc/wireguard/private.key' \
  --dry-run=client -o yaml \
| kubeseal --format yaml > deploy/k8s/overlays/prod/sealedsecret-core.yaml
```

Keep `ADMIN_API_TOKEN` identical between entry and core.

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

## 5. Production hard requirements enforced by binaries
- `APP_ENV=production`
- `entry`:
  - `DATABASE_URL` required
  - `APP_REQUIRE_CORE_TLS=true`
  - `APP_ALLOW_LEGACY_CUSTOMER_HEADER=false`
  - non-default JWT signing keys required
  - `ADMIN_API_TOKEN` required
- `core`:
  - `CORE_DATAPLANE_NOOP=false`
  - `CORE_REQUIRE_TLS=true`
  - `WG_SERVER_PUBLIC_KEY` required
