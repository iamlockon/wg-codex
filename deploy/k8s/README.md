# Kubernetes Deployment (GKE)

## 1. Build and push images
```bash
docker build -f services/entry/Dockerfile -t ghcr.io/<org>/wg-entry:<tag> .
docker build -f services/core/Dockerfile -t ghcr.io/<org>/wg-core:<tag> .
docker push ghcr.io/<org>/wg-entry:<tag>
docker push ghcr.io/<org>/wg-core:<tag>
```

Update image tags in:
- `deploy/k8s/entry-deployment.yaml`
- `deploy/k8s/core-daemonset.yaml`

## 2. Prepare secrets/config
1. Copy and edit:
   - `deploy/k8s/entry-secret.example.yaml`
   - `deploy/k8s/core-secret.example.yaml`
2. Keep `ADMIN_API_TOKEN` identical between entry and core.
3. Provide valid TLS file paths in secret values.

## 3. Apply manifests
```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/entry-configmap.yaml
kubectl apply -f deploy/k8s/core-configmap.yaml
kubectl apply -f deploy/k8s/entry-secret.example.yaml
kubectl apply -f deploy/k8s/core-secret.example.yaml
kubectl apply -f deploy/k8s/entry-deployment.yaml
kubectl apply -f deploy/k8s/core-daemonset.yaml
```

## 4. Run DB migrations
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
