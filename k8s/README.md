# Kubernetes manifests (sample)

These manifests are **examples** intended to get you to a secure baseline quickly.
They assume:
- You build and publish container images for:
  - API: `Dockerfile` in repo root (Gunicorn on port 5000)
  - Frontend: `frontend/Dockerfile` (nginx static on port 80)
- You use **NGINX Ingress Controller** and optionally **cert-manager** for TLS.

## Quick start (namespace + in-cluster Redis)

1) Set image names/tags in `k8s/*.yaml`:
- `image: ghcr.io/YOUR_ORG/queencalifia-api:TAG`
- `image: ghcr.io/YOUR_ORG/queencalifia-frontend:TAG`

2) Create secrets (REQUIRED in prod):
- Copy `k8s/secret.example.yaml` to `k8s/secret.yaml`
- Fill values (pepper/hmac/metrics token)

3) Apply:
```bash
kubectl apply -f k8s/namespace.yaml
kubectl -n queen-califia apply -f k8s/secret.yaml
kubectl -n queen-califia apply -f k8s/configmap.yaml
kubectl -n queen-califia apply -f k8s/redis.yaml
kubectl -n queen-califia apply -f k8s/api.yaml
kubectl -n queen-califia apply -f k8s/worker.yaml
kubectl -n queen-califia apply -f k8s/frontend.yaml
kubectl -n queen-califia apply -f k8s/ingress.yaml
```

## Ingress + cert-manager (optional TLS automation)

Install cert-manager in your cluster, then apply one of:

- Staging (recommended first):
```bash
kubectl apply -f k8s/cert-manager/clusterissuer-staging.yaml
```

- Production:
```bash
kubectl apply -f k8s/cert-manager/clusterissuer-prod.yaml
```

Then edit `k8s/ingress.yaml`:
- set `spec.rules[0].host`
- set `spec.tls[0].hosts[0]`
- choose the issuer via annotation:
  - `cert-manager.io/cluster-issuer: letsencrypt-staging` or `letsencrypt-prod`

## Probes

The API exposes:
- `GET /healthz` liveness
- `GET /readyz` readiness (returns 503 until dependencies are OK)

Manifests wire these into Kubernetes probes on the API Deployment.


## Helm (recommended)

A production-ready Helm chart lives in `helm/queen-califia`.

```bash
helm lint ./helm/queen-califia
helm template qc ./helm/queen-califia -f ./helm/queen-califia/ci-values.yaml | head
```

## Kustomize (CI validation)

A `k8s/kustomization.yaml` is provided so CI can validate manifests via:

```bash
kustomize build k8s/ | head
```
