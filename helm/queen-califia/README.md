# Helm chart: queen-califia

This chart deploys:
- API (Gunicorn, port 5000) with `/healthz` + `/readyz`
- Worker (Celery) (optional)
- Frontend (nginx static, port 80)
- Redis (optional)
- Ingress (optional, NGINX Ingress Controller)

## Values schema

This chart includes `values.schema.json` — Helm validates all values at lint/install/upgrade time. CI runs `helm lint` which enforces the schema.

## Install (example)

```bash
helm upgrade --install qc ./helm/queen-califia \
  -n queen-califia --create-namespace \
  --set api.image.repository=ghcr.io/YOUR_ORG/queencalifia-api \
  --set api.image.tag=v0.1.0 \
  --set frontend.image.repository=ghcr.io/YOUR_ORG/queencalifia-frontend \
  --set frontend.image.tag=v0.1.0
```

## Digest pinning (immutable deploys)

For production, pin images by OCI digest instead of mutable tags:

```bash
helm upgrade --install qc ./helm/queen-califia -n queen-califia \
  --set api.image.repository=ghcr.io/YOUR_ORG/queencalifia-api \
  --set api.image.digest=sha256:abcdef0123456789... \
  --set frontend.image.repository=ghcr.io/YOUR_ORG/queencalifia-frontend \
  --set frontend.image.digest=sha256:fedcba9876543210...
```

When `image.digest` is set, it takes priority over `image.tag`. Argo CD Image Updater writes digests automatically (see `k8s/argocd/`).

## Ingress + cert-manager

```bash
helm upgrade --install qc ./helm/queen-califia -n queen-califia --create-namespace \
  --set ingress.enabled=true \
  --set ingress.host=example.com \
  --set ingress.certManager.clusterIssuer=letsencrypt-staging
```

> For production, use an externally-managed Secret (recommended):
> - `--set secrets.create=false --set secrets.name=qc-secrets`
> - create that secret via your secret manager / sealed-secrets / external-secrets.

## Hardening knobs

All are optional; safe defaults.

- Pod/Container security context:
  - global: `podSecurityContext`, `containerSecurityContext`
  - per component: `<component>.podSecurityContext`, `<component>.containerSecurityContext`

- PodDisruptionBudget: `<component>.pdb.enabled`
- HorizontalPodAutoscaler: `<component>.autoscaling.enabled`
- NetworkPolicy: `networkPolicy.enabled`

Example:

```bash
helm upgrade --install qc ./helm/queen-califia -n queen-califia \
  --set api.pdb.enabled=true \
  --set api.autoscaling.enabled=true \
  --set networkPolicy.enabled=true
```

## Argo CD Image Updater

If you want PR-gated automatic image updates with digest pinning, see:

- `k8s/argocd/application-queen-califia.yaml`
- `docs/ARGOCD_IMAGE_UPDATER.md`

## Release version sync

On tag releases (`vX.Y.Z`), CI updates `Chart.yaml` (version/appVersion) and the default image tags in `values.yaml` to match the release.

- Script: `scripts/release/sync_versions.sh`
