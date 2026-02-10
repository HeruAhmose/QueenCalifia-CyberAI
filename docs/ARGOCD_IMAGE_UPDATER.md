# Argo CD Image Updater (PR-gated auto updates)

This repo includes a **PR-gated** Argo CD Image Updater flow with **digest pinning** for immutable deploys:

- Image Updater detects new images and pins their `sha256` digest
- Commits the digest to `helm/queen-califia/values-argocd.yaml`
- Pushes to a branch (`image-updater-*`)
- GitHub Actions opens a PR for review
- Merge PR → Argo CD syncs and rolls out

## Digest pinning

With `update-strategy: digest`, Image Updater writes the exact OCI digest (e.g. `sha256:abc123...`) into the `image.digest` Helm value. The chart's image helper uses `repository@digest` instead of `repository:tag`, guaranteeing immutable deploys.

To switch to semver tag tracking instead, see `k8s/argocd/README.md`.

## Files

- `k8s/argocd/application-queen-califia.yaml` (Application + Image Updater annotations)
- `helm/queen-califia/values-argocd.yaml` (values file that gets updated)
- `.github/workflows/image-updater-pr.yml` (opens PRs on pushes to `image-updater-*`)
- `helm/queen-califia/values.schema.json` (validates digest format: `sha256:[a-f0-9]{64}`)
