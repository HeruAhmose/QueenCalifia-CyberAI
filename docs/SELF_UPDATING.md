# Self-updating (production-safe)

This repository supports **controlled** self-updates (GitOps-friendly), without surprise changes in running workloads.

## Recommended: GitOps + digest-pinned images

Use the release workflow to publish:
- API image: `ghcr.io/<OWNER>/queencalifia-api:<version>`
- Frontend image: `ghcr.io/<OWNER>/queencalifia-frontend:<version>`
- Helm chart: `oci://ghcr.io/<OWNER>/charts/queen-califia:<version>`

Then deploy with Helm using **digest-pinned** images. The `image.digest` field in values takes priority over `image.tag`, ensuring every deploy is byte-identical to what CI tested. Tags are still set for human readability but the digest is the source of truth.

## Automated dependency refresh (safe)

GitHub Actions workflow:
- `.github/workflows/deps-refresh.yml`

Runs weekly and opens a PR refreshing:
- `requirements.lock`
- `requirements-dev.lock`

Your CI will validate and tests must pass before merge.

## Automated chart/values sync (protected-branch safe)

Release workflow:
- `.github/workflows/release-helm.yml`

On tag push `vX.Y.Z`, it opens a PR syncing:
- `helm/queen-califia/Chart.yaml`
- `helm/queen-califia/values.yaml`

## Automated image updates (Kubernetes — PR-gated)

Argo CD Image Updater monitors your registry for new images and commits updated `image.digest` values to a dedicated branch. A GitHub Action opens a PR for review.

Flow: **new image pushed → Image Updater detects → writes digest to branch → CI opens PR → human reviews → merge → Argo CD syncs → pods roll**

Files:
- `k8s/argocd/application-queen-califia.yaml` (Application + Image Updater annotations)
- `helm/queen-califia/values-argocd.yaml` (values file that gets updated)
- `.github/workflows/image-updater-pr.yml` (opens PRs on pushes to `image-updater-*`)

See `docs/ARGOCD_IMAGE_UPDATER.md` for full setup.

## Values schema validation

The Helm chart includes `values.schema.json` which validates all configuration knobs. CI runs `helm lint` which enforces the schema — invalid values, typos, or wrong types are caught before deploy.
