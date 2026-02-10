# Argo CD + Image Updater (PR-gated auto updates)

This folder contains a ready-to-apply Argo CD `Application` manifest that enables **automatic image updates** via **Argo CD Image Updater**, while still keeping a **PR review gate**.

## What you get

- Argo CD deploys the Helm chart from `helm/queen-califia`
- Image Updater watches your registry for new digests (immutable deploys)
- Image Updater commits updated `image.digest` values into `helm/queen-califia/values-argocd.yaml`
- Image Updater pushes those commits to a new branch like `image-updater-<sha>`
- A GitHub Action opens a PR from that branch into `main`

## Digest pinning (immutable deploys)

The default configuration uses `update-strategy: digest`, which means Image Updater pins the exact `sha256:...` digest of the latest image. This ensures:

- Every deploy is byte-identical to what was tested
- No tag mutation attacks (a rebuilt `:latest` or `:v1.0.0` won't sneak in)
- Full audit trail of exactly which image bytes are running

The Helm chart's `image.digest` field takes priority over `image.tag` when set.

### Switching to semver tags (alternative)

If you prefer tag-based tracking instead of digest pinning, edit `application-queen-califia.yaml`:

```yaml
argocd-image-updater.argoproj.io/api.update-strategy: semver
argocd-image-updater.argoproj.io/api.allow-tags: "regexp:^v?\\d+\\.\\d+\\.\\d+$"
argocd-image-updater.argoproj.io/api.helm.image-tag: api.image.tag   # write to tag, not digest
```

## Prereqs

- Argo CD installed
- Argo CD Image Updater installed (recommended: official Helm chart)
- Argo CD has repo access to this Git repo
- Image Updater has *write* access to this repo (PAT or GitHub App)

## 1) Create Image Updater git credentials secret (example)

If you use HTTPS + PAT:

```bash
kubectl -n argocd-image-updater create secret generic git-creds \
  --from-literal=username=YOUR_GH_USERNAME \
  --from-literal=password=YOUR_GH_PAT
```

Then configure Image Updater to use it (installation-specific).

## 2) Apply the Application

Edit `application-queen-califia.yaml`:
- `repoURL`
- image repositories in `image-list`
- `ingress.host` in `values-argocd.yaml`

Then:

```bash
kubectl apply -f k8s/argocd/application-queen-califia.yaml
```

## Notes

- Image Updater does **not** create PRs by itself; it creates branches. The PR is opened by `.github/workflows/image-updater-pr.yml`.
- Digest pinning is the default; switch to semver if you prefer tag-based tracking.
