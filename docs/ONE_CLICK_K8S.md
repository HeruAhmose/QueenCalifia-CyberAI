# One-click K8s (PR-gated production)

What you click:
1) **Actions → Bootstrap K8s → Run workflow** (installs ingress-nginx, cert-manager, Argo CD, Image Updater)
2) Merge Image Updater PRs into `staging`
3) Approve & merge the automatic promotion PR (`staging` → `production`)

No manual Argo “Sync” clicks: both apps auto-sync.

Production safety:
- `production` branch is protected (approvals + required checks)
- CI includes `argocd-health` gate on production PRs (fails if prod is degraded)
