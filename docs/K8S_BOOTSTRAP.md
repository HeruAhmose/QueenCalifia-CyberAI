# Minimal cluster bootstrap checklist (exact commands)

## Get kubeconfig

### EKS (AWS)
```bash
aws eks update-kubeconfig --region <REGION> --name <CLUSTER_NAME>
kubectl get nodes
```

### GKE (Google Cloud)
```bash
gcloud container clusters get-credentials <CLUSTER_NAME> --region <REGION> --project <PROJECT_ID>
kubectl get nodes
```

### AKS (Azure)
```bash
az aks get-credentials --resource-group <RG> --name <CLUSTER_NAME> --overwrite-existing
kubectl get nodes
```

## “One click” bootstrap (GitHub Actions)
1. Add repo secret `KUBECONFIG_B64` (base64 of kubeconfig):
   ```bash
   cat ~/.kube/config | base64 -w 0
   ```
2. GitHub → Actions → **Bootstrap K8s** → Run workflow.

## PR-gated production auto-sync
- Staging branch: `staging` (auto-sync)
- Production branch: `production` (auto-sync, protected branch requires approvals + checks)
- Image Updater opens PRs into `staging` only.
- CI success opens promotion PR `staging` → `production`.

## Required secrets for Argo health gating
- `ARGOCD_SERVER` (e.g. https://argocd.example.com)
- `ARGOCD_AUTH_TOKEN` (token with read access)
Optional:
- `ARGOCD_OPTS` (e.g. --grpc-web)

## Controlled upgrades
- Pinned chart versions live in `scripts/bootstrap/versions.env`
- Weekly PR bumps them via workflow `weekly-platform-upgrades`


## Apply Argo CD Applications + ImageUpdater
```bash
kubectl apply -n argocd -f k8s/argocd/application-queen-califia-staging.yaml
kubectl apply -n argocd -f k8s/argocd/application-queen-califia-production.yaml
kubectl apply -f k8s/argocd/image-updater-queen-califia-staging.yaml
```
