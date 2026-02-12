#!/usr/bin/env bash
set -euo pipefail

QC_GIT_REPO="${QC_GIT_REPO:-QueenCalifia-CyberAI}"
QC_INSTALL_CLUSTER_ISSUERS="${QC_INSTALL_CLUSTER_ISSUERS:-1}"

need() { if [ -z "${!1:-}" ]; then echo "Missing env var: $1" >&2; exit 2; fi; }

need QC_GIT_ORG
need QC_API_IMAGE
need QC_FRONTEND_IMAGE
need QC_STAGING_HOST
need QC_PROD_HOST
need QC_EMAIL

kubectl version --client >/dev/null
helm version >/dev/null

# Load pinned versions (controlled upgrades)
VERSIONS_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/versions.env"
if [ -f "$VERSIONS_FILE" ]; then
  # shellcheck disable=SC1090
  source "$VERSIONS_FILE"
fi

echo "==> Helm repos"
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx >/dev/null 2>&1 || true
helm repo add jetstack https://charts.jetstack.io >/dev/null 2>&1 || true
helm repo add argo https://argoproj.github.io/argo-helm >/dev/null 2>&1 || true
helm repo update >/dev/null

echo "==> ingress-nginx"
kubectl get ns ingress-nginx >/dev/null 2>&1 || kubectl create ns ingress-nginx
helm upgrade --install ingress-nginx ingress-nginx/ingress-nginx -n ingress-nginx       ${INGRESS_NGINX_CHART_VERSION:+--version "$INGRESS_NGINX_CHART_VERSION"}

echo "==> cert-manager"
kubectl get ns cert-manager >/dev/null 2>&1 || kubectl create ns cert-manager
helm upgrade --install cert-manager jetstack/cert-manager -n cert-manager --set crds.enabled=true       ${CERT_MANAGER_CHART_VERSION:+--version "$CERT_MANAGER_CHART_VERSION"}

echo "==> Argo CD"
kubectl get ns argocd >/dev/null 2>&1 || kubectl create ns argocd
helm upgrade --install argocd argo/argo-cd -n argocd       ${ARGOCD_CHART_VERSION:+--version "$ARGOCD_CHART_VERSION"}

echo "==> Argo CD Image Updater"
kubectl get ns argocd-image-updater >/dev/null 2>&1 || kubectl create ns argocd-image-updater
helm upgrade --install argocd-image-updater argo/argocd-image-updater -n argocd-image-updater       ${ARGOCD_IMAGE_UPDATER_CHART_VERSION:+--version "$ARGOCD_IMAGE_UPDATER_CHART_VERSION"}

echo "==> Wait for readiness"
kubectl -n ingress-nginx rollout status deploy/ingress-nginx-controller --timeout=10m
kubectl -n cert-manager rollout status deploy/cert-manager --timeout=10m
kubectl -n argocd rollout status deploy/argocd-server --timeout=10m
kubectl -n argocd-image-updater rollout status deploy/argocd-image-updater --timeout=10m

if [ "$QC_INSTALL_CLUSTER_ISSUERS" = "1" ]; then
  echo "==> ClusterIssuers"
  cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    email: ${QC_EMAIL}
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-staging
    solvers:
      - http01:
          ingress:
            class: nginx
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    email: ${QC_EMAIL}
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
      - http01:
          ingress:
            class: nginx
EOF
fi

echo "✅ Bootstrap complete."
