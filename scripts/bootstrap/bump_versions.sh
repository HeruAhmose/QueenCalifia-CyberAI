#!/usr/bin/env bash
set -euo pipefail

VERSIONS_FILE="${1:-scripts/bootstrap/versions.env}"
if [ ! -f "$VERSIONS_FILE" ]; then
  echo "canonical version manifest missing: $VERSIONS_FILE" >&2
  exit 2
fi

required_keys=(
  KUBECTL_VERSION
  HELM_VERSION
  ARGOCD_CLI_VERSION
  ARGOCD_CLI_SHA256
  INGRESS_NGINX_CHART_VERSION
  CERT_MANAGER_CHART_VERSION
  ARGOCD_CHART_VERSION
  ARGOCD_IMAGE_UPDATER_CHART_VERSION
)

for key in "${required_keys[@]}"; do
  if ! grep -q "^${key}=" "$VERSIONS_FILE"; then
    echo "missing required version key: $key" >&2
    exit 2
  fi
done

if ! command -v helm >/dev/null 2>&1; then
  echo "helm is required" >&2
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 2
fi

helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx >/dev/null 2>&1 || true
helm repo add jetstack https://charts.jetstack.io >/dev/null 2>&1 || true
helm repo add argo https://argoproj.github.io/argo-helm >/dev/null 2>&1 || true
helm repo update >/dev/null

latest() {
  local chart="$1"
  local version
  version="$(
    helm search repo "$chart" --versions -o json \
      | jq -r '.[].version' \
      | sort -Vr \
      | head -n 1
  )"
  if [ -z "$version" ] || [ "$version" = "null" ]; then
    echo "unable to resolve chart version for $chart" >&2
    exit 2
  fi
  printf '%s\n' "$version"
}

INGRESS="$(latest ingress-nginx/ingress-nginx)"
CERT="$(latest jetstack/cert-manager)"
ARGOCD="$(latest argo/argo-cd)"
UPDATER="$(latest argo/argocd-image-updater)"

VERSIONS_FILE="$VERSIONS_FILE" \
INGRESS="$INGRESS" \
CERT="$CERT" \
ARGOCD="$ARGOCD" \
UPDATER="$UPDATER" \
python - <<'PY'
import os
import re
from pathlib import Path

p = Path(os.environ["VERSIONS_FILE"])
s = p.read_text(encoding="utf-8")
updates = {
    "INGRESS_NGINX_CHART_VERSION": os.environ["INGRESS"],
    "CERT_MANAGER_CHART_VERSION": os.environ["CERT"],
    "ARGOCD_CHART_VERSION": os.environ["ARGOCD"],
    "ARGOCD_IMAGE_UPDATER_CHART_VERSION": os.environ["UPDATER"],
}

s2 = s
for key, value in updates.items():
    s2, count = re.subn(rf"(?m)^{re.escape(key)}=.*$", f"{key}={value}", s2)
    if count != 1:
        raise SystemExit(f"expected exactly one {key} entry, found {count}")

if s2 != s:
    p.write_text(s2, encoding="utf-8")
    print("UPDATED")
else:
    print("NOCHANGES")
PY
