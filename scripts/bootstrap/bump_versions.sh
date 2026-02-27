    #!/usr/bin/env bash
    set -euo pipefail

    VERSIONS_FILE="${1:-scripts/bootstrap/versions.env}"
    if [ ! -f "$VERSIONS_FILE" ]; then
      echo "versions.env not found: $VERSIONS_FILE" >&2
      exit 2
    fi

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
      helm search repo "$chart" --versions -o json         | jq -r '.[].version'         | sort -Vr         | head -n 1
    }

    INGRESS="$(latest ingress-nginx/ingress-nginx)"
    CERT="$(latest jetstack/cert-manager)"
    ARGOCD="$(latest argo/argo-cd)"
    UPDATER="$(latest argo/argocd-image-updater)"

    python - <<PY
import re
from pathlib import Path

p = Path("$VERSIONS_FILE")
s = p.read_text(encoding="utf-8")
def sub(key, val, s):
    return re.sub(rf"(?m)^{key}=.*$", f"{key}={val}", s)

s2 = s
s2 = sub("INGRESS_NGINX_CHART_VERSION", "$INGRESS", s2)
s2 = sub("CERT_MANAGER_CHART_VERSION", "$CERT", s2)
s2 = sub("ARGOCD_CHART_VERSION", "$ARGOCD", s2)
s2 = sub("ARGOCD_IMAGE_UPDATER_CHART_VERSION", "$UPDATER", s2)

if s2 != s:
    p.write_text(s2, encoding="utf-8")
    print("UPDATED")
else:
    print("NOCHANGES")
PY
