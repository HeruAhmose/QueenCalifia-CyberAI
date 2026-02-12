#!/usr/bin/env bash
set -euo pipefail

# CI-only: assumes KIND cluster exists and kubectl context points to it.
# Installs ingress-nginx (kind provider manifest), enables app Ingress with TLS, then port-forwards
# the ingress controller and verifies routing end-to-end for:
#   - / (frontend)
#   - /api/health and /api/ready (API behind /api prefix)
# plus:
#   - HTTP -> HTTPS redirect
#   - TLS handshake (self-signed cert in-kind), using curl --resolve for host routing.

NAMESPACE="${QC_K8S_NAMESPACE:-queen-califia}"
RELEASE="${QC_HELM_RELEASE:-qc}"
HOST="${QC_INGRESS_HOST:-qc.local}"

LOCAL_HTTP_PORT="${QC_INGRESS_LOCAL_HTTP_PORT:-18080}"
LOCAL_HTTPS_PORT="${QC_INGRESS_LOCAL_HTTPS_PORT:-18443}"

TLS_SECRET_NAME="${QC_INGRESS_TLS_SECRET_NAME:-qc-tls}"

INGRESS_NGINX_TAG="${QC_INGRESS_NGINX_TAG:-v1.11.4}"
INGRESS_NGINX_MANIFEST_URL="${QC_INGRESS_NGINX_MANIFEST_URL:-https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-${INGRESS_NGINX_TAG}/deploy/static/provider/kind/deploy.yaml}"

PF_LOG="$(mktemp)"
TMP_DIR="$(mktemp -d)"
PF_PID=""

cleanup() {
  if [[ -n "${PF_PID}" ]]; then
    kill "${PF_PID}" >/dev/null 2>&1 || true
  fi
  rm -f "${PF_LOG}" >/dev/null 2>&1 || true
  rm -rf "${TMP_DIR}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Installing ingress-nginx for kind (${INGRESS_NGINX_TAG})..."
kubectl apply -f "${INGRESS_NGINX_MANIFEST_URL}"

echo "Waiting for ingress-nginx controller..."
kubectl rollout status deployment/ingress-nginx-controller -n ingress-nginx --timeout=300s

echo "Ensuring namespace '${NAMESPACE}' exists..."
kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1 || kubectl create namespace "${NAMESPACE}"

echo "Creating self-signed TLS cert for host '${HOST}' (secret: ${TLS_SECRET_NAME})..."
if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required for TLS E2E. Install openssl and retry." >&2
  exit 1
fi

openssl req -x509 -nodes -newkey rsa:2048   -keyout "${TMP_DIR}/tls.key"   -out "${TMP_DIR}/tls.crt"   -days 1   -subj "/CN=${HOST}"   -addext "subjectAltName=DNS:${HOST}" >/dev/null 2>&1

kubectl -n "${NAMESPACE}" create secret tls "${TLS_SECRET_NAME}"   --cert="${TMP_DIR}/tls.crt"   --key="${TMP_DIR}/tls.key"   --dry-run=client -o yaml | kubectl apply -f -

echo "Enabling app Ingress (host=${HOST}, tls=${TLS_SECRET_NAME})..."
if helm status "${RELEASE}" -n "${NAMESPACE}" >/dev/null 2>&1; then
  helm upgrade "${RELEASE}" ./helm/queen-califia     -n "${NAMESPACE}"     --reuse-values     --set ingress.enabled=true     --set ingress.host="${HOST}"     --set ingress.tls.enabled=true     --set ingress.tls.secretName="${TLS_SECRET_NAME}"     --set ingress.certManager.enabled=false     --set ingress.annotations."nginx\.ingress\.kubernetes\.io/ssl-redirect"="true"
else
  echo "Release '${RELEASE}' not found; installing with CI defaults."
  helm upgrade --install "${RELEASE}" ./helm/queen-califia     -n "${NAMESPACE}" --create-namespace     -f ./helm/queen-califia/ci-values.yaml     --set ingress.enabled=true     --set ingress.host="${HOST}"     --set ingress.tls.enabled=true     --set ingress.tls.secretName="${TLS_SECRET_NAME}"     --set ingress.certManager.enabled=false     --set ingress.annotations."nginx\.ingress\.kubernetes\.io/ssl-redirect"="true"
fi

echo "Waiting for app workloads..."
kubectl rollout status statefulset/redis -n "${NAMESPACE}" --timeout=300s
kubectl rollout status deployment/qc-api -n "${NAMESPACE}" --timeout=300s
kubectl rollout status deployment/qc-worker -n "${NAMESPACE}" --timeout=300s
kubectl rollout status deployment/qc-frontend -n "${NAMESPACE}" --timeout=300s

echo "Port-forwarding ingress-nginx controller to localhost:${LOCAL_HTTP_PORT} (http) and :${LOCAL_HTTPS_PORT} (https)..."
kubectl -n ingress-nginx port-forward svc/ingress-nginx-controller   "${LOCAL_HTTP_PORT}:80" "${LOCAL_HTTPS_PORT}:443" >"${PF_LOG}" 2>&1 &
PF_PID="$!"

wait_for_http() {
  for _ in $(seq 1 90); do
    if curl -sS -o /dev/null --connect-timeout 1       --resolve "${HOST}:${LOCAL_HTTP_PORT}:127.0.0.1"       "http://${HOST}:${LOCAL_HTTP_PORT}/" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Ingress did not become reachable. Port-forward logs:" >&2
  tail -n 200 "${PF_LOG}" >&2 || true
  return 1
}

wait_for_http

echo "Validating HTTP -> HTTPS redirect..."
HDRS="$(curl -sSI --connect-timeout 2   --resolve "${HOST}:${LOCAL_HTTP_PORT}:127.0.0.1"   "http://${HOST}:${LOCAL_HTTP_PORT}/")"

echo "${HDRS}" | grep -Eqi "^HTTP/.* (301|302|307|308)" || { echo "Expected redirect status from HTTP"; echo "${HDRS}"; exit 1; }
echo "${HDRS}" | grep -Eqi "^location: https://${HOST}(/|$)" || { echo "Expected Location: https://${HOST}"; echo "${HDRS}"; exit 1; }

echo "Validating TLS handshake (self-signed) on :${LOCAL_HTTPS_PORT}..."
# Validate the server presents a certificate with CN/HOST in the subject (best-effort).
CERT_SUBJECT="$(echo | openssl s_client -connect "127.0.0.1:${LOCAL_HTTPS_PORT}" -servername "${HOST}" 2>/dev/null | openssl x509 -noout -subject 2>/dev/null || true)"
echo "${CERT_SUBJECT}" | grep -q "${HOST}" || { echo "TLS cert subject did not contain host '${HOST}'"; echo "${CERT_SUBJECT}"; exit 1; }

echo "E2E routing checks via HTTPS Ingress..."
HTML="$(curl -ksS --connect-timeout 2   --resolve "${HOST}:${LOCAL_HTTPS_PORT}:127.0.0.1"   "https://${HOST}:${LOCAL_HTTPS_PORT}/" | head -c 400)"

echo "${HTML}" | grep -qi "<html" || { echo "Frontend did not return HTML via HTTPS Ingress"; exit 1; }

curl -ksS --connect-timeout 2   --resolve "${HOST}:${LOCAL_HTTPS_PORT}:127.0.0.1"   "https://${HOST}:${LOCAL_HTTPS_PORT}/api/health" >/dev/null

curl -ksS --connect-timeout 2   --resolve "${HOST}:${LOCAL_HTTPS_PORT}:127.0.0.1"   "https://${HOST}:${LOCAL_HTTPS_PORT}/api/ready" >/dev/null

echo "OK"
