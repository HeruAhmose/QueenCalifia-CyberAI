#!/usr/bin/env bash
set -euo pipefail

# CI-only: assumes KIND cluster is already configured and kubectl context points to it.
# Builds local images, loads them into kind, installs the Helm chart, and probes /readyz.

NAMESPACE="${QC_K8S_NAMESPACE:-queen-califia}"
RELEASE="${QC_HELM_RELEASE:-qc}"
API_IMAGE="${QC_API_IMAGE:-qc-api:ci}"
FRONTEND_IMAGE="${QC_FRONTEND_IMAGE:-qc-frontend:ci}"

echo "Building images..."
docker build -t "${API_IMAGE}" -f Dockerfile .
docker build -t "${FRONTEND_IMAGE}" -f frontend/Dockerfile ./frontend

echo "Loading images into kind..."
kind load docker-image "${API_IMAGE}"
kind load docker-image "${FRONTEND_IMAGE}"

echo "Installing chart..."
helm upgrade --install "${RELEASE}" ./helm/queen-califia       -n "${NAMESPACE}" --create-namespace       -f ./helm/queen-califia/ci-values.yaml       --set api.image.repository="$(echo "${API_IMAGE}" | cut -d: -f1)"       --set api.image.tag="$(echo "${API_IMAGE}" | cut -d: -f2)"       --set worker.image.repository="$(echo "${API_IMAGE}" | cut -d: -f1)"       --set worker.image.tag="$(echo "${API_IMAGE}" | cut -d: -f2)"       --set frontend.image.repository="$(echo "${FRONTEND_IMAGE}" | cut -d: -f1)"       --set frontend.image.tag="$(echo "${FRONTEND_IMAGE}" | cut -d: -f2)"       --set ingress.enabled=false

echo "Waiting for workloads..."
kubectl rollout status statefulset/redis -n "${NAMESPACE}" --timeout=300s
kubectl rollout status deployment/qc-api -n "${NAMESPACE}" --timeout=300s
kubectl rollout status deployment/qc-worker -n "${NAMESPACE}" --timeout=300s
kubectl rollout status deployment/qc-frontend -n "${NAMESPACE}" --timeout=300s

echo "Probing services from inside the cluster..."
kubectl run qc-curl --rm -i --restart=Never -n "${NAMESPACE}"       --image=curlimages/curl:8.6.0       --command -- sh -lc       "curl -fsS http://api:5000/readyz >/dev/null &&        curl -fsS http://api:5000/healthz >/dev/null &&        curl -fsS http://frontend:80/ | head -c 200 >/dev/null &&        echo OK"
