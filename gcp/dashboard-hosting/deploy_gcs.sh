#!/usr/bin/env bash
# Deploy the Vite dashboard (frontend/dist) to a Google Cloud Storage bucket configured
# for static website hosting — replacement path for Firebase Hosting.
# Prereqs: gcloud CLI, authenticated project; bucket already created.
# Optional: use Google Antigravity to generate/iterate infra for the same resources.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUCKET="${GCS_DASHBOARD_BUCKET:-}"
if [[ -z "${BUCKET}" ]]; then
  echo "Set GCS_DASHBOARD_BUCKET to your bucket name (no gs:// prefix), e.g. export GCS_DASHBOARD_BUCKET=queencalifia-cyberai-dashboard" >&2
  exit 1
fi

echo "==> Building frontend"
(cd "${ROOT}/frontend" && npm run build)

echo "==> Syncing to gs://${BUCKET}/"
gcloud storage rsync -r "${ROOT}/frontend/dist" "gs://${BUCKET}/" --delete-unmatched-destination-objects

echo "==> Website config (SPA: send unknown routes to index.html)"
gcloud storage buckets update "gs://${BUCKET}" \
  --website-main-page-suffix=index.html \
  --website-error-page=index.html

echo "Done. Site URL (virtual-hosted style): https://${BUCKET}.storage.googleapis.com"
echo "Add that exact Origin to QC_CORS_ORIGINS on the API (or use a custom domain + Cloud CDN)."
