# Dashboard static hosting on Google Cloud

Deploy the Vite build to **Cloud Storage** (static website). This replaces **Firebase Hosting** for new rollouts.

- **Scripts:** `deploy_gcs.sh` (bash) or **`deploy_gcs.ps1` (Windows PowerShell)** — set `$env:GCS_DASHBOARD_BUCKET` first; requires `gcloud`, Node/npm.
- **Guide:** `docs/DEPLOY_DASHBOARD_GCS.md` (CORS, IAM, Antigravity references).

Legacy Firebase config remains at repo root (`firebase.json`, `.firebaserc`) until you delete it after cutover.
