# Dashboard hosting: Firebase → Google Cloud Storage (Antigravity-friendly)

Firebase Hosting files in this repo (`firebase.json`, `.firebaserc`) are **legacy**. The supported path for the static dashboard is **Google Cloud Storage** static website hosting, which you can provision and deploy using **`gcloud`** or by driving the same steps through **[Google Antigravity](https://antigravity.google/)** (agentic planning/deploy to GCP — see Google’s codelab *Build and Deploy to Google Cloud with Antigravity*).

## Why GCS

- Same Google ecosystem; no Firebase Hosting lock-in.
- Cheap, global object storage; optional Cloud CDN / HTTPS load balancer + custom domain later.
- Build output is still `frontend/dist` (Vite); only the upload target changes.

## Windows (PowerShell)

### Install `gcloud` first

If PowerShell says **`gcloud` is not recognized**, the [Google Cloud SDK](https://cloud.google.com/sdk/docs/install-sdk#windows) is not installed or not on your **PATH**. Install it, then **close and reopen** PowerShell, and run:

```powershell
gcloud init
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
```

Confirm:

```powershell
gcloud --version
```

### Command syntax

PowerShell does **not** use `\` at the end of a line like bash. Either put each command on **one line**, or use a backtick `` ` `` as the line-continuation character at the **end** of the line.

**Do not** paste lines that start with `--member=...` alone — that must be part of the same `gcloud` command as `add-iam-policy-binding`.

**Create the bucket before** `add-iam-policy-binding` (order matters).

1. Set project and create the bucket (choose a **globally unique** name):

```powershell
gcloud config set project YOUR_PROJECT_ID
gcloud storage buckets create gs://YOUR_DASHBOARD_BUCKET --location=us-central1 --uniform-bucket-level-access
```

2. Allow public read of objects (static site only):

```powershell
gcloud storage buckets add-iam-policy-binding gs://YOUR_DASHBOARD_BUCKET --member=allUsers --role=roles/storage.objectViewer
```

3. Deploy from the **repository root** (no `bash` / WSL required).

Pass the bucket name as a **parameter** (simplest — avoids env var order mistakes):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File gcp\dashboard-hosting\deploy_gcs.ps1 -Bucket YOUR_REAL_BUCKET_NAME
```

Or set the variable **first** in the **same** PowerShell window, then run the script on the **next** line:

```powershell
$env:GCS_DASHBOARD_BUCKET = "YOUR_REAL_BUCKET_NAME"
powershell -NoProfile -ExecutionPolicy Bypass -File gcp\dashboard-hosting\deploy_gcs.ps1
```

From repo root with npm (inherits your current PowerShell environment):

```powershell
$env:GCS_DASHBOARD_BUCKET = "YOUR_REAL_BUCKET_NAME"
npm run deploy:dashboard:gcs
```

**Note:** `deploy:gcs:ps1` is defined under **`frontend/package.json`** (run from `frontend/`). **`deploy:dashboard:gcs`** is at the **repo root** `package.json` and is the one to use from `C:\...\QueenCalifia-CyberAI`.

## One-time: create bucket and public read (macOS / Linux / Git Bash)

Replace `PROJECT_ID` and choose a globally unique bucket name (DNS label style).

```bash
gcloud config set project PROJECT_ID
gcloud storage buckets create gs://YOUR_DASHBOARD_BUCKET --location=us-central1 --uniform-bucket-level-access
gcloud storage buckets add-iam-policy-binding gs://YOUR_DASHBOARD_BUCKET \
  --member=allUsers --role=roles/storage.objectViewer
```

**Security note:** `allUsers` objectViewer makes bucket objects world-readable — intended only for **public** dashboard static assets (HTML/JS/CSS). Do not store secrets in this bucket.

## SPA routing

The deploy script sets:

- `website-main-page-suffix=index.html`
- `website-error-page=index.html`

so client-side routes work like Firebase rewrites.

## Deploy

```bash
export GCS_DASHBOARD_BUCKET=YOUR_DASHBOARD_BUCKET
bash gcp/dashboard-hosting/deploy_gcs.sh
```

Or from `frontend` after a manual build:

```bash
gcloud storage rsync -r dist gs://YOUR_DASHBOARD_BUCKET/ --delete-unmatched-destination-objects
```

## CORS on the API (Render / backend)

Browsers send `Origin: https://YOUR_BUCKET.storage.googleapis.com` when the dashboard is opened via the [virtual-hosted–style](https://cloud.google.com/storage/docs/static-website) URL.

1. Add that origin **exactly** to **`QC_CORS_ORIGINS`** on the API (comma-separated), **or**
2. Rely on the gateway regex that allows `https://<bucket>.storage.googleapis.com` (see `api/gateway.py`).

Custom domains (e.g. Cloud Load Balancing → backend bucket) must be listed explicitly in `QC_CORS_ORIGINS`.

## Build-time API URL

`VITE_API_URL` / `VITE_QC_API_URL` are still baked at **`npm run build`**. Set them in `frontend/.env.production` before deploying to GCS.

## Removing Firebase (optional)

After cutover:

1. Update `QC_CORS_ORIGINS` to drop `*.web.app` / `*.firebaseapp.com` if no longer used.
2. Remove or archive `firebase.json` and `.firebaserc` locally; they are not required for GCS hosting.
