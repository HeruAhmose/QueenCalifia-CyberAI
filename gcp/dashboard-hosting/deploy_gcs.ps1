# Deploy frontend/dist to a GCS static website bucket (Windows PowerShell).
# Requires: Google Cloud SDK (gcloud) on PATH, Node/npm, authenticated project.
#
# Usage (pick one):
#   .\gcp\dashboard-hosting\deploy_gcs.ps1 -Bucket my-unique-bucket-name
#   $env:GCS_DASHBOARD_BUCKET = "my-bucket"; .\gcp\dashboard-hosting\deploy_gcs.ps1

param(
    [Parameter(Position = 0)]
    [string] $Bucket = ""
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command gcloud -ErrorAction SilentlyContinue)) {
    Write-Host @"
gcloud was not found on PATH.

Install the Google Cloud SDK for Windows, then open a NEW PowerShell window:
  https://cloud.google.com/sdk/docs/install-sdk#windows

After install, run:
  gcloud init
  gcloud auth login
  gcloud config set project YOUR_PROJECT_ID
"@ -ForegroundColor Yellow
    exit 1
}

if (-not $Bucket) {
    $Bucket = $env:GCS_DASHBOARD_BUCKET
}
if (-not $Bucket -or $Bucket -eq "YOUR_DASHBOARD_BUCKET" -or $Bucket -eq "your-actual-bucket-name") {
    Write-Host @"
Set the bucket name in one of these ways:

  .\gcp\dashboard-hosting\deploy_gcs.ps1 -Bucket your-real-bucket-name

Or:

  `$env:GCS_DASHBOARD_BUCKET = 'your-real-bucket-name'
  .\gcp\dashboard-hosting\deploy_gcs.ps1

(Placeholder names like 'your-actual-bucket-name' are not accepted.)
"@ -ForegroundColor Yellow
    exit 1
}

$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$Frontend = Join-Path $Root "frontend"
$Dist = Join-Path $Root "frontend\dist"

Write-Host "==> Building frontend"
Push-Location $Frontend
try {
    npm run build
} finally {
    Pop-Location
}

if (-not (Test-Path $Dist)) {
    Write-Error "Build output not found: $Dist"
}

Write-Host "==> Syncing to gs://$Bucket/"
gcloud storage rsync -r $Dist "gs://$Bucket/" --delete-unmatched-destination-objects

Write-Host "==> Website config (SPA)"
gcloud storage buckets update "gs://$Bucket" `
    --website-main-page-suffix=index.html `
    --website-error-page=index.html

Write-Host "Done. Open: https://$Bucket.storage.googleapis.com"
Write-Host "Add that Origin to QC_CORS_ORIGINS on the API if needed."
