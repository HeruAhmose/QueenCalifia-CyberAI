# Run k6 full-suite stress test against the local compose API.
# Requires: Docker Desktop started (Linux engine), repo root .env (gitignored) for compose.
# Usage: .\scripts\run_k6_docker.ps1
# Optional: $env:QC_LOADTEST_API_KEY = "..." ; $env:QC_K6_VUS = "25" ; $env:QC_K6_DURATION = "90s"

$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

if (-not (Test-Path (Join-Path $root "docker-compose.yml"))) {
  Write-Host "Run this from the QueenCalifia-CyberAI repo (docker-compose.yml missing)." -ForegroundColor Red
  exit 1
}

# Do not use ErrorActionPreference Stop here: docker prints to stderr when the daemon is down.
$ErrorActionPreference = "Continue"
docker info 2>&1 | Out-Null
$ErrorActionPreference = "Stop"
if ($LASTEXITCODE -ne 0) {
  Write-Host "Docker engine is not running. Open Docker Desktop and wait until the engine is running, then retry." -ForegroundColor Yellow
  exit 1
}

if (-not (Test-Path (Join-Path $root ".env"))) {
  $envBody = @"
# Minimal compose env (gitignored). Add secrets from .env.example as needed.
QC_ALLOW_INSECURE_BOOTSTRAP=1
"@
  Set-Content -Path (Join-Path $root ".env") -Value $envBody -Encoding UTF8
  Write-Host "Created minimal .env - customize if needed." -ForegroundColor DarkYellow
}

if (-not $env:QC_K6_FULL_SUITE) { $env:QC_K6_FULL_SUITE = "1" }
if (-not $env:QC_K6_VUS) { $env:QC_K6_VUS = "20" }
if (-not $env:QC_K6_DURATION) { $env:QC_K6_DURATION = "60s" }
if (-not $env:QC_K6_ENABLE_POSTS) { $env:QC_K6_ENABLE_POSTS = "1" }
if (-not $env:QC_K6_ENABLE_SCAN) { $env:QC_K6_ENABLE_SCAN = "0" }
if (-not $env:QC_K6_ENABLE_CHAT) { $env:QC_K6_ENABLE_CHAT = "0" }
if (-not $env:QC_K6_EXPECT_BUDGET_HEADERS) { $env:QC_K6_EXPECT_BUDGET_HEADERS = "0" }
$env:QC_SCAN_DRY_RUN = "1"

Write-Host "Running k6 (FULL_SUITE=$($env:QC_K6_FULL_SUITE) VUS=$($env:QC_K6_VUS) DURATION=$($env:QC_K6_DURATION))..." -ForegroundColor Cyan
docker compose --profile loadtest run --rm k6
$code = $LASTEXITCODE
if ($code -eq 0) {
  Write-Host "Done. See data/loadtest/summary.txt" -ForegroundColor Green
}
exit $code
