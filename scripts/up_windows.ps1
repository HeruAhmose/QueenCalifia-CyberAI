param(
  [switch]$Build,
  [string]$ComposeFile = "",
  [string]$VenvPath = ".venv"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

# Ensure deps/tests env is ready (no frontend tests here)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/dev_setup_windows.ps1 -VenvPath $VenvPath

function Find-ComposeFile {
  if ($ComposeFile -and (Test-Path $ComposeFile)) { return $ComposeFile }
  foreach ($c in @("docker-compose.yml","docker-compose.dev.yml","compose.yml")) {
    if (Test-Path $c) { return $c }
  }
  return ""
}

$cf = Find-ComposeFile
if (-not $cf) {
  throw "No compose file found (docker-compose.yml / docker-compose.dev.yml / compose.yml). Provide -ComposeFile path."
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  throw "docker not found. Install Docker Desktop or run services manually."
}

Write-Host "Starting dev stack via: $cf"
if ($Build) {
  docker compose -f $cf up --build
} else {
  docker compose -f $cf up
}
