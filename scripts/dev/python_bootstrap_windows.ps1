#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Windows-friendly Python bootstrap for QueenCalifia-CyberAI.

.DESCRIPTION
  - Ensures the *base* Python has pip (via ensurepip).
  - Creates (or recreates) a local .venv.
  - Installs backend/requirements.txt and, with -Dev, bootstrap requirements plus pytest.

  This script is intentionally "boring": no downloads beyond pip installs.
  If you are behind a proxy, configure pip accordingly.

.EXAMPLE
  pwsh -File scripts/dev/python_bootstrap_windows.ps1 -Dev -Recreate

.EXAMPLE
  pwsh -File scripts/dev/python_bootstrap_windows.ps1 -Python py
#>

param(
  [switch] $Dev,
  [switch] $Recreate,
  [string] $Python = "python",
  [string] $RepoRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info([string] $Msg) { Write-Host "[py-bootstrap] $Msg" }
function Write-Warn([string] $Msg) { Write-Warning "[py-bootstrap] $Msg" }

function Exec([string] $File, [string[]] $Args) {
  $p = Start-Process -FilePath $File -ArgumentList $Args -NoNewWindow -Wait -PassThru
  if ($p.ExitCode -ne 0) { throw "Command failed ($File): $($Args -join ' ')" }
}

function Resolve-RepoRoot() {
  if ($RepoRoot) { return (Resolve-Path $RepoRoot).Path }
  try {
    $top = (git rev-parse --show-toplevel 2>$null).Trim()
    if ($top) { return $top }
  } catch {}
  # fallback: script's grandparent (scripts/dev/.. -> repo root)
  return (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}

$root = Resolve-RepoRoot
Push-Location $root
try {
  Write-Info "repo: $root"

  # 1) Ensure base python exists
  $pyCmd = Get-Command $Python -ErrorAction Stop
  $py = $pyCmd.Source

  # 2) Ensure pip exists on base python
  Write-Info "ensuring pip on base python..."
  try {
    & $py -m pip --version *> $null
  } catch {
    Exec $py @("-m","ensurepip","--upgrade")
  }
  # Upgrade base pip tooling (best-effort)
  try { Exec $py @("-m","pip","install","--upgrade","pip","setuptools","wheel") } catch { Write-Warn "could not upgrade base pip; continuing" }

  # 3) Create venv
  $venvDir = Join-Path $root ".venv"
  if ($Recreate -and (Test-Path $venvDir)) {
    Write-Info "removing existing .venv"
    Remove-Item -Recurse -Force $venvDir
  }

  if (-not (Test-Path $venvDir)) {
    Write-Info "creating venv (.venv)"
    Exec $py @("-m","venv",".venv")
  } else {
    Write-Info "venv exists (.venv)"
  }

  $venvPy = Join-Path $venvDir "Scripts\python.exe"
  if (-not (Test-Path $venvPy)) { throw "venv python not found: $venvPy" }

  # 4) Install requirements
  Write-Info "upgrading pip in venv"
  Exec $venvPy @("-m","pip","install","--upgrade","pip","setuptools","wheel")

  $backendReq = Join-Path $root "backend\requirements.txt"
  if (-not (Test-Path $backendReq)) { throw "backend requirements not found: $backendReq" }
  Write-Info "installing backend/requirements.txt"
  Exec $venvPy @("-m","pip","install","-r",$backendReq)

  if ($Dev) {
    $bootstrapReq = Join-Path $root "scripts\bootstrap\requirements.txt"
    if (-not (Test-Path $bootstrapReq)) { throw "bootstrap requirements not found: $bootstrapReq" }
    Write-Info "installing bootstrap requirements and pytest"
    Exec $venvPy @("-m","pip","install","-r",$bootstrapReq,"pytest")
  }

  Write-Info "done"
  Write-Host ""
  Write-Host "Next:"
  Write-Host "  .\.venv\Scripts\Activate.ps1"
  Write-Host "  python -m pytest -q   (optional: install dev deps with -Dev)"
} finally {
  Pop-Location
}
