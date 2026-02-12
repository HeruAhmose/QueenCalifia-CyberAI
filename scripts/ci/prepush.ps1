#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Cross-platform pre-push checks (PowerShell 7).

.DESCRIPTION
  Default behavior:
    - BLOCKS on gitlinks/submodules staged (mode 160000).
    - Runs pytest only if available; otherwise warns and allows push.

  Set QC_PREPUSH_STRICT=1 to fail push if python/pytest missing.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info([string] $Msg) { Write-Host "[pre-push] $Msg" }
function Write-Warn([string] $Msg) { Write-Warning "[pre-push] $Msg" }

function Exec([string] $File, [string[]] $Args) {
  $p = Start-Process -FilePath $File -ArgumentList $Args -NoNewWindow -Wait -PassThru
  if ($p.ExitCode -ne 0) { throw "Command failed ($File): $($Args -join ' ')" }
}

function GitTop() { (git rev-parse --show-toplevel).Trim() }

function FailIfGitlinksStaged() {
  $lines = git ls-files --stage
  $gitlinks = @($lines | Select-String -Pattern '^\s*160000\s' -AllMatches | ForEach-Object { $_.Line })
  if ($gitlinks.Count -gt 0) {
    Write-Host "Detected gitlinks/submodules staged (mode 160000):"
    $gitlinks | ForEach-Object { Write-Host "  $_" }
    throw "Refusing to push with gitlinks/submodules staged. Remove them (git rm --cached <path>) and retry."
  }

  if (Test-Path ".gitmodules") {
    $strict = [bool]($env:QC_PREPUSH_STRICT -eq "1")
    $msg = ".gitmodules exists. If not intentional, remove it."
    if ($strict) { throw $msg } else { Write-Warn $msg }
  }
}

function TryRunPytest() {
  $strict = [bool]($env:QC_PREPUSH_STRICT -eq "1")

  $py = $null
  try { $py = (Get-Command python -ErrorAction Stop).Source } catch {}
  if (-not $py) {
    $msg = "python not found; skipping pytest."
    if ($strict) { throw $msg } else { Write-Warn $msg; return }
  }

  $hasPytest = $true
  try { Exec $py @("-c", "import pytest; print(pytest.__version__)") } catch { $hasPytest = $false }

  if (-not $hasPytest) {
    $msg = "pytest not installed; skipping tests. (Install: python -m pip install -r requirements-dev.txt)"
    if ($strict) { throw $msg } else { Write-Warn $msg; return }
  }

  Write-Info "running unit tests (pytest -q)"
  Exec $py @("-m", "pytest", "-q")
}

try {
  Push-Location (GitTop)
  Write-Info "starting"
  FailIfGitlinksStaged
  TryRunPytest
  Write-Info "ok"
} finally {
  Pop-Location
}
