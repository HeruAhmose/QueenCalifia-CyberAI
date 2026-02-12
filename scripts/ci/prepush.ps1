#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Cross-platform pre-push checks (PowerShell 7).

.DESCRIPTION
  Always:
    - Refuses gitlinks/submodules (mode 160000) in the index.
  Default (fast):
    - Runs a quick Python "syntax/lint-ish" pass via compileall if Python exists.
    - Runs a small pytest subset if pytest exists.
  Full:
    - Set QC_PREPUSH_FULL=1 to run full pytest suite.

  Strict:
    - Set QC_PREPUSH_STRICT=1 to fail if python/pytest missing.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info([string] $Msg) { Write-Host "[pre-push] $Msg" }
function Write-Warn([string] $Msg) { Write-Warning "[pre-push] $Msg" }

function Get-GitTop() { (git rev-parse --show-toplevel).Trim() }

function Invoke-External {
  param(
    [Parameter(Mandatory=$true)] [string] $File,
    [Parameter(Mandatory=$true)] [string[]] $Args
  )

  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName = $File
  foreach ($a in $Args) { [void] $psi.ArgumentList.Add($a) }

  $psi.UseShellExecute = $false
  $psi.RedirectStandardInput = $true

  $p = [System.Diagnostics.Process]::Start($psi)

  # Critical: pre-push provides refs on stdin; close so children never read them.
  $p.StandardInput.Close()

  $p.WaitForExit()
  if ($p.ExitCode -ne 0) {
    throw "Command failed ($File): $($Args -join ' ')"
  }
}

function Fail-IfGitlinksStaged {
  $lines = git ls-files --stage
  $gitlinks = @($lines | Select-String -Pattern '^\s*160000\s' -AllMatches | ForEach-Object { $_.Line })

  if ($gitlinks.Count -gt 0) {
    Write-Host "Detected gitlinks/submodules in index (mode 160000):"
    $gitlinks | ForEach-Object { Write-Host "  $_" }
    throw "Refusing to push with gitlinks/submodules staged. Remove them (git rm --cached <path>) and retry."
  }

  if (Test-Path ".gitmodules") {
    $strict = ($env:QC_PREPUSH_STRICT -eq "1")
    $msg = ".gitmodules exists. If not intentional, remove it."
    if ($strict) { throw $msg } else { Write-Warn $msg }
  }
}

function Get-PythonPath {
  try { return (Get-Command python -ErrorAction Stop).Source } catch { return $null }
}

function Has-Pytest([string] $Python) {
  try {
    Invoke-External -File $Python -Args @("-c","import pytest; print(pytest.__version__)")
    return $true
  } catch {
    return $false
  }
}

function Try-CompileAll([string] $Python) {
  Write-Info "fast: compileall"
  Invoke-External -File $Python -Args @("-m","compileall","-q",".")
}

function Try-PytestFast([string] $Python) {
  # Conservative "fast" filter that won't explode if markers don't exist.
  Write-Info "fast: pytest subset"
  Invoke-External -File $Python -Args @(
    "-m","pytest","-q",
    "--maxfail=1",
    "-k","not integration and not e2e and not slow"
  )
}

function Try-PytestFull([string] $Python) {
  Write-Info "full: pytest"
  Invoke-External -File $Python -Args @("-m","pytest","-q")
}

try {
  Push-Location (Get-GitTop)

  # Drain git's pre-push stdin refs if present (avoid accidental consumers).
  if ([System.Console]::IsInputRedirected) {
    [void] [System.Console]::In.ReadToEnd()
  }

  Write-Info "starting"
  Fail-IfGitlinksStaged

  $strict = ($env:QC_PREPUSH_STRICT -eq "1")
  $full = ($env:QC_PREPUSH_FULL -eq "1")

  $py = Get-PythonPath
  if (-not $py) {
    $msg = "python not found; skipping python checks."
    if ($strict) { throw $msg } else { Write-Warn $msg; Write-Info "ok"; exit 0 }
  }

  Try-CompileAll -Python $py

  $hasPytest = Has-Pytest -Python $py
  if (-not $hasPytest) {
    $msg = "pytest not installed; skipping tests. (Fix: python -m ensurepip --upgrade; python -m pip install -r requirements-dev.txt)"
    if ($strict) { throw $msg } else { Write-Warn $msg; Write-Info "ok"; exit 0 }
  }

  if ($full) { Try-PytestFull -Python $py } else { Try-PytestFast -Python $py }

  Write-Info "ok"
} finally {
  Pop-Location
}
