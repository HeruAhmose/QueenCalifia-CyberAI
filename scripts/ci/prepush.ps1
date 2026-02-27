#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Cross-platform pre-push checks (PowerShell 7).

.DESCRIPTION
  Default (FAST) mode:
    - Blocks pushes that stage gitlinks/submodules (mode 160000).
    - Optionally lints GitHub Actions YAML if actionlint/yamllint is installed.
    - Runs python compileall.
    - If pytest is installed, runs a small fast test set (zero-day predictor tests).

  FULL mode:
    - Set QC_PREPUSH_FULL=1 to run full pytest suite (pytest -q).

  STRICT mode:
    - Set QC_PREPUSH_STRICT=1 to fail push if python/pytest/tooling is missing.

  Tip:
    - To skip locally: set QC_PREPUSH_SKIP=1 (or use git push --no-verify).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info([string] $Msg) { Write-Host "[pre-push] $Msg" }
function Write-Warn([string] $Msg) { Write-Warning "[pre-push] $Msg" }

function GitTop() { (git rev-parse --show-toplevel).Trim() }

function Exec([string] $File, [string[]] $Args, [switch] $NoStdin) {
  $tmpIn = $null
  try {
    if ($NoStdin) {
      $tmpIn = Join-Path $env:TEMP ("qc_empty_stdin_" + [Guid]::NewGuid().ToString("n") + ".txt")
      Set-Content -Path $tmpIn -Value "" -Encoding Ascii
      $p = Start-Process -FilePath $File -ArgumentList $Args -NoNewWindow -Wait -PassThru -RedirectStandardInput $tmpIn
    } else {
      $p = Start-Process -FilePath $File -ArgumentList $Args -NoNewWindow -Wait -PassThru
    }
    if ($p.ExitCode -ne 0) { throw "Command failed ($File): $($Args -join ' ')" }
  } finally {
    if ($tmpIn -and (Test-Path $tmpIn)) { Remove-Item -Force $tmpIn -ErrorAction SilentlyContinue }
  }
}

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

function Resolve-Python() {
  # Prefer local venv
  if (Test-Path ".venv/Scripts/python.exe") { return (Resolve-Path ".venv/Scripts/python.exe").Path }
  try { return (Get-Command python -ErrorAction Stop).Source } catch {}
  try { return (Get-Command py -ErrorAction Stop).Source } catch {}
  return $null
}

function Has-Module([string] $Py, [string] $ModuleName) {
  try { Exec $Py @("-c", "import $ModuleName; print(getattr($ModuleName,'__version__','ok'))") -NoStdin; return $true } catch { return $false }
}

function TryRunActionlint() {
  $strict = [bool]($env:QC_PREPUSH_STRICT -eq "1")
  try {
    $cmd = (Get-Command actionlint -ErrorAction Stop).Source
    Write-Info "lint: GitHub Actions (actionlint)"
    Exec $cmd @() -NoStdin
  } catch {
    $msg = "actionlint not found; skipping GitHub Actions lint."
    if ($strict) { throw $msg } else { Write-Warn $msg }
  }
}

function TryRunYamllint() {
  $strict = [bool]($env:QC_PREPUSH_STRICT -eq "1")
  try {
    $cmd = (Get-Command yamllint -ErrorAction Stop).Source
    if (Test-Path ".github/workflows") {
      Write-Info "lint: YAML (yamllint) on .github/workflows"
      Exec $cmd @(".github/workflows") -NoStdin
    }
  } catch {
    $msg = "yamllint not found; skipping YAML lint."
    if ($strict) { throw $msg } else { Write-Warn $msg }
  }
}

function RunCompileAll([string] $Py) {
  Write-Info "fast: compileall"
  $targets = @("api","core","engines","scripts","tests")
  $args = @("-m","compileall","-q") + $targets
  Exec $Py $args -NoStdin
}

function RunPytestFast([string] $Py) {
  # Only run if pytest exists
  if (-not (Has-Module $Py "pytest")) {
    $msg = "pytest not installed; skipping tests. (Run: pwsh -File scripts/dev/python_bootstrap_windows.ps1 -Dev)"
    if ($env:QC_PREPUSH_STRICT -eq "1") { throw $msg } else { Write-Warn $msg; return }
  }
  Write-Info "fast: pytest (zero-day predictor)"
  Exec $Py @("-m","pytest","-q","tests/test_zero_day_predictor.py") -NoStdin
}

function RunPytestFull([string] $Py) {
  if (-not (Has-Module $Py "pytest")) {
    $msg = "pytest not installed; cannot run full test suite."
    if ($env:QC_PREPUSH_STRICT -eq "1") { throw $msg } else { Write-Warn $msg; return }
  }
  Write-Info "full: pytest"
  Exec $Py @("-m","pytest","-q") -NoStdin
}

if ($env:QC_PREPUSH_SKIP -eq "1") {
  Write-Warn "QC_PREPUSH_SKIP=1 set; skipping checks."
  exit 0
}

try {
  Push-Location (GitTop)
  Write-Info "starting"
  FailIfGitlinksStaged

  TryRunActionlint
  TryRunYamllint

  $py = Resolve-Python
  if (-not $py) {
    $msg = "python not found; skipping python checks."
    if ($env:QC_PREPUSH_STRICT -eq "1") { throw $msg } else { Write-Warn $msg; Write-Info "ok"; exit 0 }
  }

  RunCompileAll $py

  $full = [bool]($env:QC_PREPUSH_FULL -eq "1")
  if ($full) { RunPytestFull $py } else { RunPytestFast $py }

  Write-Info "ok"
} finally {
  Pop-Location
}
