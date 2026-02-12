param(
  [string]$VenvPath = ".venv",
  [switch]$SkipLock,
  [switch]$LockOnly,
  [switch]$RunFrontendTests,
  [switch]$InstallNode,
  [string]$FrontendDir = "frontend"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Require-Cmd([string]$name) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) { return $false }
  return $true
}

function Ensure-Venv {
  if (!(Test-Path $VenvPath)) {
    Write-Host "Creating venv: $VenvPath"
    python -m venv $VenvPath
    if ($LASTEXITCODE -ne 0) { throw "Failed to create venv." }
  }
  $venvPython = Join-Path $VenvPath "Scripts\python.exe"
  if (!(Test-Path $venvPython)) { throw "Venv python not found at: $venvPython" }
  return $venvPython
}

function Pip([string]$venvPython, [string[]]$pipArgs) {
  & $venvPython -m pip @pipArgs
  if ($LASTEXITCODE -ne 0) { throw "pip failed: $($pipArgs -join ' ')" }
}

function Compile-Lock([string]$venvPython, [string]$inFile, [string]$outFile) {
  if (!(Test-Path $inFile)) { return $false }
  Write-Host "Compiling: $outFile (from $inFile)"
  & $venvPython -m piptools compile --resolver=backtracking --generate-hashes --allow-unsafe --strip-extras `
    --output-file $outFile $inFile
  if ($LASTEXITCODE -ne 0) { throw "piptools compile failed for $inFile" }
  return (Test-Path $outFile)
}

function Install-FromFirst([string]$venvPython, [string[]]$files) {
  foreach ($f in $files) {
    if (Test-Path $f) {
      Write-Host "Installing from $f"
      Pip $venvPython @("install","-r",$f)
      return $true
    }
  }
  return $false
}

function Ensure-Node {
  if (Require-Cmd "node" -and (Require-Cmd "npm")) { return }

  if (-not $InstallNode) {
    throw "Node/npm not found. Re-run with -InstallNode or install Node LTS manually."
  }

  if (-not (Require-Cmd "winget")) {
    throw "winget not found. Install Node LTS manually (nodejs.org) or install winget."
  }

  Write-Host "Installing Node.js LTS via winget..."
  winget install -e --id OpenJS.NodeJS.LTS --accept-package-agreements --accept-source-agreements
  if ($LASTEXITCODE -ne 0) { throw "winget failed installing Node.js LTS." }

  if (-not (Require-Cmd "node")) { throw "node still not available after install." }
}

function Run-Frontend-Tests {
  $dir = Join-Path (Get-Location) $FrontendDir
  if (!(Test-Path $dir)) { throw "Frontend dir not found: $dir" }
  if (!(Test-Path (Join-Path $dir "package.json"))) { throw "package.json not found in: $dir" }

  Ensure-Node

  Push-Location $dir
  try {
    # choose package manager by lockfile; prefer deterministic install
    if (Test-Path "pnpm-lock.yaml") {
      if (-not (Require-Cmd "corepack")) { throw "corepack missing (should come with modern Node). Install Node LTS." }
      corepack enable | Out-Null
      pnpm -v | Out-Null
      pnpm install --frozen-lockfile
      pnpm test
    } elseif (Test-Path "yarn.lock") {
      if (-not (Require-Cmd "corepack")) { throw "corepack missing (should come with modern Node). Install Node LTS." }
      corepack enable | Out-Null
      yarn -v | Out-Null
      yarn install --frozen-lockfile
      yarn test
    } else {
      if (Test-Path "package-lock.json") { npm ci } else { npm install }
      npm test
    }

    if ($LASTEXITCODE -ne 0) { throw "Frontend tests failed." }
  } finally {
    Pop-Location
  }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

if (-not (Require-Cmd "python")) { throw "python not found on PATH. Install Python 3.12+." }

$venvPython = Ensure-Venv

Pip $venvPython @("install","--upgrade","pip","setuptools","wheel")
Pip $venvPython @("install","--upgrade","pip-tools")

# Windows-specific deterministic locks (runtime + dev)
if (-not $SkipLock) {
  [void](Compile-Lock $venvPython "requirements.in" "requirements.lock.win")
  [void](Compile-Lock $venvPython "requirements-dev.in" "requirements-dev.lock.win")
}

if ($LockOnly) { Write-Host "OK: lock-only completed."; exit 0 }

# Install dev deps for tests
$ok = $false
$ok = $ok -or (Install-FromFirst $venvPython @("requirements-dev.lock.win","requirements-dev.lock","requirements-dev.txt"))
if (-not $ok) {
  Write-Host "No dev requirements file found; installing pytest fallback."
  Pip $venvPython @("install","pytest")
}

Write-Host "Running backend tests..."
& $venvPython -m pytest -q
if ($LASTEXITCODE -ne 0) { throw "pytest failed." }

if ($RunFrontendTests) {
  Write-Host "Running frontend tests..."
  Run-Frontend-Tests
}

Write-Host "OK: Windows setup + tests completed."
