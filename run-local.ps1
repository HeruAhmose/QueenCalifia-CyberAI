Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "Starting backend..."
Start-Process powershell -ArgumentList @(
    "-NoExit", "-Command",
    "Set-Location '$repoRoot\backend'; if (-not (Test-Path .venv)) { python -m venv .venv }; . .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt; if (-not (Test-Path .env)) { Copy-Item .env.example .env }; python .\app.py"
)

Write-Host "Starting frontend..."
Start-Process powershell -ArgumentList @(
    "-NoExit", "-Command",
    "Set-Location '$repoRoot\frontend'; npm install; npm run dev"
)
