<#
.SYNOPSIS
  Run qc_perpetual_learner.py with UTF-8 console.

.EXAMPLE
  $env:QC_API_KEY = '...'
  .\scripts\run_perpetual_learner.ps1 -Workers 16
#>
param(
    [int]$Workers = 16,
    [int]$Batch = 48,
    [switch]$Heavy
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

if (-not $env:QC_API_KEY -or -not $env:QC_API_KEY.Trim()) {
    Write-Host "QC_API_KEY is not set." -ForegroundColor Yellow
    exit 1
}

chcp 65001 | Out-Null
$env:PYTHONUTF8 = "1"

$pyArgs = @(
    (Join-Path $RepoRoot "scripts\qc_perpetual_learner.py"),
    "--workers", $Workers,
    "--batch", $Batch
)
if ($Heavy) { $pyArgs += "--heavy" }

& python @pyArgs
exit $LASTEXITCODE
