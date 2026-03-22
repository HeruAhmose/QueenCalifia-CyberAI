<#
.SYNOPSIS
  Run qc_sovereign_training.py with UTF-8 console and Render-friendly /healthz retries.

.DESCRIPTION
  Expects QC_API_KEY in the environment (set before calling):
    $env:QC_API_KEY = 'your-render-key'

.EXAMPLE
  $env:QC_API_KEY = '...'
  .\scripts\run_training_advanced.ps1

.EXAMPLE
  .\scripts\run_training_advanced.ps1 -Phase all -HealthTimeout 90 -HealthRetries 5
#>
param(
    [ValidateSet("infrastructure", "identity", "functions", "workflows", "adversarial", "production", "competitive", "all", "advanced")]
    [string]$Phase = "advanced",

    [int]$HealthTimeout = 90,
    [int]$HealthRetries = 5,
    [string]$BaseUrl = "",
    [switch]$NoReport
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

if (-not $env:QC_API_KEY -or -not $env:QC_API_KEY.Trim()) {
    Write-Host "QC_API_KEY is not set. In this shell run:" -ForegroundColor Yellow
    Write-Host '  $env:QC_API_KEY = "<your Render QC_API_KEY value>"' -ForegroundColor Gray
    exit 1
}

chcp 65001 | Out-Null
$env:PYTHONUTF8 = "1"

$pyArgs = @(
    (Join-Path $RepoRoot "scripts\qc_sovereign_training.py"),
    "--phase", $Phase,
    "--health-timeout", $HealthTimeout,
    "--health-retries", $HealthRetries
)
if ($BaseUrl) {
    $pyArgs += @("--base-url", $BaseUrl)
}
if ($NoReport) {
    $pyArgs += "--no-report"
}

Write-Host "Repo: $RepoRoot" -ForegroundColor Cyan
Write-Host "python $($pyArgs -join ' ')" -ForegroundColor DarkGray
& python @pyArgs
exit $LASTEXITCODE
