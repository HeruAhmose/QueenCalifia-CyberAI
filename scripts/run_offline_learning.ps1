<#
.SYNOPSIS
  Run qc_offline_learning.py (no API key, no network).

.EXAMPLE
  .\scripts\run_offline_learning.ps1 -Synthetic 50
#>
param(
    [int]$Synthetic = 40,
    [string]$Db = "",
    [string]$Corpus = "scripts\offline_corpus\sample_scan.json"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

chcp 65001 | Out-Null
$env:PYTHONUTF8 = "1"

$pyArgs = @(
    (Join-Path $RepoRoot "scripts\qc_offline_learning.py"),
    "--synthetic", $Synthetic,
    "--corpus", (Join-Path $RepoRoot $Corpus)
)
if ($Db) { $pyArgs += @("--db", $Db) }

& python @pyArgs
exit $LASTEXITCODE
