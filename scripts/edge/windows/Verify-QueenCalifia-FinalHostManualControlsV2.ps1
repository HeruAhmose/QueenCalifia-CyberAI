#requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$VmName = 'QueenCalifia-Sovereign-Edge-HyperV'
$EvidenceRoot = Join-Path $env:ProgramData 'QueenCalifia\evidence'
$HostEvidenceRoot = Join-Path $EvidenceRoot 'hyperv-final-host'
$DossierRoot = Join-Path $EvidenceRoot 'hyperv-final-host-manual-controls'
$RequestPath = Join-Path $DossierRoot 'request.json'
$BiosEvidenceRoot = Join-Path $DossierRoot 'bios-evidence'
$UpsEvidenceRoot = Join-Path $DossierRoot 'ups-evidence'
$VerificationPath = Join-Path $DossierRoot 'verification.json'
$QcControl = Join-Path $PSScriptRoot 'qc.ps1'
$RequestSchema = 'queen-califia-hyperv-final-host-manual-controls-request-v2'
$OutputSchema = 'queen-califia-hyperv-final-host-manual-controls-verification-v2'
$Attestation = 'I attest that the BIOS restore-after-power-loss and UPS results in this request describe physical tests performed on the selected Queen Califia Windows Hyper-V final production host, and that this verifier only prepares those assertions for human review.'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'FINAL_HOST_MANUAL_CONTROLS_ERROR=run PowerShell 7 as Administrator'
    }
}

function Get-FileSha256Lower([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-RegularNonEmptyFile([string]$Path,[string]$Label) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer) { throw "FINAL_HOST_MANUAL_CONTROLS_ERROR=$Label must be a file: $Path" }
    if ($item.LinkType) { throw "FINAL_HOST_MANUAL_CONTROLS_ERROR=$Label symlink/reparse substitution refused: $Path" }
    if ($item.Length -le 0) { throw "FINAL_HOST_MANUAL_CONTROLS_ERROR=$Label must be non-empty: $Path" }
    $item
}

function Get-EvidenceFiles([string]$Root,[string]$Label) {
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw "FINAL_HOST_MANUAL_CONTROLS_ERROR=missing $Label evidence directory: $Root"
    }
    $rootItem = Get-Item -LiteralPath $Root -Force
    if ($rootItem.LinkType) { throw "FINAL_HOST_MANUAL_CONTROLS_ERROR=$Label evidence root may not be a symlink/reparse point" }
    $files = @(Get-ChildItem -LiteralPath $Root -File -Recurse -Force | Sort-Object FullName)
    if ($files.Count -eq 0) { throw "FINAL_HOST_MANUAL_CONTROLS_ERROR=at least one $Label evidence file is required" }
    @($files | ForEach-Object {
        $item = Assert-RegularNonEmptyFile -Path $_.FullName -Label $Label
        [pscustomobject]@{
            relative_path = $item.FullName.Substring($Root.Length).TrimStart('\\')
            size = [int64]$item.Length
            sha256 = Get-FileSha256Lower $item.FullName
        }
    })
}

function Get-LatestHostEvidence {
    $latest = Get-ChildItem -LiteralPath $HostEvidenceRoot -Filter 'hyperv-final-host-v2-*.json' -File -ErrorAction Stop |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if (-not $latest) { throw 'FINAL_HOST_MANUAL_CONTROLS_ERROR=no Hyper-V final-host V2 evidence found' }
    Assert-RegularNonEmptyFile -Path $latest.FullName -Label 'final-host evidence' | Out-Null
    $record = Get-Content -LiteralPath $latest.FullName -Raw | ConvertFrom-Json
    if ($record.schema -ne 'queen-califia-hyperv-final-host-evidence-v2') { throw 'FINAL_HOST_MANUAL_CONTROLS_ERROR=unsupported final-host evidence schema' }
    if ($record.automated_host_evidence_ready_for_review -ne $true) { throw 'FINAL_HOST_MANUAL_CONTROLS_ERROR=latest Hyper-V final-host evidence is not review-ready' }
    if ($record.architecture -ne 'windows-physical-host-with-hyperv-ubuntu-guest') { throw 'FINAL_HOST_MANUAL_CONTROLS_ERROR=unexpected final-host architecture' }
    if ($record.guest_control_boundary.authorization_gate_closed -ne $true -or $record.guest_control_boundary.vm_running -ne $true) {
        throw 'FINAL_HOST_MANUAL_CONTROLS_ERROR=source host evidence did not prove running VM with authorization closed'
    }
    [pscustomobject]@{ Item=$latest; Record=$record }
}

function Assert-UtcTimestamp([string]$Value,[string]$Label) {
    if ($Value -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$') {
        throw "FINAL_HOST_MANUAL_CONTROLS_ERROR=$Label must be UTC ISO-8601 ending in Z"
    }
}

function Assert-SubstantiveReference([string]$Value,[string]$Label) {
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Trim().Length -lt 8) {
        throw "FINAL_HOST_MANUAL_CONTROLS_ERROR=$Label evidence_reference must be substantive"
    }
}

function Get-LiveClosedGateEvidence {
    $output = @(& pwsh -NoLogo -NoProfile -File $QcControl status -Hypervisor hyperv -VmName $VmName 2>&1)
    $rc = $LASTEXITCODE
    $text = ($output | ForEach-Object { $_.ToString() }) -join "`n"
    if ($rc -ne 0) { throw "FINAL_HOST_MANUAL_CONTROLS_ERROR=qc status failed with exit code $rc" }
    if ($text -notmatch '(?m)^VM_STATE=Running\s*$') { throw 'FINAL_HOST_MANUAL_CONTROLS_ERROR=QC VM is not running' }
    if ($text -notmatch '(?m)^QUEEN_CALIFIA=BLOCKED\s*$') { throw 'FINAL_HOST_MANUAL_CONTROLS_ERROR=QC authorization gate is not closed' }
    if ($text -notmatch '(?mi)runtime authorization gate is closed') { throw 'FINAL_HOST_MANUAL_CONTROLS_ERROR=closed authorization detail not confirmed' }
    [pscustomobject]@{
        command_exit_code = $rc
        vm_running = $true
        authorization_gate_closed = $true
        expected_closed_detail = $true
    }
}

Assert-Administrator
if (-not (Test-Path -LiteralPath $RequestPath -PathType Leaf)) { throw "FINAL_HOST_MANUAL_CONTROLS_ERROR=missing request: $RequestPath" }
if (Test-Path -LiteralPath $VerificationPath) { throw "FINAL_HOST_MANUAL_CONTROLS_ERROR=refusing to overwrite verification: $VerificationPath" }

$host = Get-LatestHostEvidence
$request = Get-Content -LiteralPath $RequestPath -Raw | ConvertFrom-Json
if ($request.schema -ne $RequestSchema) { throw 'FINAL_HOST_MANUAL_CONTROLS_ERROR=unsupported manual-controls request schema' }
$hostFingerprint = [string]$host.Record.host_identity.fingerprint_sha256
if ($hostFingerprint -notmatch '^[0-9a-f]{64}$') { throw 'FINAL_HOST_MANUAL_CONTROLS_ERROR=source host fingerprint invalid' }
if ([string]$request.host_identity_fingerprint_sha256 -ne $hostFingerprint) { throw 'FINAL_HOST_MANUAL_CONTROLS_ERROR=request does not match selected Windows host fingerprint' }

$bios = $request.bios_restore_after_power_loss
if ($bios.firmware_setting_observed -ne $true) { throw 'FINAL_HOST_MANUAL_CONTROLS_ERROR=firmware setting must be physically observed before asserting true' }
if ($bios.controlled_ac_loss_test_performed -ne $true) { throw 'FINAL_HOST_MANUAL_CONTROLS_ERROR=controlled AC-loss test must actually be performed' }
if ($bios.automatic_power_restore_observed -ne $true) { throw 'FINAL_HOST_MANUAL_CONTROLS_ERROR=automatic power restoration must actually be observed' }
Assert-UtcTimestamp -Value ([string]$bios.observed_at_utc) -Label 'bios_restore_after_power_loss.observed_at_utc'
Assert-SubstantiveReference -Value ([string]$bios.evidence_reference) -Label 'bios_restore_after_power_loss'

$ups = $request.ups
if ($ups.physical_ups_present -ne $true) { throw 'FINAL_HOST_MANUAL_CONTROLS_ERROR=physical UPS presence must actually be observed' }
if ($ups.controlled_utility_interruption_test_performed -ne $true) { throw 'FINAL_HOST_MANUAL_CONTROLS_ERROR=controlled UPS utility interruption must actually be performed' }
if ($ups.host_power_continuity_or_graceful_shutdown_observed -ne $true) { throw 'FINAL_HOST_MANUAL_CONTROLS_ERROR=UPS continuity or approved graceful shutdown must actually be observed' }
if ($ups.post_test_normal_operation_observed -ne $true) { throw 'FINAL_HOST_MANUAL_CONTROLS_ERROR=post-test normal operation must actually be observed' }
Assert-UtcTimestamp -Value ([string]$ups.observed_at_utc) -Label 'ups.observed_at_utc'
Assert-SubstantiveReference -Value ([string]$ups.evidence_reference) -Label 'ups'

if ([string]$request.operator_attestation -ne $Attestation) { throw 'FINAL_HOST_MANUAL_CONTROLS_ERROR=operator attestation does not preserve the physical-test/human-review boundary' }

$biosFiles = Get-EvidenceFiles -Root $BiosEvidenceRoot -Label 'BIOS'
$upsFiles = Get-EvidenceFiles -Root $UpsEvidenceRoot -Label 'UPS'
$liveGate = Get-LiveClosedGateEvidence

$record = [ordered]@{
    schema = $OutputSchema
    verified_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    architecture = 'windows-physical-host-with-hyperv-ubuntu-guest'
    host_identity_fingerprint_sha256 = $hostFingerprint
    source_final_host_evidence = [ordered]@{
        name = $host.Item.Name
        sha256 = Get-FileSha256Lower $host.Item.FullName
    }
    request_sha256 = Get-FileSha256Lower $RequestPath
    bios_evidence_files = $biosFiles
    ups_evidence_files = $upsFiles
    live_guest_control_boundary = $liveGate
    bios_physical_test_assertions_structurally_verified = $true
    ups_physical_test_assertions_structurally_verified = $true
    eligible_for_bios_restore_after_power_loss_review = $true
    eligible_for_ups_review = $true
    physical_truth_automatically_verified = $false
    human_review_required = $true
    automatic_ledger_promotion = $false
    authorization_modified = $false
    deployment_ledger_modified = $false
}

$json = $record | ConvertTo-Json -Depth 12
[IO.File]::WriteAllText($VerificationPath,$json + [Environment]::NewLine,[Text.UTF8Encoding]::new($false))
$sha = Get-FileSha256Lower $VerificationPath
Write-Host 'HYPERV_FINAL_HOST_MANUAL_CONTROLS=ELIGIBLE_FOR_HUMAN_REVIEW'
Write-Host 'HYPERV_FINAL_HOST_BIOS_RESTORE_AFTER_POWER_LOSS=ELIGIBLE_FOR_HUMAN_REVIEW'
Write-Host 'HYPERV_FINAL_HOST_UPS=ELIGIBLE_FOR_HUMAN_REVIEW'
Write-Host "HYPERV_FINAL_HOST_MANUAL_CONTROLS_VERIFICATION=$VerificationPath"
Write-Host "HYPERV_FINAL_HOST_MANUAL_CONTROLS_VERIFICATION_SHA256=$sha"
Write-Host 'HYPERV_FINAL_HOST_PHYSICAL_TRUTH_AUTOMATICALLY_VERIFIED=NO'
Write-Host 'HYPERV_FINAL_HOST_MANUAL_CONTROLS_LEDGER_UPDATED=NO'
Write-Host 'HYPERV_FINAL_HOST_MANUAL_CONTROLS_AUTHORIZATION_UPDATED=NO'
