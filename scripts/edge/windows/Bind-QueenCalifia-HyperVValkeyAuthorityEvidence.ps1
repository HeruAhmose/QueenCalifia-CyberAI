#requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$VmName = 'QueenCalifia-Sovereign-Edge-HyperV'
$EvidenceRoot = Join-Path $env:ProgramData 'QueenCalifia\evidence'
$HostEvidenceRoot = Join-Path $EvidenceRoot 'hyperv-final-host'
$AuthorityRoot = Join-Path $EvidenceRoot 'hyperv-valkey-authority'
$GuestEvidenceRoot = Join-Path $AuthorityRoot 'guest'
$QcControl = Join-Path $PSScriptRoot 'qc.ps1'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$ExpectedCertNames = @('api','ca','health','server','worker')

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'HYPERV_VALKEY_AUTHORITY_ERROR=run PowerShell 7 as Administrator'
    }
}

function Get-FileSha256Lower([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-RegularJsonFile([string]$Path,[string]$Label) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer) { throw "HYPERV_VALKEY_AUTHORITY_ERROR=$Label must be a file: $Path" }
    if ($item.LinkType) { throw "HYPERV_VALKEY_AUTHORITY_ERROR=$Label symlink/reparse substitution refused: $Path" }
    if ($item.Length -le 0) { throw "HYPERV_VALKEY_AUTHORITY_ERROR=$Label must be non-empty: $Path" }
    try { $record = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json }
    catch { throw "HYPERV_VALKEY_AUTHORITY_ERROR=invalid JSON in ${Label}: $Path" }
    [pscustomobject]@{ Item=$item; Record=$record }
}

function Get-Newest([string]$Root,[string]$Filter,[string]$Label) {
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw "HYPERV_VALKEY_AUTHORITY_ERROR=missing $Label root: $Root"
    }
    $rootItem = Get-Item -LiteralPath $Root -Force
    if ($rootItem.LinkType) { throw "HYPERV_VALKEY_AUTHORITY_ERROR=$Label root may not be a symlink/reparse point" }
    $latest = Get-ChildItem -LiteralPath $Root -Filter $Filter -File -Force |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if (-not $latest) { throw "HYPERV_VALKEY_AUTHORITY_ERROR=no $Label evidence found" }
    Assert-RegularJsonFile -Path $latest.FullName -Label $Label
}

function Normalize-Guid([string]$Value,[string]$Label) {
    $parsed = [guid]::Empty
    if (-not [guid]::TryParse($Value,[ref]$parsed)) {
        throw "HYPERV_VALKEY_AUTHORITY_ERROR=invalid GUID for ${Label}: $Value"
    }
    $parsed.ToString('D').ToLowerInvariant()
}

function Assert-Hex40([string]$Value,[string]$Label) {
    if ($Value -notmatch '^[0-9a-f]{40}$') { throw "HYPERV_VALKEY_AUTHORITY_ERROR=invalid SHA-1 for ${Label}: $Value" }
}

function Assert-Hex64([string]$Value,[string]$Label) {
    if ($Value -notmatch '^[0-9a-f]{64}$') { throw "HYPERV_VALKEY_AUTHORITY_ERROR=invalid SHA-256 for ${Label}: $Value" }
}

function Get-CertMap([object]$Map,[string]$Label) {
    if ($null -eq $Map) { throw "HYPERV_VALKEY_AUTHORITY_ERROR=missing certificate map: $Label" }
    $names = @($Map.PSObject.Properties.Name | Sort-Object)
    if (($names -join ',') -ne ($ExpectedCertNames -join ',')) {
        throw "HYPERV_VALKEY_AUTHORITY_ERROR=unexpected certificate identities in ${Label}: $($names -join ',')"
    }
    $result = [ordered]@{}
    foreach ($name in $ExpectedCertNames) {
        $value = [string]$Map.$name
        Assert-Hex64 -Value $value -Label "$Label.$name"
        $result[$name] = $value
    }
    $result
}

function Get-LiveClosedGateEvidence {
    $output = @(& pwsh -NoLogo -NoProfile -File $QcControl status -Hypervisor hyperv -VmName $VmName 2>&1)
    $rc = $LASTEXITCODE
    $text = ($output | ForEach-Object { $_.ToString() }) -join "`n"
    if ($rc -ne 0) { throw "HYPERV_VALKEY_AUTHORITY_ERROR=qc status failed with exit code $rc" }
    if ($text -notmatch '(?m)^VM_STATE=Running\s*$') { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=QC VM is not running' }
    if ($text -notmatch '(?m)^QUEEN_CALIFIA=BLOCKED\s*$') { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=QC authorization gate is not closed' }
    if ($text -notmatch '(?mi)runtime authorization gate is closed') { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=closed authorization detail not confirmed' }
    [ordered]@{
        command_exit_code = $rc
        vm_running = $true
        authorization_gate_closed = $true
        expected_closed_detail = $true
    }
}

Assert-Administrator
foreach ($cmd in @('Get-VM','git','pwsh')) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        throw "HYPERV_VALKEY_AUTHORITY_ERROR=required command missing: $cmd"
    }
}

$repoHead = (& git -C $RepoRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=git rev-parse failed' }
Assert-Hex40 -Value $repoHead -Label 'Windows repository head'
$dirty = @(& git -C $RepoRoot status --porcelain)
if ($LASTEXITCODE -ne 0) { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=git status failed' }
if ($dirty.Count -gt 0) { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=Windows repository checkout must be clean' }
$branch = (& git -C $RepoRoot branch --show-current).Trim()
if ($branch -ne 'main') { throw "HYPERV_VALKEY_AUTHORITY_ERROR=Windows repository must be on protected main; observed $branch" }

$host = Get-Newest -Root $HostEvidenceRoot -Filter 'hyperv-final-host-v2-*.json' -Label 'Windows final-host'
if ($host.Record.schema -ne 'queen-califia-hyperv-final-host-evidence-v2') { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=unsupported Windows final-host schema' }
if ($host.Record.architecture -ne 'windows-physical-host-with-hyperv-ubuntu-guest') { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=unexpected Windows final-host architecture' }
if ($host.Record.automated_host_evidence_ready_for_review -ne $true) { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=Windows final-host evidence is not review-ready' }
if ($host.Record.guest_control_boundary.vm_running -ne $true -or $host.Record.guest_control_boundary.authorization_gate_closed -ne $true) {
    throw 'HYPERV_VALKEY_AUTHORITY_ERROR=Windows final-host evidence did not prove running guest with closed authorization'
}
$hostHead = [string]$host.Record.repository.head
Assert-Hex40 -Value $hostHead -Label 'Windows final-host Git head'
if ($hostHead -ne $repoHead) { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=Windows final-host evidence must be recollected at current protected main before binding' }
$hostFingerprint = [string]$host.Record.host_identity.fingerprint_sha256
Assert-Hex64 -Value $hostFingerprint -Label 'Windows physical-host fingerprint'
$hostVmId = Normalize-Guid -Value ([string]$host.Record.hyperv.vm_id) -Label 'Windows Hyper-V VM ID'

$pki = Get-Newest -Root $GuestEvidenceRoot -Filter 'hyperv-final-valkey-pki-*.json' -Label 'guest Hyper-V Valkey PKI'
$runtime = Get-Newest -Root $GuestEvidenceRoot -Filter 'runtime-*.json' -Label 'guest preauthorization runtime'
$binding = Get-Newest -Root $GuestEvidenceRoot -Filter 'hyperv-runtime-binding-*.json' -Label 'guest Hyper-V runtime binding'

if ($pki.Record.schema -ne 'queen-califia-hyperv-final-valkey-pki-evidence-v1') { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=unsupported Hyper-V PKI schema' }
if ($runtime.Record.schema -ne 'queen-califia-sovereign-edge-runtime-evidence-v2' -or $runtime.Record.mode -ne '--preauth') { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=runtime evidence must be v2 preauthorization evidence' }
if ($binding.Record.schema -ne 'queen-califia-hyperv-runtime-binding-evidence-v1') { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=unsupported Hyper-V runtime binding schema' }

if ($pki.Record.virtualization -ne 'microsoft' -or $binding.Record.virtualization -ne 'microsoft') { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=guest evidence is not Microsoft Hyper-V evidence' }
if ($pki.Record.pki_material_verified -ne $true -or $pki.Record.repository_clean -ne $true) { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=offline Hyper-V PKI evidence is not review-ready' }
if ($pki.Record.eligible_for_pki_generated_review -ne $true -or $pki.Record.live_valkey_authority_verified -ne $false) { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=unexpected offline PKI eligibility state' }
if ($runtime.Record.authorization_marker_present -ne $false -or $runtime.Record.repository_clean -ne $true) { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=runtime preauthorization boundary is invalid' }
if ($binding.Record.runtime_preauthorization_claims_verified -ne $true -or $binding.Record.authorization_marker_absent_verified -ne $true) { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=runtime binding claims are incomplete' }
if ($runtime.Record.running_application_containers.Count -ne 0) { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=preauthorization runtime includes application containers' }

foreach ($claim in @('no_host_ports_published','valkey_tls_verified','valkey_plaintext_refused','valkey_client_certificate_required','valkey_health_client_verified','valkey_api_client_verified','valkey_worker_client_verified','unauthorized_application_runtime_absent')) {
    if ($runtime.Record.claims.$claim -ne $true) { throw "HYPERV_VALKEY_AUTHORITY_ERROR=runtime claim must be true: $claim" }
}
if ($runtime.Record.claims.authorized_runtime_probed -ne $false) { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=runtime evidence unexpectedly probed authorized runtime' }

$pkiVmId = Normalize-Guid -Value ([string]$pki.Record.hyperv_guest_vm_id_raw) -Label 'PKI guest VM ID'
$bindingVmId = Normalize-Guid -Value ([string]$binding.Record.hyperv_guest_vm_id_raw) -Label 'runtime-binding guest VM ID'
if ($hostVmId -ne $pkiVmId -or $hostVmId -ne $bindingVmId) { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=Windows Hyper-V VM ID and guest DMI VM IDs do not match' }

$pkiGuestFp = [string]$pki.Record.guest_host_identity_fingerprint_sha256
$runtimeGuestFp = [string]$runtime.Record.host_identity_fingerprint_sha256
$bindingGuestFp = [string]$binding.Record.guest_host_identity_fingerprint_sha256
foreach ($entry in @(@('PKI guest fingerprint',$pkiGuestFp),@('runtime guest fingerprint',$runtimeGuestFp),@('binding guest fingerprint',$bindingGuestFp))) { Assert-Hex64 -Value $entry[1] -Label $entry[0] }
if ($pkiGuestFp -ne $runtimeGuestFp -or $pkiGuestFp -ne $bindingGuestFp) { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=guest host fingerprints do not match across evidence' }

$pkiHead = [string]$pki.Record.git_head
$runtimeHead = [string]$runtime.Record.git_head
$bindingHead = [string]$binding.Record.git_head
foreach ($entry in @(@('PKI Git head',$pkiHead),@('runtime Git head',$runtimeHead),@('binding Git head',$bindingHead))) { Assert-Hex40 -Value $entry[1] -Label $entry[0] }
if ($repoHead -ne $pkiHead -or $repoHead -ne $runtimeHead -or $repoHead -ne $bindingHead) { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=Windows and guest evidence Git heads do not all match protected main' }

$pkiCerts = Get-CertMap -Map $pki.Record.certificate_fingerprints_sha256 -Label 'offline PKI'
$runtimeCerts = Get-CertMap -Map $runtime.Record.valkey_certificate_fingerprints_sha256 -Label 'runtime'
$bindingCerts = Get-CertMap -Map $binding.Record.valkey_certificate_fingerprints_sha256 -Label 'runtime binding'
foreach ($name in $ExpectedCertNames) {
    if ($pkiCerts[$name] -ne $runtimeCerts[$name] -or $pkiCerts[$name] -ne $bindingCerts[$name]) {
        throw "HYPERV_VALKEY_AUTHORITY_ERROR=certificate fingerprint mismatch for $name"
    }
}

$runtimeSha = Get-FileSha256Lower $runtime.Item.FullName
if ([string]$binding.Record.runtime_source.sha256 -ne $runtimeSha) { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=runtime binding does not hash-bind to copied runtime evidence' }
if ([string]$binding.Record.runtime_source.name -ne $runtime.Item.Name) { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=runtime binding source filename differs from copied runtime evidence' }
if ([string]$binding.Record.runtime_source.boot_id -ne [string]$runtime.Record.boot_id) { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=runtime binding boot ID differs from runtime evidence' }

$liveGate = Get-LiveClosedGateEvidence
$vm = Get-VM -Name $VmName -ErrorAction Stop
$currentVmId = Normalize-Guid -Value ([string]$vm.Id) -Label 'current Hyper-V VM ID'
if ($currentVmId -ne $hostVmId) { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=current Hyper-V VM identity differs from reviewed host evidence' }
if ([string]$vm.State -ne 'Running') { throw 'HYPERV_VALKEY_AUTHORITY_ERROR=current Hyper-V VM is not running' }

New-Item -ItemType Directory -Path $AuthorityRoot -Force | Out-Null
$stamp = [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$output = Join-Path $AuthorityRoot "hyperv-final-valkey-authority-$stamp.json"
if (Test-Path -LiteralPath $output) { throw "HYPERV_VALKEY_AUTHORITY_ERROR=refusing to overwrite authority evidence: $output" }

$record = [ordered]@{
    schema = 'queen-califia-hyperv-final-valkey-authority-evidence-v1'
    bound_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    architecture = 'windows-physical-host-with-hyperv-ubuntu-guest'
    windows_physical_host_identity_fingerprint_sha256 = $hostFingerprint
    hyperv_vm_id = $hostVmId
    guest_host_identity_fingerprint_sha256 = $pkiGuestFp
    git_head = $repoHead
    valkey_certificate_fingerprints_sha256 = $pkiCerts
    source_evidence = [ordered]@{
        windows_final_host = [ordered]@{ name=$host.Item.Name; sha256=Get-FileSha256Lower $host.Item.FullName }
        guest_valkey_pki = [ordered]@{ name=$pki.Item.Name; sha256=Get-FileSha256Lower $pki.Item.FullName }
        guest_runtime_preauthorization = [ordered]@{ name=$runtime.Item.Name; sha256=$runtimeSha; boot_id=[string]$runtime.Record.boot_id }
        guest_runtime_binding = [ordered]@{ name=$binding.Item.Name; sha256=Get-FileSha256Lower $binding.Item.FullName }
    }
    live_guest_control_boundary = $liveGate
    same_hyperv_vm_identity = $true
    same_guest_identity = $true
    same_repository_head = $true
    same_valkey_pki = $true
    live_mtls_authority_verified = $true
    plaintext_refusal_verified = $true
    client_certificate_requirement_verified = $true
    all_intended_client_identities_verified = $true
    no_host_ports_published_verified = $true
    unauthorized_application_runtime_absent_verified = $true
    authorization_gate_closed_verified = $true
    eligible_for_pki_generated_review = $true
    eligible_for_authority_verified_review = $true
    automatic_ledger_promotion = $false
    authorization_modified = $false
    deployment_ledger_modified = $false
}

[IO.File]::WriteAllText($output,($record | ConvertTo-Json -Depth 12) + [Environment]::NewLine,[Text.UTF8Encoding]::new($false))
$sha = Get-FileSha256Lower $output
Write-Host 'HYPERV_FINAL_VALKEY_AUTHORITY_EVIDENCE=PASS'
Write-Host 'HYPERV_FINAL_VALKEY_PKI_GENERATED=ELIGIBLE_FOR_HUMAN_REVIEW'
Write-Host 'HYPERV_FINAL_VALKEY_AUTHORITY_VERIFIED=ELIGIBLE_FOR_HUMAN_REVIEW'
Write-Host "HYPERV_FINAL_VALKEY_AUTHORITY_EVIDENCE_PATH=$output"
Write-Host "HYPERV_FINAL_VALKEY_AUTHORITY_EVIDENCE_SHA256=$sha"
Write-Host "HYPERV_FINAL_VALKEY_VM_ID=$hostVmId"
Write-Host 'HYPERV_FINAL_VALKEY_LEDGER_UPDATED=NO'
Write-Host 'HYPERV_FINAL_VALKEY_AUTHORIZATION_UPDATED=NO'
