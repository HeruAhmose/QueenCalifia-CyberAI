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
        throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=run PowerShell 7 as Administrator'
    }
}

function Get-FileSha256Lower([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-RegularJsonFile([string]$Path,[string]$Label) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer) { throw "HYPERV_VALKEY_AUTHORITY_V2_ERROR=${Label} must be a file: $Path" }
    if ($item.LinkType) { throw "HYPERV_VALKEY_AUTHORITY_V2_ERROR=${Label} symlink/reparse substitution refused: $Path" }
    if ($item.Length -le 0) { throw "HYPERV_VALKEY_AUTHORITY_V2_ERROR=${Label} must be non-empty: $Path" }
    try { $record = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json }
    catch { throw "HYPERV_VALKEY_AUTHORITY_V2_ERROR=invalid JSON in ${Label}: $Path" }
    [pscustomobject]@{ Item=$item; Record=$record }
}

function Get-Newest([string]$Root,[string]$Filter,[string]$Label) {
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw "HYPERV_VALKEY_AUTHORITY_V2_ERROR=missing ${Label} root: $Root"
    }
    $latest = Get-ChildItem -LiteralPath $Root -Filter $Filter -File -Force |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if (-not $latest) { throw "HYPERV_VALKEY_AUTHORITY_V2_ERROR=no ${Label} evidence found" }
    Assert-RegularJsonFile -Path $latest.FullName -Label $Label
}

function Assert-Hex40([string]$Value,[string]$Label) {
    if ($Value -notmatch '^[0-9a-f]{40}$') { throw "HYPERV_VALKEY_AUTHORITY_V2_ERROR=invalid SHA-1 for ${Label}: $Value" }
}

function Assert-Hex64([string]$Value,[string]$Label) {
    if ($Value -notmatch '^[0-9a-f]{64}$') { throw "HYPERV_VALKEY_AUTHORITY_V2_ERROR=invalid SHA-256 for ${Label}: $Value" }
}

function Normalize-Guid([string]$Value,[string]$Label) {
    $parsed = [guid]::Empty
    if (-not [guid]::TryParse($Value,[ref]$parsed)) {
        throw "HYPERV_VALKEY_AUTHORITY_V2_ERROR=invalid GUID for ${Label}: $Value"
    }
    $parsed.ToString('D').ToLowerInvariant()
}

function Get-CertMap([object]$Map,[string]$Label) {
    if ($null -eq $Map) { throw "HYPERV_VALKEY_AUTHORITY_V2_ERROR=missing certificate map: $Label" }
    $names = @($Map.PSObject.Properties.Name | Sort-Object)
    if (($names -join ',') -ne ($ExpectedCertNames -join ',')) {
        throw "HYPERV_VALKEY_AUTHORITY_V2_ERROR=unexpected certificate identities in ${Label}: $($names -join ',')"
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
    if ($rc -ne 0) { throw "HYPERV_VALKEY_AUTHORITY_V2_ERROR=qc status failed with exit code $rc" }
    if ($text -notmatch '(?m)^VM_STATE=Running\s*$') { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=QC VM is not running' }
    if ($text -notmatch '(?m)^QUEEN_CALIFIA=BLOCKED\s*$') { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=QC authorization gate is not closed' }
    if ($text -notmatch '(?mi)runtime authorization gate is closed') { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=closed authorization detail not confirmed' }
    [ordered]@{ command_exit_code=$rc; vm_running=$true; authorization_gate_closed=$true; expected_closed_detail=$true }
}

Assert-Administrator
foreach ($cmd in @('Get-VM','git','pwsh')) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        throw "HYPERV_VALKEY_AUTHORITY_V2_ERROR=required command missing: $cmd"
    }
}

$repoHead = (& git -C $RepoRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=git rev-parse failed' }
Assert-Hex40 -Value $repoHead -Label 'Windows repository head'
if (@(& git -C $RepoRoot status --porcelain).Count -gt 0) { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=Windows repository checkout must be clean' }
if ((& git -C $RepoRoot branch --show-current).Trim() -ne 'main') { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=Windows repository must be on protected main' }

$host = Get-Newest -Root $HostEvidenceRoot -Filter 'hyperv-final-host-v2-*.json' -Label 'Windows final-host'
if ($host.Record.schema -ne 'queen-califia-hyperv-final-host-evidence-v2') { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=unsupported Windows final-host schema' }
if ($host.Record.architecture -ne 'windows-physical-host-with-hyperv-ubuntu-guest') { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=unexpected Windows final-host architecture' }
if ($host.Record.automated_host_evidence_ready_for_review -ne $true) { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=Windows final-host evidence is not review-ready' }
$hostHead = [string]$host.Record.repository.head
Assert-Hex40 -Value $hostHead -Label 'Windows final-host Git head'
if ($hostHead -ne $repoHead) { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=Windows final-host evidence must be recollected at current protected main' }
$hostFingerprint = [string]$host.Record.host_identity.fingerprint_sha256
Assert-Hex64 -Value $hostFingerprint -Label 'Windows physical-host fingerprint'
$hostVmId = Normalize-Guid -Value ([string]$host.Record.hyperv.vm_id) -Label 'Windows Hyper-V VM ID'

$hostNicHashes = @(
    $host.Record.hyperv.network_adapters |
        Where-Object { $_.connected -eq $true -and $_.mac_address_sha256 } |
        ForEach-Object { ([string]$_.mac_address_sha256).ToLowerInvariant() }
)
if ($hostNicHashes.Count -lt 1) { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=no connected Hyper-V NIC hash in final-host evidence' }
foreach ($hash in $hostNicHashes) { Assert-Hex64 -Value $hash -Label 'Windows Hyper-V NIC hash' }

$pki = Get-Newest -Root $GuestEvidenceRoot -Filter 'hyperv-final-valkey-pki-*.json' -Label 'guest Hyper-V Valkey PKI'
$identity = Get-Newest -Root $GuestEvidenceRoot -Filter 'hyperv-guest-identity-*.json' -Label 'guest Hyper-V identity binding'
$runtime = Get-Newest -Root $GuestEvidenceRoot -Filter 'runtime-*.json' -Label 'guest preauthorization runtime'
$binding = Get-Newest -Root $GuestEvidenceRoot -Filter 'hyperv-runtime-binding-*.json' -Label 'guest Hyper-V runtime binding'

if ($pki.Record.schema -ne 'queen-califia-hyperv-final-valkey-pki-evidence-v1') { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=unsupported PKI schema' }
if ($identity.Record.schema -ne 'queen-califia-hyperv-guest-identity-binding-evidence-v1') { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=unsupported guest identity schema' }
if ($runtime.Record.schema -ne 'queen-califia-sovereign-edge-runtime-evidence-v2' -or $runtime.Record.mode -ne '--preauth') { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=runtime evidence must be v2 preauthorization evidence' }
if ($binding.Record.schema -ne 'queen-califia-hyperv-runtime-binding-evidence-v1') { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=unsupported runtime binding schema' }

if ($pki.Record.pki_material_verified -ne $true -or $pki.Record.repository_clean -ne $true) { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=PKI evidence is not review-ready' }
if ($runtime.Record.authorization_marker_present -ne $false -or $runtime.Record.repository_clean -ne $true) { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=runtime preauthorization boundary invalid' }
if ($binding.Record.runtime_preauthorization_claims_verified -ne $true -or $binding.Record.authorization_marker_absent_verified -ne $true) { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=runtime binding claims incomplete' }
if ($identity.Record.authorization_marker_absent_verified -ne $true) { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=guest identity binding did not prove closed authorization' }
if ($runtime.Record.running_application_containers.Count -ne 0) { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=preauthorization runtime contains application containers' }

foreach ($claim in @('no_host_ports_published','valkey_tls_verified','valkey_plaintext_refused','valkey_client_certificate_required','valkey_health_client_verified','valkey_api_client_verified','valkey_worker_client_verified','unauthorized_application_runtime_absent')) {
    if ($runtime.Record.claims.$claim -ne $true) { throw "HYPERV_VALKEY_AUTHORITY_V2_ERROR=runtime claim must be true: $claim" }
}
if ($runtime.Record.claims.authorized_runtime_probed -ne $false) { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=authorized runtime was unexpectedly probed' }

$guestFp = [string]$pki.Record.guest_host_identity_fingerprint_sha256
foreach ($entry in @(
    @('PKI guest fingerprint',$guestFp),
    @('identity guest fingerprint',[string]$identity.Record.guest_host_identity_fingerprint_sha256),
    @('runtime guest fingerprint',[string]$runtime.Record.host_identity_fingerprint_sha256),
    @('binding guest fingerprint',[string]$binding.Record.guest_host_identity_fingerprint_sha256)
)) { Assert-Hex64 -Value $entry[1] -Label $entry[0] }
if ($guestFp -ne [string]$identity.Record.guest_host_identity_fingerprint_sha256 -or $guestFp -ne [string]$runtime.Record.host_identity_fingerprint_sha256 -or $guestFp -ne [string]$binding.Record.guest_host_identity_fingerprint_sha256) {
    throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=guest fingerprints do not match across evidence'
}

foreach ($head in @([string]$pki.Record.git_head,[string]$identity.Record.git_head,[string]$runtime.Record.git_head,[string]$binding.Record.git_head)) {
    Assert-Hex40 -Value $head -Label 'guest Git head'
    if ($head -ne $repoHead) { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=Windows and guest evidence Git heads do not match protected main' }
}

$pkiDmi = ([string]$pki.Record.hyperv_guest_vm_id_raw).ToLowerInvariant()
$identityDmi = ([string]$identity.Record.guest_dmi_product_uuid).ToLowerInvariant()
$bindingDmi = ([string]$binding.Record.hyperv_guest_vm_id_raw).ToLowerInvariant()
if ($pkiDmi -ne $identityDmi -or $pkiDmi -ne $bindingDmi) { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=guest DMI UUID changed across evidence' }

$guestNicHashes = @(
    $identity.Record.network_adapters |
        Where-Object { $_.operstate -eq 'up' -and $_.mac_address_sha256 } |
        ForEach-Object { ([string]$_.mac_address_sha256).ToLowerInvariant() }
)
if ($guestNicHashes.Count -lt 1) { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=no active guest NIC hash in identity evidence' }
foreach ($hash in $guestNicHashes) { Assert-Hex64 -Value $hash -Label 'guest NIC hash' }
$sharedNicHashes = @($hostNicHashes | Where-Object { $guestNicHashes -contains $_ } | Sort-Object -Unique)
if ($sharedNicHashes.Count -ne 1) { throw "HYPERV_VALKEY_AUTHORITY_V2_ERROR=expected exactly one shared Hyper-V NIC identity hash; observed $($sharedNicHashes.Count)" }

$pkiSha = Get-FileSha256Lower $pki.Item.FullName
if ([string]$identity.Record.source_pki.sha256 -ne $pkiSha -or [string]$identity.Record.source_pki.name -ne $pki.Item.Name) {
    throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=guest identity record does not hash-bind the copied PKI evidence'
}
$runtimeSha = Get-FileSha256Lower $runtime.Item.FullName
if ([string]$binding.Record.runtime_source.sha256 -ne $runtimeSha -or [string]$binding.Record.runtime_source.name -ne $runtime.Item.Name) {
    throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=runtime binding does not hash-bind the copied runtime evidence'
}

$pkiCerts = Get-CertMap -Map $pki.Record.certificate_fingerprints_sha256 -Label 'offline PKI'
$runtimeCerts = Get-CertMap -Map $runtime.Record.valkey_certificate_fingerprints_sha256 -Label 'runtime'
$bindingCerts = Get-CertMap -Map $binding.Record.valkey_certificate_fingerprints_sha256 -Label 'runtime binding'
foreach ($name in $ExpectedCertNames) {
    if ($pkiCerts[$name] -ne $runtimeCerts[$name] -or $pkiCerts[$name] -ne $bindingCerts[$name]) {
        throw "HYPERV_VALKEY_AUTHORITY_V2_ERROR=certificate fingerprint mismatch for $name"
    }
}

$liveGate = Get-LiveClosedGateEvidence
$vm = Get-VM -Name $VmName -ErrorAction Stop
$currentVmId = Normalize-Guid -Value ([string]$vm.Id) -Label 'current Hyper-V VM ID'
if ($currentVmId -ne $hostVmId) { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=current Hyper-V VM ID differs from final-host evidence' }
if ([string]$vm.State -ne 'Running') { throw 'HYPERV_VALKEY_AUTHORITY_V2_ERROR=current Hyper-V VM is not running' }

New-Item -ItemType Directory -Path $AuthorityRoot -Force | Out-Null
$stamp = [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$output = Join-Path $AuthorityRoot "hyperv-final-valkey-authority-v2-$stamp.json"
if (Test-Path -LiteralPath $output) { throw "HYPERV_VALKEY_AUTHORITY_V2_ERROR=refusing to overwrite authority evidence: $output" }

$record = [ordered]@{
    schema = 'queen-califia-hyperv-final-valkey-authority-evidence-v2'
    bound_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    architecture = 'windows-physical-host-with-hyperv-ubuntu-guest'
    windows_physical_host_identity_fingerprint_sha256 = $hostFingerprint
    hyperv_vm_id = $hostVmId
    guest_dmi_product_uuid_informational = $pkiDmi
    guest_host_identity_fingerprint_sha256 = $guestFp
    shared_hyperv_nic_identity_sha256 = $sharedNicHashes[0]
    cross_host_binding_method = 'hyperv-nic-mac-sha256-with-trailing-nul'
    git_head = $repoHead
    valkey_certificate_fingerprints_sha256 = $pkiCerts
    source_evidence = [ordered]@{
        windows_final_host = [ordered]@{ name=$host.Item.Name; sha256=Get-FileSha256Lower $host.Item.FullName }
        guest_valkey_pki = [ordered]@{ name=$pki.Item.Name; sha256=$pkiSha }
        guest_identity_binding = [ordered]@{ name=$identity.Item.Name; sha256=Get-FileSha256Lower $identity.Item.FullName }
        guest_runtime_preauthorization = [ordered]@{ name=$runtime.Item.Name; sha256=$runtimeSha; boot_id=[string]$runtime.Record.boot_id }
        guest_runtime_binding = [ordered]@{ name=$binding.Item.Name; sha256=Get-FileSha256Lower $binding.Item.FullName }
    }
    live_guest_control_boundary = $liveGate
    same_hyperv_vm_network_identity = $true
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
Write-Host 'HYPERV_FINAL_VALKEY_AUTHORITY_V2_EVIDENCE=PASS'
Write-Host 'HYPERV_FINAL_VALKEY_PKI_GENERATED=ELIGIBLE_FOR_HUMAN_REVIEW'
Write-Host 'HYPERV_FINAL_VALKEY_AUTHORITY_VERIFIED=ELIGIBLE_FOR_HUMAN_REVIEW'
Write-Host "HYPERV_FINAL_VALKEY_AUTHORITY_V2_EVIDENCE_PATH=$output"
Write-Host "HYPERV_FINAL_VALKEY_AUTHORITY_V2_EVIDENCE_SHA256=$sha"
Write-Host "HYPERV_FINAL_VALKEY_VM_ID=$hostVmId"
Write-Host 'HYPERV_FINAL_VALKEY_CROSS_HOST_BINDING=NIC_HASH'
Write-Host 'HYPERV_FINAL_VALKEY_LEDGER_UPDATED=NO'
Write-Host 'HYPERV_FINAL_VALKEY_AUTHORIZATION_UPDATED=NO'
