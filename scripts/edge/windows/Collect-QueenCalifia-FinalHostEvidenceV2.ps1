#requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$VmName = 'QueenCalifia-Sovereign-Edge-HyperV'
$EvidenceRoot = Join-Path $env:ProgramData 'QueenCalifia\evidence\hyperv-final-host'
$QcControl = Join-Path $PSScriptRoot 'qc.ps1'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$ProhibitedPorts = @(80,443,5432,6379)

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'FINAL_HOST_EVIDENCE_ERROR=run PowerShell 7 as Administrator'
    }
}

function Get-Sha256Text {
    param([Parameter(Mandatory)][string[]]$Parts)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $stream = [IO.MemoryStream]::new()
        try {
            foreach ($part in $Parts) {
                $bytes = [Text.Encoding]::UTF8.GetBytes($part)
                $stream.Write($bytes,0,$bytes.Length)
                $stream.WriteByte(0)
            }
            $stream.Position = 0
            ([Convert]::ToHexString($sha.ComputeHash($stream))).ToLowerInvariant()
        }
        finally { $stream.Dispose() }
    }
    finally { $sha.Dispose() }
}

function Get-HostIdentityEvidence {
    $parts = [Collections.Generic.List[string]]::new()
    $kinds = [Collections.Generic.List[string]]::new()
    [void]$parts.Add($env:COMPUTERNAME); [void]$kinds.Add('computer-name')
    $product = Get-CimInstance Win32_ComputerSystemProduct
    if ($product.UUID) { [void]$parts.Add([string]$product.UUID); [void]$kinds.Add('computer-system-product-uuid') }
    $bios = Get-CimInstance Win32_BIOS
    if ($bios.SerialNumber) { [void]$parts.Add([string]$bios.SerialNumber); [void]$kinds.Add('bios-serial') }
    $board = Get-CimInstance Win32_BaseBoard
    if ($board.SerialNumber) { [void]$parts.Add([string]$board.SerialNumber); [void]$kinds.Add('baseboard-serial') }
    [pscustomobject]@{
        fingerprint_sha256 = Get-Sha256Text -Parts @($parts)
        source_kinds = @($kinds)
        raw_identifiers_included = $false
    }
}

function Get-PhysicalHostEvidence {
    $system = Get-CimInstance Win32_ComputerSystem
    $combined = "$($system.Manufacturer) $($system.Model)"
    $virtualPattern = '(?i)(VMware|VirtualBox|Virtual Machine|KVM|QEMU|Xen|Parallels|Bochs)'
    [pscustomobject]@{
        manufacturer = [string]$system.Manufacturer
        model = [string]$system.Model
        hypervisor_present = [bool]$system.HypervisorPresent
        known_virtual_machine_signature = [bool]($combined -match $virtualPattern)
        physical_host_candidate = -not [bool]($combined -match $virtualPattern)
    }
}

function Resolve-DriveRoot([string]$Path) {
    if ($Path -match '^[A-Za-z]:$') { return $Path }
    $root = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Path))
    if (-not $root) { throw "Unable to resolve drive root for $Path" }
    $root.TrimEnd('\')
}

function Get-BitLockerEvidence([string]$DriveRoot) {
    $volume = Get-BitLockerVolume -MountPoint $DriveRoot
    [pscustomobject]@{
        mount_point = [string]$volume.MountPoint
        volume_status = [string]$volume.VolumeStatus
        protection_status = [string]$volume.ProtectionStatus
        encryption_method = [string]$volume.EncryptionMethod
        encrypted = ([string]$volume.VolumeStatus -eq 'FullyEncrypted')
        protection_on = ([string]$volume.ProtectionStatus -eq 'On')
    }
}

function Get-StorageEvidence($Vm) {
    $paths = [Collections.Generic.List[string]]::new()
    [void]$paths.Add($env:SystemDrive)
    foreach ($candidate in @($Vm.ConfigurationLocation,$Vm.SnapshotFileLocation,$Vm.SmartPagingFilePath)) {
        if ($candidate) { [void]$paths.Add([string]$candidate) }
    }
    foreach ($disk in @(Get-VMHardDiskDrive -VMName $VmName)) {
        if ($disk.Path) { [void]$paths.Add([string]$disk.Path) }
    }
    [void]$paths.Add($HOME)
    $drives = @($paths | ForEach-Object { Resolve-DriveRoot $_ } | Sort-Object -Unique)
    $volumes = @($drives | ForEach-Object { Get-BitLockerEvidence $_ })
    [pscustomobject]@{
        protected_drive_roots = $drives
        volumes = $volumes
        all_required_volumes_fully_encrypted = (@($volumes | Where-Object { -not $_.encrypted }).Count -eq 0)
        all_required_volumes_protection_on = (@($volumes | Where-Object { -not $_.protection_on }).Count -eq 0)
    }
}

function Get-TpmSecureBootEvidence {
    $tpm = Get-Tpm
    $secureBoot = $false
    try { $secureBoot = [bool](Confirm-SecureBootUEFI) } catch { $secureBoot = $false }
    [pscustomobject]@{
        tpm_present = [bool]$tpm.TpmPresent
        tpm_ready = [bool]$tpm.TpmReady
        tpm_enabled = [bool]$tpm.TpmEnabled
        tpm_activated = [bool]$tpm.TpmActivated
        tpm_auto_provisioning = [string]$tpm.AutoProvisioning
        secure_boot = $secureBoot
    }
}

function Get-WindowsIsolationEvidence {
    $vbs = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard
    $lsa = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $runAsPpl = if ($null -ne $lsa.RunAsPPL) { [int]$lsa.RunAsPPL } else { 0 }
    $runAsPplBoot = if ($null -ne $lsa.RunAsPPLBoot) { [int]$lsa.RunAsPPLBoot } else { 0 }
    [pscustomobject]@{
        virtualization_based_security_status = [int]$vbs.VirtualizationBasedSecurityStatus
        security_services_running = @($vbs.SecurityServicesRunning)
        run_as_ppl = $runAsPpl
        run_as_ppl_boot = $runAsPplBoot
        vbs_running = ([int]$vbs.VirtualizationBasedSecurityStatus -eq 2)
        lsa_protection_enabled = ($runAsPpl -ge 1)
    }
}

function Get-FirewallEvidence {
    $rows = @(Get-NetFirewallProfile | Sort-Object Name | ForEach-Object {
        [pscustomobject]@{
            name = [string]$_.Name
            enabled = [bool]$_.Enabled
            default_inbound_action = [string]$_.DefaultInboundAction
            default_outbound_action = [string]$_.DefaultOutboundAction
        }
    })
    [pscustomobject]@{
        profiles = $rows
        all_profiles_enabled = (@($rows | Where-Object { -not $_.enabled }).Count -eq 0)
        all_profiles_default_block_inbound = (@($rows | Where-Object { $_.default_inbound_action -ne 'Block' }).Count -eq 0)
    }
}

function Get-ListenerEvidence {
    $observed = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object)
    $prohibited = @($observed | Where-Object { $_ -in $ProhibitedPorts })
    [pscustomobject]@{
        observed_tcp_listener_count = $observed.Count
        prohibited_ports = $prohibited
        prohibited_ports_absent = ($prohibited.Count -eq 0)
    }
}

function Get-HyperVEvidence {
    $vm = Get-VM -Name $VmName -ErrorAction Stop
    $generation = [int]$vm.Generation
    $firmwareMode = if ($generation -eq 2) { 'uefi' } else { 'legacy-bios' }
    $guestSecureBootSupported = ($generation -eq 2)
    $guestVtpmSupported = ($generation -eq 2)
    $guestSecureBoot = $null
    $guestVtpm = $null
    $secureBootTemplate = $null
    $biosState = $null

    if ($generation -eq 2) {
        $firmware = Get-VMFirmware -VMName $VmName -ErrorAction Stop
        $security = Get-VMSecurity -VMName $VmName -ErrorAction Stop
        $guestSecureBoot = ([string]$firmware.SecureBoot -eq 'On')
        $secureBootTemplate = [string]$firmware.SecureBootTemplate
        $guestVtpm = [bool]$security.TpmEnabled
    }
    elseif ($generation -eq 1) {
        $bios = Get-VMBios -VMName $VmName -ErrorAction Stop
        $biosState = [pscustomobject]@{
            startup_order = @($bios.StartupOrder | ForEach-Object { [string]$_ })
            num_lock_enabled = [bool]$bios.NumLockEnabled
        }
    }
    else {
        throw "Unsupported Hyper-V VM generation: $generation"
    }

    $network = @(Get-VMNetworkAdapter -VMName $VmName | ForEach-Object {
        [pscustomobject]@{
            switch_name = [string]$_.SwitchName
            connected = [bool]$_.Connected
            mac_address_sha256 = if ($_.MacAddress) { Get-Sha256Text -Parts @([string]$_.MacAddress) } else { $null }
        }
    })
    $disks = @(Get-VMHardDiskDrive -VMName $VmName | ForEach-Object {
        [pscustomobject]@{
            controller_type = [string]$_.ControllerType
            controller_number = [int]$_.ControllerNumber
            controller_location = [int]$_.ControllerLocation
            path_sha256 = if ($_.Path) { Get-Sha256Text -Parts @([string]$_.Path) } else { $null }
            extension = if ($_.Path) { [IO.Path]::GetExtension([string]$_.Path).ToLowerInvariant() } else { $null }
        }
    })

    [pscustomobject]@{
        vm_name = $VmName
        vm_id = [string]$vm.Id
        state = [string]$vm.State
        generation = $generation
        version = [string]$vm.Version
        firmware_mode = $firmwareMode
        automatic_start_action = [string]$vm.AutomaticStartAction
        automatic_stop_action = [string]$vm.AutomaticStopAction
        guest_secure_boot_supported = $guestSecureBootSupported
        guest_secure_boot = $guestSecureBoot
        guest_secure_boot_template = $secureBootTemplate
        guest_virtual_tpm_supported = $guestVtpmSupported
        guest_virtual_tpm_enabled = $guestVtpm
        generation1_bios = $biosState
        network_adapters = $network
        virtual_disks = $disks
        expected_vm_identity = ($vm.Name -eq $VmName -and $generation -in @(1,2))
        generation_supported_by_qc = ($generation -in @(1,2))
        restart_after_host_boot_configured = ([string]$vm.AutomaticStartAction -ne 'Nothing')
    }
}

function Get-RepositoryEvidence {
    Push-Location $RepoRoot
    try {
        $head = (& git rev-parse HEAD).Trim(); if ($LASTEXITCODE -ne 0) { throw 'git rev-parse failed' }
        $branch = (& git branch --show-current).Trim(); if ($LASTEXITCODE -ne 0) { throw 'git branch failed' }
        $dirty = @(& git status --porcelain); if ($LASTEXITCODE -ne 0) { throw 'git status failed' }
        [pscustomobject]@{
            repository = 'HeruAhmose/QueenCalifia-CyberAI'
            head = $head
            branch = $branch
            clean = ($dirty.Count -eq 0)
            protected_main_expected = ($branch -eq 'main')
        }
    }
    finally { Pop-Location }
}

function Get-GuestGateEvidence {
    $output = & pwsh -NoLogo -NoProfile -File $QcControl status -Hypervisor hyperv -VmName $VmName 2>&1
    $rc = $LASTEXITCODE
    $text = (@($output | ForEach-Object { $_.ToString() }) -join "`n")
    [pscustomobject]@{
        command_exit_code = $rc
        control_plane_status_sha256 = Get-Sha256Text -Parts @($text)
        raw_control_output_included = $false
        vm_running = ($text -match '(?m)^VM_STATE=Running\s*$')
        authorization_gate_closed = ($text -match '(?m)^QUEEN_CALIFIA=BLOCKED\s*$')
        expected_closed_detail = ($text -match '(?mi)runtime authorization gate is closed')
    }
}

Assert-Administrator
foreach ($cmd in @('Get-VM','Get-BitLockerVolume','pwsh')) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "FINAL_HOST_EVIDENCE_ERROR=required command missing: $cmd" }
}

$vm = Get-VM -Name $VmName -ErrorAction Stop
$hostIdentity = Get-HostIdentityEvidence
$physical = Get-PhysicalHostEvidence
$hyperv = Get-HyperVEvidence
$storage = Get-StorageEvidence $vm
$tpmSecureBoot = Get-TpmSecureBootEvidence
$isolation = Get-WindowsIsolationEvidence
$firewall = Get-FirewallEvidence
$listeners = Get-ListenerEvidence
$repository = Get-RepositoryEvidence
$guestGate = Get-GuestGateEvidence

$automatedReady = @(
    $physical.physical_host_candidate,
    $storage.all_required_volumes_fully_encrypted,
    $storage.all_required_volumes_protection_on,
    $tpmSecureBoot.tpm_present,
    $tpmSecureBoot.tpm_ready,
    $tpmSecureBoot.tpm_enabled,
    $tpmSecureBoot.tpm_activated,
    $tpmSecureBoot.secure_boot,
    $isolation.vbs_running,
    $isolation.lsa_protection_enabled,
    $firewall.all_profiles_enabled,
    $firewall.all_profiles_default_block_inbound,
    $listeners.prohibited_ports_absent,
    $hyperv.expected_vm_identity,
    $hyperv.generation_supported_by_qc,
    $hyperv.restart_after_host_boot_configured,
    $repository.clean,
    $repository.protected_main_expected,
    $guestGate.vm_running,
    $guestGate.authorization_gate_closed,
    $guestGate.expected_closed_detail
) -notcontains $false

$record = [ordered]@{
    schema = 'queen-califia-hyperv-final-host-evidence-v2'
    collected_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    architecture = 'windows-physical-host-with-hyperv-ubuntu-guest'
    host_identity = $hostIdentity
    physical_host = $physical
    storage = $storage
    tpm_secure_boot = $tpmSecureBoot
    windows_isolation = $isolation
    firewall = $firewall
    listeners = $listeners
    hyperv = $hyperv
    repository = $repository
    guest_control_boundary = $guestGate
    manual_controls = [ordered]@{
        bios_restore_after_power_loss = [ordered]@{ verified = $false; status = 'manual-physical-evidence-required' }
        ups = [ordered]@{ verified = $false; status = 'manual-physical-evidence-required' }
    }
    automated_host_evidence_ready_for_review = [bool]$automatedReady
    physical_truth_automatically_verified = $false
    human_review_required = $true
    automatic_ledger_promotion = $false
    deployment_ledger_modified = $false
    authorization_modified = $false
}

New-Item -ItemType Directory -Path $EvidenceRoot -Force | Out-Null
$stamp = [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$outputPath = Join-Path $EvidenceRoot "hyperv-final-host-v2-$stamp.json"
if (Test-Path -LiteralPath $outputPath) { throw "FINAL_HOST_EVIDENCE_ERROR=refusing to overwrite evidence: $outputPath" }
$json = $record | ConvertTo-Json -Depth 12
[IO.File]::WriteAllText($outputPath,$json + [Environment]::NewLine,[Text.UTF8Encoding]::new($false))
$hash = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant()

Write-Host ('HYPERV_FINAL_HOST_EVIDENCE=' + $(if ($automatedReady) {'PASS'} else {'BLOCKED'})) -ForegroundColor $(if ($automatedReady) {'Green'} else {'Yellow'})
Write-Host "HYPERV_FINAL_HOST_EVIDENCE_SCHEMA=queen-califia-hyperv-final-host-evidence-v2"
Write-Host "HYPERV_FINAL_HOST_EVIDENCE_PATH=$outputPath"
Write-Host "HYPERV_FINAL_HOST_EVIDENCE_SHA256=$hash"
Write-Host "HYPERV_FINAL_HOST_VM_ID=$($hyperv.vm_id)"
Write-Host "HYPERV_FINAL_HOST_VM_GENERATION=$($hyperv.generation)"
Write-Host "HYPERV_FINAL_HOST_GUEST_SECURE_BOOT_SUPPORTED=$($hyperv.guest_secure_boot_supported)"
Write-Host "HYPERV_FINAL_HOST_GIT_HEAD=$($repository.head)"
Write-Host 'HYPERV_FINAL_HOST_MANUAL_CONTROLS=BIOS_AND_UPS_REQUIRED'
Write-Host 'HYPERV_FINAL_HOST_LEDGER_UPDATED=NO'
Write-Host 'HYPERV_FINAL_HOST_AUTHORIZATION_UPDATED=NO'
