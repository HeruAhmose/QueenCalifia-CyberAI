#requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$VmName = 'QueenCalifia-Sovereign-Edge-HyperV'
$EvidenceRoot = Join-Path $env:ProgramData 'QueenCalifia\evidence\hyperv-final-host'
$QcControl = Join-Path $PSScriptRoot 'qc.ps1'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$ProhibitedPorts = @(80, 443, 5432, 6379)

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
                $stream.Write($bytes, 0, $bytes.Length)
                $stream.WriteByte(0)
            }
            $stream.Position = 0
            return ([Convert]::ToHexString($sha.ComputeHash($stream))).ToLowerInvariant()
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        $sha.Dispose()
    }
}

function Get-HostIdentityEvidence {
    $parts = [Collections.Generic.List[string]]::new()
    $kinds = [Collections.Generic.List[string]]::new()

    [void]$parts.Add($env:COMPUTERNAME)
    [void]$kinds.Add('computer-name')

    $computerProduct = Get-CimInstance -ClassName Win32_ComputerSystemProduct
    if ($computerProduct.UUID) {
        [void]$parts.Add([string]$computerProduct.UUID)
        [void]$kinds.Add('computer-system-product-uuid')
    }

    $bios = Get-CimInstance -ClassName Win32_BIOS
    if ($bios.SerialNumber) {
        [void]$parts.Add([string]$bios.SerialNumber)
        [void]$kinds.Add('bios-serial')
    }

    $board = Get-CimInstance -ClassName Win32_BaseBoard
    if ($board.SerialNumber) {
        [void]$parts.Add([string]$board.SerialNumber)
        [void]$kinds.Add('baseboard-serial')
    }

    [pscustomobject]@{
        fingerprint_sha256 = Get-Sha256Text -Parts @($parts)
        source_kinds = @($kinds)
        raw_identifiers_included = $false
    }
}

function Get-PhysicalHostEvidence {
    $system = Get-CimInstance -ClassName Win32_ComputerSystem
    $manufacturer = [string]$system.Manufacturer
    $model = [string]$system.Model
    $combined = "$manufacturer $model"
    $virtualPattern = '(?i)(VMware|VirtualBox|Virtual Machine|KVM|QEMU|Xen|Parallels|Bochs)'

    [pscustomobject]@{
        manufacturer = $manufacturer
        model = $model
        hypervisor_present = [bool]$system.HypervisorPresent
        known_virtual_machine_signature = [bool]($combined -match $virtualPattern)
        physical_host_candidate = -not [bool]($combined -match $virtualPattern)
    }
}

function Get-BitLockerEvidenceForDrive {
    param([Parameter(Mandatory)][string]$DriveRoot)

    $volume = Get-BitLockerVolume -MountPoint $DriveRoot
    [pscustomobject]@{
        mount_point = $volume.MountPoint
        volume_status = [string]$volume.VolumeStatus
        protection_status = [string]$volume.ProtectionStatus
        encryption_method = [string]$volume.EncryptionMethod
        encrypted = ([string]$volume.VolumeStatus -eq 'FullyEncrypted')
        protection_on = ([string]$volume.ProtectionStatus -eq 'On')
    }
}

function Get-DriveRootFromPath {
    param([Parameter(Mandatory)][string]$Path)
    $resolved = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($resolved)
    if (-not $root) { throw "Unable to resolve drive root for $Path" }
    return $root.TrimEnd('\')
}

function Get-StorageEvidence {
    param([Parameter(Mandatory)]$Vm)

    $paths = [Collections.Generic.List[string]]::new()
    [void]$paths.Add($env:SystemDrive)

    foreach ($candidate in @($Vm.ConfigurationLocation, $Vm.SnapshotFileLocation, $Vm.SmartPagingFilePath)) {
        if ($candidate) { [void]$paths.Add([string]$candidate) }
    }

    foreach ($disk in @(Get-VMHardDiskDrive -VMName $VmName)) {
        if ($disk.Path) { [void]$paths.Add([string]$disk.Path) }
    }

    if (Test-Path -LiteralPath $HOME) { [void]$paths.Add($HOME) }

    $drives = @(
        $paths |
            ForEach-Object {
                if ($_ -match '^[A-Za-z]:$') { $_ } else { Get-DriveRootFromPath -Path $_ }
            } |
            Sort-Object -Unique
    )

    $evidence = @($drives | ForEach-Object { Get-BitLockerEvidenceForDrive -DriveRoot $_ })
    [pscustomobject]@{
        protected_drive_roots = $drives
        volumes = $evidence
        all_required_volumes_fully_encrypted = (@($evidence | Where-Object { -not $_.encrypted }).Count -eq 0)
        all_required_volumes_protection_on = (@($evidence | Where-Object { -not $_.protection_on }).Count -eq 0)
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

    [pscustomobject]@{
        virtualization_based_security_status = [int]$vbs.VirtualizationBasedSecurityStatus
        security_services_running = @($vbs.SecurityServicesRunning)
        run_as_ppl = [int]($lsa.RunAsPPL ?? 0)
        run_as_ppl_boot = [int]($lsa.RunAsPPLBoot ?? 0)
        vbs_running = ([int]$vbs.VirtualizationBasedSecurityStatus -eq 2)
        lsa_protection_enabled = ([int]($lsa.RunAsPPL ?? 0) -ge 1)
    }
}

function Get-FirewallEvidence {
    $profiles = @(Get-NetFirewallProfile | Sort-Object Name)
    $rows = @(
        $profiles | ForEach-Object {
            [pscustomobject]@{
                name = [string]$_.Name
                enabled = [bool]$_.Enabled
                default_inbound_action = [string]$_.DefaultInboundAction
                default_outbound_action = [string]$_.DefaultOutboundAction
            }
        }
    )

    [pscustomobject]@{
        profiles = $rows
        all_profiles_enabled = (@($rows | Where-Object { -not $_.enabled }).Count -eq 0)
        all_profiles_default_block_inbound = (@($rows | Where-Object { $_.default_inbound_action -ne 'Block' }).Count -eq 0)
    }
}

function Get-ListenerEvidence {
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)
    $observed = @($listeners | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object)
    $prohibited = @($observed | Where-Object { $_ -in $ProhibitedPorts })

    [pscustomobject]@{
        observed_tcp_listener_count = @($observed).Count
        prohibited_ports = $prohibited
        prohibited_ports_absent = (@($prohibited).Count -eq 0)
    }
}

function Get-HyperVEvidence {
    $vm = Get-VM -Name $VmName -ErrorAction Stop
    $firmware = Get-VMFirmware -VMName $VmName -ErrorAction Stop
    $security = Get-VMSecurity -VMName $VmName -ErrorAction Stop
    $switches = @(
        Get-VMNetworkAdapter -VMName $VmName |
            ForEach-Object {
                [pscustomobject]@{
                    switch_name = [string]$_.SwitchName
                    connected = [bool]$_.Connected
                    mac_address_sha256 = if ($_.MacAddress) { Get-Sha256Text -Parts @([string]$_.MacAddress) } else { $null }
                }
            }
    )
    $disks = @(
        Get-VMHardDiskDrive -VMName $VmName |
            ForEach-Object {
                [pscustomobject]@{
                    controller_type = [string]$_.ControllerType
                    controller_number = [int]$_.ControllerNumber
                    controller_location = [int]$_.ControllerLocation
                    path_sha256 = if ($_.Path) { Get-Sha256Text -Parts @([string]$_.Path) } else { $null }
                    extension = if ($_.Path) { [IO.Path]::GetExtension([string]$_.Path).ToLowerInvariant() } else { $null }
                }
            }
    )

    [pscustomobject]@{
        vm_name = $VmName
        vm_id = [string]$vm.Id
        state = [string]$vm.State
        generation = [int]$vm.Generation
        version = [string]$vm.Version
        automatic_start_action = [string]$vm.AutomaticStartAction
        automatic_stop_action = [string]$vm.AutomaticStopAction
        secure_boot = ([string]$firmware.SecureBoot -eq 'On')
        secure_boot_template = [string]$firmware.SecureBootTemplate
        virtual_tpm_enabled = [bool]$security.TpmEnabled
        network_adapters = $switches
        virtual_disks = $disks
        expected_vm_identity = ($vm.Name -eq $VmName -and [int]$vm.Generation -eq 2)
        restart_after_host_boot_configured = ([string]$vm.AutomaticStartAction -ne 'Nothing')
    }
}

function Get-RepositoryEvidence {
    Push-Location $RepoRoot
    try {
        $head = (& git rev-parse HEAD).Trim()
        if ($LASTEXITCODE -ne 0) { throw 'git rev-parse failed' }
        $branch = (& git branch --show-current).Trim()
        if ($LASTEXITCODE -ne 0) { throw 'git branch failed' }
        $dirty = (& git status --porcelain)
        if ($LASTEXITCODE -ne 0) { throw 'git status failed' }
        [pscustomobject]@{
            repository = 'HeruAhmose/QueenCalifia-CyberAI'
            head = $head
            branch = $branch
            clean = (@($dirty).Count -eq 0)
            protected_main_expected = ($branch -eq 'main')
        }
    }
    finally {
        Pop-Location
    }
}

function Get-GuestGateEvidence {
    if (-not (Test-Path -LiteralPath $QcControl)) {
        throw "Missing QC control script: $QcControl"
    }

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

if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
    throw 'FINAL_HOST_EVIDENCE_ERROR=Hyper-V PowerShell module is required'
}
if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
    throw 'FINAL_HOST_EVIDENCE_ERROR=BitLocker PowerShell module is required'
}
if (-not (Get-Command pwsh -ErrorAction SilentlyContinue)) {
    throw 'FINAL_HOST_EVIDENCE_ERROR=PowerShell 7 executable is required'
}

$hostIdentity = Get-HostIdentityEvidence
$physical = Get-PhysicalHostEvidence
$hyperv = Get-HyperVEvidence
$storage = Get-StorageEvidence -Vm (Get-VM -Name $VmName -ErrorAction Stop)
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
    $hyperv.secure_boot,
    $hyperv.restart_after_host_boot_configured,
    $repository.clean,
    $repository.protected_main_expected,
    $guestGate.vm_running,
    $guestGate.authorization_gate_closed,
    $guestGate.expected_closed_detail
) -notcontains $false

$record = [ordered]@{
    schema = 'queen-califia-hyperv-final-host-evidence-v1'
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
        bios_restore_after_power_loss = [ordered]@{
            verified = $false
            status = 'manual-physical-evidence-required'
        }
        ups = [ordered]@{
            verified = $false
            status = 'manual-physical-evidence-required'
        }
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
$outputPath = Join-Path $EvidenceRoot "hyperv-final-host-$stamp.json"
if (Test-Path -LiteralPath $outputPath) {
    throw "FINAL_HOST_EVIDENCE_ERROR=refusing to overwrite existing evidence: $outputPath"
}

$json = $record | ConvertTo-Json -Depth 12
[IO.File]::WriteAllText($outputPath, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
$hash = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant()

Write-Host ('HYPERV_FINAL_HOST_EVIDENCE=' + $(if ($automatedReady) { 'PASS' } else { 'BLOCKED' })) -ForegroundColor $(if ($automatedReady) { 'Green' } else { 'Yellow' })
Write-Host "HYPERV_FINAL_HOST_EVIDENCE_PATH=$outputPath"
Write-Host "HYPERV_FINAL_HOST_EVIDENCE_SHA256=$hash"
Write-Host "HYPERV_FINAL_HOST_VM_ID=$($hyperv.vm_id)"
Write-Host "HYPERV_FINAL_HOST_GIT_HEAD=$($repository.head)"
Write-Host 'HYPERV_FINAL_HOST_MANUAL_CONTROLS=BIOS_AND_UPS_REQUIRED'
Write-Host 'HYPERV_FINAL_HOST_LEDGER_UPDATED=NO'
Write-Host 'HYPERV_FINAL_HOST_AUTHORIZATION_UPDATED=NO'
