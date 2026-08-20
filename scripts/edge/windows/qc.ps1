#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('activate', 'status', 'stop', 'restart')]
    [string]$Action = 'activate',

    [ValidateSet('auto', 'hyperv', 'virtualbox')]
    [string]$Hypervisor = 'auto',

    [string]$VmName = '',
    [string]$GuestUser = 'qcadmin',
    [string]$HyperVKeyPath = (Join-Path $HOME '.ssh\queen-califia-hyperv-control'),

    [ValidateSet('gui', 'separate')]
    [string]$Frontend = 'gui',

    [ValidateRange(30, 900)]
    [int]$GuestAdditionsTimeoutSeconds = 180,

    [ValidateRange(30, 1800)]
    [int]$ReadyTimeoutSeconds = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-QC {
    param([string]$Message, [ConsoleColor]$Color = [ConsoleColor]::Gray)
    Write-Host $Message -ForegroundColor $Color
}

function Resolve-Hypervisor {
    if ($Hypervisor -ne 'auto') { return $Hypervisor }

    if (Get-Command Get-VM -ErrorAction SilentlyContinue) {
        $candidate = if ($VmName) { $VmName } else { 'QueenCalifia-Sovereign-Edge-HyperV' }
        if (Get-VM -Name $candidate -ErrorAction SilentlyContinue) { return 'hyperv' }
    }

    if (Get-Command VBoxManage.exe -ErrorAction SilentlyContinue) { return 'virtualbox' }
    throw 'Neither the Queen Califia Hyper-V VM nor VBoxManage.exe could be resolved.'
}

$script:ResolvedHypervisor = Resolve-Hypervisor
if (-not $VmName) {
    $VmName = if ($script:ResolvedHypervisor -eq 'hyperv') {
        'QueenCalifia-Sovereign-Edge-HyperV'
    } else {
        'QueenCalifia-Sovereign-Edge'
    }
}

function Get-HyperVIP {
    $adapter = Get-VMNetworkAdapter -VMName $VmName | Select-Object -First 1
    foreach ($candidate in @($adapter.IPAddresses)) {
        if ($candidate -match '^\d{1,3}(\.\d{1,3}){3}$' -and -not $candidate.StartsWith('169.254.')) {
            return $candidate
        }
    }

    $mac = ($adapter.MacAddress -replace '(.{2})(?!$)', '$1-').ToUpperInvariant()
    $neighbor = Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object {
        $_.LinkLayerAddress -and
        $_.LinkLayerAddress.ToUpperInvariant() -eq $mac -and
        $_.IPAddress -match '^\d{1,3}(\.\d{1,3}){3}$'
    } | Select-Object -First 1

    if ($neighbor) { return $neighbor.IPAddress }
    return $null
}

function Ensure-HyperVRunning {
    $vm = Get-VM -Name $VmName -ErrorAction Stop
    Write-QC "VM_STATE=$($vm.State)" Cyan
    switch ($vm.State.ToString()) {
        'Running' { return }
        'Off' {
            Start-VM -Name $VmName | Out-Null
            Write-QC 'VM_START=PASS (Hyper-V)' Green
            return
        }
        default { throw "Hyper-V VM '$VmName' is in unsupported state '$($vm.State)'." }
    }
}

function Wait-HyperVSSH {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($ReadyTimeoutSeconds)
    do {
        $ip = Get-HyperVIP
        if ($ip -and (Test-NetConnection -ComputerName $ip -Port 22 -InformationLevel Quiet -WarningAction SilentlyContinue)) {
            return $ip
        }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "Timed out waiting for SSH on Hyper-V VM '$VmName'."
}

function Invoke-HyperVControl {
    param([Parameter(Mandatory)][ValidateSet('ACTIVATE', 'STATUS', 'STOP', 'RESTART')][string]$Verb)

    if (-not (Get-Command ssh.exe -ErrorAction SilentlyContinue)) {
        throw 'Windows OpenSSH client is required for Hyper-V host control.'
    }
    if (-not (Test-Path -LiteralPath $HyperVKeyPath)) {
        throw "Hyper-V control key is not enrolled. Run scripts/edge/windows/Initialize-QueenCalifia-HyperV.ps1 once."
    }

    $ip = Wait-HyperVSSH
    $knownHosts = "$HyperVKeyPath.known_hosts"
    $sshArgs = @('-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o',"IdentityFile=$HyperVKeyPath",'-o','StrictHostKeyChecking=accept-new','-o',"UserKnownHostsFile=$knownHosts",'-o','ConnectTimeout=5',"$GuestUser@$ip",$Verb)
    $output = & ssh.exe @sshArgs 2>&1
    $rc = $LASTEXITCODE
    $text = ($output | ForEach-Object { $_.ToString() }) -join "`n"

    if ($text) {
        foreach ($line in ($text -split "`n")) {
            $color = if ($line -match 'READY|STOPPED|PASS') { 'Green' } elseif ($line -match 'BLOCKED|FAILED') { 'Red' } else { 'Cyan' }
            Write-QC $line $color
        }
    }
    if ($rc -eq 78 -and $Verb -eq 'STATUS') { return }
    if ($rc -eq 78) { throw 'QC activation is fail-closed: runtime authorization gate is closed.' }
    if ($rc -ne 0) { throw "Hyper-V guest control failed (ExitCode=$rc): $text" }
}

function Get-VBoxManagePath {
    $fromPath = Get-Command 'VBoxManage.exe' -ErrorAction SilentlyContinue
    if ($fromPath) { return $fromPath.Source }

    if (${env:ProgramFiles}) {
        $candidate = Join-Path ${env:ProgramFiles} 'Oracle\VirtualBox\VBoxManage.exe'
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    throw 'VBoxManage.exe was not found.'
}

function Invoke-VBox {
    param([Parameter(Mandatory)][string[]]$Arguments, [switch]$AllowFailure)
    $output = & $script:VBoxManage @Arguments 2>&1
    $code = $LASTEXITCODE
    $text = ($output | ForEach-Object { $_.ToString() }) -join "`n"
    if (-not $AllowFailure -and $code -ne 0) { throw "VBoxManage failed (ExitCode=$code): $text" }
    [pscustomobject]@{ ExitCode = $code; Output = $text }
}

function Get-VBoxState {
    $result = Invoke-VBox -Arguments @('showvminfo', $VmName, '--machinereadable')
    $match = [regex]::Match($result.Output, '(?m)^VMState="([^"]+)"\r?$')
    if (-not $match.Success) { throw "Unable to determine VirtualBox state for '$VmName'." }
    return $match.Groups[1].Value
}

function Get-GuestProperty {
    param([Parameter(Mandatory)][string]$Name)
    $result = Invoke-VBox -Arguments @('guestproperty', 'get', $VmName, $Name) -AllowFailure
    if ($result.ExitCode -ne 0 -or $result.Output -match 'No value set!') { return $null }
    $match = [regex]::Match($result.Output, '(?m)^Value:\s?(.*)\r?$')
    if ($match.Success) { return $match.Groups[1].Value.Trim() }
    return $null
}

function Ensure-VBoxRunning {
    $state = Get-VBoxState
    Write-QC "VM_STATE=$state" Cyan
    switch ($state) {
        'running' { return }
        'paused' { Invoke-VBox -Arguments @('controlvm', $VmName, 'resume') | Out-Null; return }
        'poweroff' { Invoke-VBox -Arguments @('startvm', "--type=$Frontend", $VmName) | Out-Null; Write-QC 'VM_START=PASS (VirtualBox)' Green; return }
        'saved' { Invoke-VBox -Arguments @('startvm', "--type=$Frontend", $VmName) | Out-Null; return }
        'aborted' { Invoke-VBox -Arguments @('startvm', "--type=$Frontend", $VmName) | Out-Null; return }
        default { throw "Unsupported VirtualBox state '$state'." }
    }
}

function Wait-GuestAdditions {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($GuestAdditionsTimeoutSeconds)
    do {
        $version = Get-GuestProperty -Name '/VirtualBox/GuestAdd/Version'
        if ($version) { Write-QC "GUEST_ADDITIONS=PASS ($version)" Green; return }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw 'Guest Additions did not become ready.'
}

function Invoke-VBoxControl {
    param(
        [ValidateSet('ACTIVATE', 'STOP', 'RESTART')][string]$Verb,
        [ValidateSet('READY', 'STOPPED')][string]$Target
    )
    $nonce = [guid]::NewGuid().ToString()
    $payload = "$Verb|$nonce"
    Invoke-VBox -Arguments @('guestproperty', 'set', $VmName, '/QueenCalifia/SovereignEdge/Command', $payload, '--flags', 'TRANSRESET,RDONLYGUEST') | Out-Null
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($ReadyTimeoutSeconds)
    do {
        $state = Get-GuestProperty -Name '/QueenCalifia/SovereignEdge/State'
        $detail = Get-GuestProperty -Name '/QueenCalifia/SovereignEdge/Detail'
        $ack = Get-GuestProperty -Name '/QueenCalifia/SovereignEdge/CommandAck'
        if ($state -eq $Target) { Write-QC "QUEEN_CALIFIA=$Target" Green; return }
        if ($ack -and $ack.StartsWith("$payload|")) {
            $rc = [int]($ack.Split('|')[-1])
            if ($rc -eq 78) { throw "QC activation is fail-closed: $detail" }
            if ($rc -ne 0) { throw "QC guest command failed (ExitCode=$rc): $detail" }
        }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "Timed out waiting for Queen Califia state '$Target'."
}

Write-QC '============================================================' DarkCyan
Write-QC 'QUEEN CALIFIA — SOVEREIGN EDGE CONTROL' Cyan
Write-QC '============================================================' DarkCyan
Write-QC "ACTION=$Action" Cyan
Write-QC "HYPERVISOR=$script:ResolvedHypervisor" Cyan
Write-QC "VM=$VmName" Cyan

if ($script:ResolvedHypervisor -eq 'hyperv') {
    if ($Action -eq 'status') {
        $vm = Get-VM -Name $VmName -ErrorAction Stop
        Write-QC "VM_STATE=$($vm.State)" Cyan
        if ($vm.State.ToString() -ne 'Running') { Write-QC 'QUEEN_CALIFIA=OFFLINE' Yellow; exit 0 }
        Invoke-HyperVControl -Verb STATUS
        exit 0
    }
    if ($Action -eq 'stop') {
        $vm = Get-VM -Name $VmName -ErrorAction Stop
        if ($vm.State.ToString() -ne 'Running') { Write-QC 'QUEEN_CALIFIA=STOPPED' Green; exit 0 }
    }
    Ensure-HyperVRunning
    switch ($Action) {
        'activate' { Invoke-HyperVControl -Verb ACTIVATE }
        'stop' { Invoke-HyperVControl -Verb STOP }
        'restart' { Invoke-HyperVControl -Verb RESTART }
    }
    exit 0
}

$script:VBoxManage = Get-VBoxManagePath
if ($Action -eq 'status') {
    $state = Get-VBoxState
    Write-QC "VM_STATE=$state" Cyan
    if ($state -ne 'running') { Write-QC 'QUEEN_CALIFIA=OFFLINE' Yellow; exit 0 }
    $runtimeState = Get-GuestProperty -Name '/QueenCalifia/SovereignEdge/State'
    if (-not $runtimeState) { $runtimeState = 'UNKNOWN' }
    Write-QC "QUEEN_CALIFIA=$runtimeState" Cyan
    exit 0
}

Ensure-VBoxRunning
Wait-GuestAdditions
switch ($Action) {
    'activate' { Invoke-VBoxControl -Verb ACTIVATE -Target READY }
    'stop' { Invoke-VBoxControl -Verb STOP -Target STOPPED }
    'restart' { Invoke-VBoxControl -Verb RESTART -Target READY }
}
