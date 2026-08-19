#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('activate', 'status', 'stop', 'restart')]
    [string]$Action = 'activate',

    [string]$VmName = 'QueenCalifia-Sovereign-Edge',

    [ValidateSet('gui', 'separate')]
    [string]$Frontend = 'gui',

    [ValidateRange(30, 900)]
    [int]$GuestAdditionsTimeoutSeconds = 180,

    [ValidateRange(30, 1800)]
    [int]$ReadyTimeoutSeconds = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Prefix = '/QueenCalifia/SovereignEdge'
$StateKey = "$Prefix/State"
$DetailKey = "$Prefix/Detail"
$ControlPlaneKey = "$Prefix/ControlPlane"
$CommandKey = "$Prefix/Command"
$AckKey = "$Prefix/CommandAck"

function Write-QC {
    param([string]$Message, [ConsoleColor]$Color = [ConsoleColor]::Gray)
    Write-Host $Message -ForegroundColor $Color
}

function Get-VBoxManagePath {
    $fromPath = Get-Command 'VBoxManage.exe' -ErrorAction SilentlyContinue
    if ($null -ne $fromPath) {
        return $fromPath.Source
    }

    $candidates = @()
    if (${env:ProgramFiles}) {
        $candidates += (Join-Path ${env:ProgramFiles} 'Oracle\VirtualBox\VBoxManage.exe')
    }
    if (${env:ProgramFiles(x86)}) {
        $candidates += (Join-Path ${env:ProgramFiles(x86)} 'Oracle\VirtualBox\VBoxManage.exe')
    }

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    throw 'VBoxManage.exe was not found. Install Oracle VirtualBox or add VBoxManage.exe to PATH.'
}

$script:VBoxManage = Get-VBoxManagePath

function Invoke-VBox {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments,
        [switch]$AllowFailure
    )

    $output = & $script:VBoxManage @Arguments 2>&1
    $code = $LASTEXITCODE
    $text = ($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine

    if (-not $AllowFailure -and $code -ne 0) {
        throw "VBoxManage failed (ExitCode=$code): $text"
    }

    [pscustomobject]@{
        ExitCode = $code
        Output   = $text
    }
}

function Get-VMState {
    $result = Invoke-VBox -Arguments @('showvminfo', $VmName, '--machinereadable')
    $match = [regex]::Match($result.Output, '(?m)^VMState="([^"]+)"$')
    if (-not $match.Success) {
        throw "Unable to determine VirtualBox state for '$VmName'."
    }
    return $match.Groups[1].Value
}

function Get-GuestProperty {
    param([Parameter(Mandatory)][string]$Name)

    $result = Invoke-VBox -Arguments @('guestproperty', 'get', $VmName, $Name) -AllowFailure
    if ($result.ExitCode -ne 0 -or $result.Output -match 'No value set!') {
        return $null
    }

    $match = [regex]::Match($result.Output, '(?m)^Value:\s?(.*)$')
    if (-not $match.Success) {
        return $null
    }
    return $match.Groups[1].Value.Trim()
}

function Set-HostCommand {
    param(
        [Parameter(Mandatory)][ValidateSet('ACTIVATE', 'STOP', 'RESTART', 'STATUS')][string]$Verb,
        [Parameter(Mandatory)][string]$Nonce
    )

    $payload = "$Verb|$Nonce"
    Invoke-VBox -Arguments @(
        'guestproperty', 'set', $VmName, $CommandKey, $payload,
        '--flags=TRANSRESET,RDONLYGUEST'
    ) | Out-Null
    return $payload
}

function Wait-GuestAdditions {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($GuestAdditionsTimeoutSeconds)
    do {
        $version = Get-GuestProperty -Name '/VirtualBox/GuestAdd/Version'
        if ($version) {
            Write-QC "GUEST_ADDITIONS=PASS ($version)" Green
            return
        }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw "Guest Additions did not become ready within $GuestAdditionsTimeoutSeconds seconds."
}

function Ensure-VMRunning {
    $state = Get-VMState
    Write-QC "VM_STATE=$state" Cyan

    switch ($state) {
        'running' { return }
        'paused' {
            Invoke-VBox -Arguments @('controlvm', $VmName, 'resume') | Out-Null
            Write-QC 'VM_RESUME=PASS' Green
            return
        }
        'poweroff' {
            Invoke-VBox -Arguments @('startvm', "--type=$Frontend", $VmName) | Out-Null
            Write-QC "VM_START=PASS ($Frontend)" Green
            return
        }
        'saved' {
            Invoke-VBox -Arguments @('startvm', "--type=$Frontend", $VmName) | Out-Null
            Write-QC "VM_RESUME_FROM_SAVED=PASS ($Frontend)" Green
            return
        }
        'aborted' {
            Invoke-VBox -Arguments @('startvm', "--type=$Frontend", $VmName) | Out-Null
            Write-QC "VM_RECOVERY_START=PASS ($Frontend)" Yellow
            return
        }
        default {
            throw "VM '$VmName' is in unsupported state '$state'."
        }
    }
}

function Show-QCStatus {
    $vmState = Get-VMState
    Write-QC "VM_STATE=$vmState" Cyan
    if ($vmState -notin @('running', 'paused')) {
        Write-QC 'QUEEN_CALIFIA=OFFLINE' Yellow
        return
    }

    $controlPlane = Get-GuestProperty -Name $ControlPlaneKey
    $state = Get-GuestProperty -Name $StateKey
    $detail = Get-GuestProperty -Name $DetailKey

    if (-not $controlPlane) { $controlPlane = 'not-installed' }
    if (-not $state) { $state = 'UNKNOWN' }

    Write-QC "CONTROL_PLANE=$controlPlane" Cyan
    Write-QC "QUEEN_CALIFIA=$state" $(if ($state -eq 'READY') { 'Green' } elseif ($state -in @('FAILED', 'BLOCKED')) { 'Red' } else { 'Yellow' })
    if ($detail) {
        Write-QC "DETAIL=$detail" Yellow
    }
}

function Require-ControlPlane {
    $controlPlane = Get-GuestProperty -Name $ControlPlaneKey
    if ($controlPlane -ne 'systemd-v1') {
        throw @"
QC boot control plane is not installed in the guest.
One-time guest setup is required from the VM console:
  cd /opt/queen-califia
  sudo bash scripts/edge/install-systemd.sh
After that, normal activation is passwordless from Windows.
"@
    }
    Write-QC 'CONTROL_PLANE=systemd-v1' Green
}

function Invoke-QCCommandAndWait {
    param(
        [Parameter(Mandatory)][ValidateSet('ACTIVATE', 'STOP', 'RESTART')][string]$Verb,
        [Parameter(Mandatory)][ValidateSet('READY', 'STOPPED')][string]$TargetState
    )

    $nonce = [guid]::NewGuid().ToString()
    $payload = Set-HostCommand -Verb $Verb -Nonce $nonce
    Write-QC "COMMAND=$Verb" Cyan

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($ReadyTimeoutSeconds)
    $lastState = $null
    $commandAcknowledged = $false

    do {
        $state = Get-GuestProperty -Name $StateKey
        $detail = Get-GuestProperty -Name $DetailKey
        $ack = Get-GuestProperty -Name $AckKey

        if ($state -and $state -ne $lastState) {
            Write-QC "QC_STATE=$state" $(if ($state -eq $TargetState) { 'Green' } elseif ($state -in @('FAILED', 'BLOCKED')) { 'Red' } else { 'Yellow' })
            $lastState = $state
        }

        if ($state -eq $TargetState) {
            Write-QC "QUEEN_CALIFIA=$TargetState" Green
            return
        }

        if ($ack -and $ack.StartsWith("$payload|")) {
            $commandAcknowledged = $true
            $parts = $ack.Split('|')
            $rc = [int]$parts[-1]
            if ($rc -eq 78) {
                if (-not $detail) { $detail = 'runtime authorization/configuration gate is closed' }
                throw "QC activation is fail-closed: $detail"
            }
            if ($rc -ne 0) {
                if (-not $detail) { $detail = 'guest runtime command failed' }
                throw "QC guest command failed (ExitCode=$rc): $detail"
            }
        }

        if ($commandAcknowledged -and $state -in @('FAILED', 'BLOCKED')) {
            if (-not $detail) { $detail = 'guest runtime entered a terminal failure state' }
            throw "QC activation did not reach '$TargetState': $state - $detail"
        }

        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    if (-not $detail) { $detail = 'no additional guest detail was published' }
    throw "Timed out waiting for Queen Califia state '$TargetState'. Last state='$lastState'. Detail='$detail'."
}

Write-QC '============================================================' DarkCyan
Write-QC 'QUEEN CALIFIA — SOVEREIGN EDGE CONTROL' Cyan
Write-QC '============================================================' DarkCyan
Write-QC "ACTION=$Action" Cyan
Write-QC "VM=$VmName" Cyan

if ($Action -eq 'status') {
    Show-QCStatus
    exit 0
}

if ($Action -eq 'stop') {
    $stopVmState = Get-VMState
    if ($stopVmState -notin @('running', 'paused')) {
        Write-QC "VM_STATE=$stopVmState" Cyan
        Write-QC 'QUEEN_CALIFIA=STOPPED' Green
        exit 0
    }
}

Ensure-VMRunning
Wait-GuestAdditions
Require-ControlPlane

switch ($Action) {
    'activate' {
        $currentState = Get-GuestProperty -Name $StateKey
        if ($currentState -eq 'READY') {
            Write-QC 'QUEEN_CALIFIA=READY' Green
            exit 0
        }
        Invoke-QCCommandAndWait -Verb 'ACTIVATE' -TargetState 'READY'
    }
    'stop' {
        Invoke-QCCommandAndWait -Verb 'STOP' -TargetState 'STOPPED'
    }
    'restart' {
        Invoke-QCCommandAndWait -Verb 'RESTART' -TargetState 'READY'
    }
}
