#requires -Version 7.0
[CmdletBinding()]
param(
    [string]$VmName = 'QueenCalifia-Sovereign-Edge-HyperV',
    [string]$GuestUser = 'qcadmin',
    [string]$KeyPath = (Join-Path $HOME '.ssh\queen-califia-hyperv-control'),
    [ValidateRange(30, 600)][int]$ReadyTimeoutSeconds = 180
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) { throw 'Hyper-V PowerShell module is required.' }
if (-not (Get-Command ssh.exe -ErrorAction SilentlyContinue)) { throw 'Windows OpenSSH client is required.' }
if (-not (Get-Command ssh-keygen.exe -ErrorAction SilentlyContinue)) { throw 'ssh-keygen.exe is required.' }

$vm = Get-VM -Name $VmName -ErrorAction Stop
if ($vm.State -eq 'Off') { Start-VM -Name $VmName | Out-Null }
elseif ($vm.State -ne 'Running') { throw "VM '$VmName' must be Off or Running; current state: $($vm.State)" }

if (-not (Test-Path -LiteralPath $KeyPath)) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $KeyPath) | Out-Null
    & ssh-keygen.exe -q -t ed25519 -a 64 -N '' -C 'queen-califia-hyperv-control' -f $KeyPath
    if ($LASTEXITCODE -ne 0) { throw 'Failed to generate Hyper-V control key.' }
}
$publicKey = (Get-Content -LiteralPath "$KeyPath.pub" -Raw).Trim()

function Get-QCHyperVIP {
    $adapter = Get-VMNetworkAdapter -VMName $VmName | Select-Object -First 1
    foreach ($candidate in @($adapter.IPAddresses)) {
        if ($candidate -match '^\d{1,3}(\.\d{1,3}){3}$' -and -not $candidate.StartsWith('169.254.')) { return $candidate }
    }
    $mac = ($adapter.MacAddress -replace '(.{2})(?!$)', '$1-').ToUpperInvariant()
    $neighbor = Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object {
        $_.LinkLayerAddress -and $_.LinkLayerAddress.ToUpperInvariant() -eq $mac -and $_.IPAddress -match '^\d{1,3}(\.\d{1,3}){3}$'
    } | Select-Object -First 1
    if ($neighbor) { return $neighbor.IPAddress }
    return $null
}

$deadline = [DateTimeOffset]::UtcNow.AddSeconds($ReadyTimeoutSeconds)
do {
    $ip = Get-QCHyperVIP
    if ($ip -and (Test-NetConnection -ComputerName $ip -Port 22 -InformationLevel Quiet -WarningAction SilentlyContinue)) { break }
    Start-Sleep -Seconds 2
} while ([DateTimeOffset]::UtcNow -lt $deadline)
if (-not $ip) { throw 'Unable to discover Hyper-V guest IPv4 address.' }

$remote = "sudo bash /opt/queen-califia/scripts/edge/install-hyperv-control.sh '$publicKey'"
Write-Host "HYPERV_GUEST_IP=$ip" -ForegroundColor Cyan
Write-Host 'One-time enrollment will request the existing guest password and sudo authentication.' -ForegroundColor Yellow
& ssh.exe -t "$GuestUser@$ip" $remote
if ($LASTEXITCODE -ne 0) { throw "Hyper-V control-key enrollment failed (ExitCode=$LASTEXITCODE)." }

$knownHosts = "$KeyPath.known_hosts"
& ssh.exe -o BatchMode=yes -o IdentitiesOnly=yes -o "IdentityFile=$KeyPath" -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$knownHosts" "$GuestUser@$ip" STATUS
if ($LASTEXITCODE -notin @(0,78)) { throw 'Restricted Hyper-V control key verification failed.' }
Write-Host 'HYPERV_CONTROL_ENROLLMENT=PASS' -ForegroundColor Green
