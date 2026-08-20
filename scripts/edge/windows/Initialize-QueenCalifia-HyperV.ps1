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
if (-not (Get-Command scp.exe -ErrorAction SilentlyContinue)) { throw 'Windows OpenSSH scp client is required.' }
if (-not (Get-Command ssh-keygen.exe -ErrorAction SilentlyContinue)) { throw 'ssh-keygen.exe is required.' }

$vm = Get-VM -Name $VmName -ErrorAction Stop
if ($vm.State -eq 'Off') { Start-VM -Name $VmName | Out-Null }
elseif ($vm.State -ne 'Running') { throw "VM '$VmName' must be Off or Running; current state: $($vm.State)" }

if (-not (Test-Path -LiteralPath $KeyPath)) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $KeyPath) | Out-Null
    & ssh-keygen.exe -q -t ed25519 -a 64 -N '' -C 'queen-califia-hyperv-control' -f $KeyPath
    if ($LASTEXITCODE -ne 0) { throw 'Failed to generate Hyper-V control key.' }
}
$publicKeyPath = "$KeyPath.pub"
if (-not (Test-Path -LiteralPath $publicKeyPath)) { throw "Missing public key: $publicKeyPath" }

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

$knownHosts = "$KeyPath.known_hosts"
$remoteKey = "/tmp/queen-califia-hyperv-control-$([guid]::NewGuid().ToString('N')).pub"
$sshBase = @('-o', 'StrictHostKeyChecking=accept-new', '-o', "UserKnownHostsFile=$knownHosts")

Write-Host "HYPERV_GUEST_IP=$ip" -ForegroundColor Cyan
Write-Host 'One-time enrollment will request the existing guest password and sudo authentication.' -ForegroundColor Yellow

& scp.exe @sshBase $publicKeyPath "$GuestUser@${ip}:$remoteKey"
if ($LASTEXITCODE -ne 0) { throw "Hyper-V public-key staging failed (ExitCode=$LASTEXITCODE)." }

# Never interpolate the public-key text into a Windows OpenSSH command line. The
# remote shell reads the staged file locally, removes it before sudo, and passes
# the key to the root-owned installer entirely inside the Linux guest.
$remote = "key=`$(cat '$remoteKey') && rm -f '$remoteKey' && sudo bash /opt/queen-califia/scripts/edge/install-hyperv-control.sh `"`$key`""
& ssh.exe @sshBase -t "$GuestUser@$ip" $remote
$enrollCode = $LASTEXITCODE
if ($enrollCode -ne 0) {
    # Best-effort cleanup for failures that occurred before the remote command
    # consumed the staged public key. This never uses or transmits the private key.
    & ssh.exe @sshBase "$GuestUser@$ip" "rm -f '$remoteKey'" 2>$null | Out-Null
    throw "Hyper-V control-key enrollment failed (ExitCode=$enrollCode)."
}

& ssh.exe -o BatchMode=yes -o IdentitiesOnly=yes -o "IdentityFile=$KeyPath" -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$knownHosts" "$GuestUser@$ip" STATUS
if ($LASTEXITCODE -notin @(0,78)) { throw 'Restricted Hyper-V control key verification failed.' }
Write-Host 'HYPERV_CONTROL_ENROLLMENT=PASS' -ForegroundColor Green
