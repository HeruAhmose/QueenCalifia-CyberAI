# Start Docker Desktop (if installed) and wait until the engine accepts commands.
# Run in PowerShell (may need "Run as administrator" if Start-Service is used).

$dockerExe = "${env:ProgramFiles}\Docker\Docker\Docker Desktop.exe"
if (Test-Path $dockerExe) {
  $running = Get-Process "Docker Desktop" -ErrorAction SilentlyContinue
  if (-not $running) {
    Write-Host "Starting Docker Desktop..." -ForegroundColor Cyan
    Start-Process $dockerExe
  } else {
    Write-Host "Docker Desktop process is already running." -ForegroundColor DarkGray
  }
} else {
  Write-Host "Docker Desktop not found at: $dockerExe" -ForegroundColor Yellow
}

# Optional: start Windows service (admin shell often required)
$svc = Get-Service -Name "com.docker.service" -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne "Running") {
  try {
    Start-Service -Name "com.docker.service" -ErrorAction Stop
    Write-Host "Started service com.docker.service" -ForegroundColor Green
  } catch {
    Write-Host "Could not start com.docker.service (try PowerShell as Administrator): $($_.Exception.Message)" -ForegroundColor Yellow
  }
}

Write-Host "Waiting for Docker engine (up to 120s)..." -ForegroundColor Cyan
$deadline = (Get-Date).AddSeconds(120)
$ErrorActionPreference = "Continue"
while ((Get-Date) -lt $deadline) {
  docker info 2>&1 | Out-Null
  if ($LASTEXITCODE -eq 0) {
    Write-Host "Docker engine is up." -ForegroundColor Green
    docker version --format '{{.Server.Version}}' 2>$null
    exit 0
  }
  Start-Sleep -Seconds 2
}

Write-Host "Timed out. Open Docker Desktop manually and wait until it says Engine running." -ForegroundColor Red
exit 1
