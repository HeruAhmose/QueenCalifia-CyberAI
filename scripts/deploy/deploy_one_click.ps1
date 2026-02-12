param(
  [Parameter(Mandatory=$true)][string]$Host,
  [Parameter(Mandatory=$true)][string]$User,
  [Parameter(Mandatory=$true)][string]$KeyPath,
  [string]$Ref = "main",
  [switch]$Acme,
  [int]$Port = 22,
  [string]$Domain,
  [string]$Email
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $Domain) { throw "Domain required (-Domain example.com)" }
if (-not $Email) { throw "Email required (-Email you@example.com)" }

# Required secrets are read from env so you can store them safely:
#   QC_API_KEY_PEPPER, QC_AUDIT_HMAC_KEY
if (-not $env:QC_API_KEY_PEPPER) { throw "Set env:QC_API_KEY_PEPPER" }
if (-not $env:QC_AUDIT_HMAC_KEY) { throw "Set env:QC_AUDIT_HMAC_KEY" }

$acmeVal = if ($Acme) { "1" } else { "0" }

$env:DEPLOY_HOST = $Host
$env:DEPLOY_USER = $User
$env:DEPLOY_SSH_KEY = $KeyPath
$env:DEPLOY_SSH_PORT = "$Port"
$env:DEPLOY_REF = $Ref
$env:QC_ACME = $acmeVal
$env:QC_DOMAIN = $Domain
$env:QC_EMAIL = $Email

bash .\scripts\deploy\vm_deploy.sh
