#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Print the real status-check context names and check-run names seen on the latest commit of each branch.

.DESCRIPTION
  Branch protection required checks must match the exact context strings.
  This script queries:
    - Combined commit statuses: GET /repos/{owner}/{repo}/commits/{ref}/status
    - Check runs:             GET /repos/{owner}/{repo}/commits/{ref}/check-runs

  It also prints check-run GitHub App metadata (app slug + app_id), so you can build
  required_status_checks.checks objects (context + app_id) to avoid check name collisions.

  Requires:
    - GitHub CLI (gh)
    - Authenticated session (gh auth login or GH_TOKEN)

.EXAMPLE
  pwsh scripts/github/print_check_contexts.ps1 -Branches staging,production

.EXAMPLE
  pwsh scripts/github/print_check_contexts.ps1 -ExcludeAppSlugs dependabot,some-external-app

.EXAMPLE
  pwsh scripts/github/print_check_contexts.ps1 -OutJson artifacts/check-contexts.json -OutText artifacts/check-contexts.txt
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

param(
  [Parameter(Mandatory = $false)]
  [string] $Owner,

  [Parameter(Mandatory = $false)]
  [string] $Repo,

  [Parameter(Mandatory = $false)]
  [string[]] $Branches = @("staging", "production"),

  [Parameter(Mandatory = $false)]
  [string] $OutJson = "",

  [Parameter(Mandatory = $false)]
  [string] $OutText = "",

  [Parameter(Mandatory = $false)]
  [string[]] $AllowlistRegex = @(),

  [Parameter(Mandatory = $false)]
  [string[]] $DenylistRegex = @(),

  [Parameter(Mandatory = $false)]
  [string[]] $ExcludeAppSlugs = @()
)

function Assert-Command([string] $Name) {
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    throw "Missing dependency: '$Name'. Install it and retry."
  }
}

function Resolve-RepoNwo() {
  if ($Owner -and $Repo) { return @($Owner, $Repo) }

  Assert-Command "gh"
  $nwo = $null
  try { $nwo = gh repo view --json nameWithOwner -q .nameWithOwner 2>$null } catch {}
  if (-not $nwo) {
    throw "Owner/Repo not provided and repo detection failed. Run inside a git repo with gh configured, or pass -Owner and -Repo."
  }
  if ($nwo -notmatch "^(?<o>[^/]+)/(?<r>.+)$") { throw "Could not parse nameWithOwner: '$nwo'" }
  return @($Matches["o"], $Matches["r"])
}

function Normalize-StringArray([string[]] $Items) {
  return @(
    $Items |
    Where-Object { ($_ ?? "").Trim() -ne "" } |
    ForEach-Object { $_.Trim() }
  )
}

function Normalize-SlugArray([string[]] $Items) {
  return @(
    Normalize-StringArray $Items |
    ForEach-Object { $_.ToLowerInvariant() } |
    Sort-Object -Unique
  )
}

function New-RegexList([string[]] $Patterns) {
  $p = Normalize-StringArray $Patterns
  return @($p | ForEach-Object { [regex]::new($_, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase) })
}

function Context-Passes([string] $Context, [regex[]] $Allow, [regex[]] $Deny) {
  $ctx = ($Context ?? "").Trim()
  if (-not $ctx) { return $false }

  if ($Allow.Count -gt 0) {
    $ok = $false
    foreach ($r in $Allow) { if ($r.IsMatch($ctx)) { $ok = $true; break } }
    if (-not $ok) { return $false }
  }

  if ($Deny.Count -gt 0) {
    foreach ($r in $Deny) { if ($r.IsMatch($ctx)) { return $false } }
  }

  return $true
}

function GhApiJson([string] $Endpoint) {
  Assert-Command "gh"
  $headers = @(
    "Accept: application/vnd.github+json",
    "X-GitHub-Api-Version: 2022-11-28"
  )

  $args = @("api")
  foreach ($h in $headers) { $args += @("-H", $h) }
  $args += @($Endpoint)

  $raw = $null
  try { $raw = & gh @args 2>$null } catch { $raw = $null }
  if (-not $raw) { return $null }

  try { return ($raw | ConvertFrom-Json -Depth 200) } catch { return $null }
}

function GhApiScalar([string] $Endpoint, [string] $Jq) {
  Assert-Command "gh"
  $headers = @(
    "Accept: application/vnd.github+json",
    "X-GitHub-Api-Version: 2022-11-28"
  )

  $args = @("api")
  foreach ($h in $headers) { $args += @("-H", $h) }
  $args += @($Endpoint, "-q", $Jq)

  $raw = $null
  try { $raw = & gh @args 2>$null } catch { $raw = $null }

  if (-not $raw) { return "" }
  if ($raw -is [string]) { return $raw.Trim() }
  return "$raw".Trim()
}

$resolved = Resolve-RepoNwo
$Owner = $resolved[0]
$Repo = $resolved[1]

$allowR = New-RegexList $AllowlistRegex
$denyR  = New-RegexList $DenylistRegex
$excludeSlugsN = Normalize-SlugArray $ExcludeAppSlugs

Write-Host "==> Repo: $Owner/$Repo"
Write-Host "==> Branches: $($Branches -join ', ')"
if ((Normalize-StringArray $AllowlistRegex).Count -gt 0) { Write-Host "==> AllowlistRegex: $($AllowlistRegex -join '; ')" }
if ((Normalize-StringArray $DenylistRegex).Count -gt 0)  { Write-Host "==> DenylistRegex:  $($DenylistRegex -join '; ')" }
if ($excludeSlugsN.Count -gt 0) { Write-Host "==> ExcludeAppSlugs: $($excludeSlugsN -join '; ')" }
Write-Host ""

$report = @()
$textLines = New-Object System.Collections.Generic.List[string]

foreach ($branch in $Branches) {
  $branch = ($branch ?? "").Trim()
  if (-not $branch) { continue }

  Write-Host "==> Branch: $branch"
  $textLines.Add("==> Branch: $branch")

  $sha = GhApiScalar "/repos/$Owner/$Repo/commits/$branch" ".sha"
  if (-not $sha) {
    Write-Warning "Could not resolve commit SHA for ref: $branch"
    $textLines.Add("    HEAD: (unknown)")
    continue
  }

  $short = $sha.Substring(0, [Math]::Min(7, $sha.Length))
  Write-Host "    HEAD: $short"
  $textLines.Add("    HEAD: $short")

  $statusResp = GhApiJson "/repos/$Owner/$Repo/commits/$sha/status?per_page=100"
  $statusItems = @()
  if ($statusResp -and $statusResp.statuses) {
    foreach ($s in $statusResp.statuses) {
      $ctx = ($s.context ?? "").Trim()
      if (-not $ctx) { continue }
      $creatorLogin = ""
      try { $creatorLogin = ($s.creator.login ?? "").ToString().Trim() } catch { $creatorLogin = "" }
      if ($creatorLogin) {
        $creatorSlug = $creatorLogin.ToLowerInvariant()
        if ($excludeSlugsN -contains $creatorSlug) { continue }
      }
      $statusItems += [pscustomobject]@{
        context = $ctx
        creator_login = $creatorLogin
      }
    }
  }

    $checksResp = GhApiJson "/repos/$Owner/$Repo/commits/$sha/check-runs?per_page=100"
  $checkItems = @()
  $droppedCheckItems = @()
  if ($checksResp -and $checksResp.check_runs) {
    foreach ($cr in $checksResp.check_runs) {
      $name = ($cr.name ?? "").ToString().Trim()
      if (-not $name) { continue }

      $status = ""
      $conclusion = ""
      try {
        $status = ($cr.status ?? "").ToString().Trim()
        $conclusion = ($cr.conclusion ?? "").ToString().Trim()
      } catch {
        $status = ""
        $conclusion = ""
      }

      $slug = ""
      $appId = $null
      try {
        $slug = ($cr.app.slug ?? "").ToString().Trim()
        $appId = $cr.app.id
      } catch {
        $slug = ""
        $appId = $null
      }

      if ($slug) {
        $slugL = $slug.ToLowerInvariant()
        if ($excludeSlugsN -contains $slugL) { continue }
      }

      if ($conclusion) {
        $c = $conclusion.ToLowerInvariant()
        if ($c -eq "skipped" -or $c -eq "neutral") {
          $droppedCheckItems += [pscustomobject]@{
            context = $name
            app_slug = $slug
            app_id = $appId
            status = $status
            conclusion = $conclusion
            reason = "conclusion:$conclusion"
          }
          continue
        }
      }

      $checkItems += [pscustomobject]@{
        context = $name
        app_slug = $slug
        app_id = $appId
        status = $status
        conclusion = $conclusion
      }
    }
  }

$statusContexts = @($statusItems | ForEach-Object { $_.context }) | Sort-Object -Unique
  $checkNames     = @($checkItems  | ForEach-Object { $_.context }) | Sort-Object -Unique
  $allNames = @($statusContexts + $checkNames) | Sort-Object -Unique

  $filtered = @()
  foreach ($n in $allNames) {
    if (Context-Passes -Context $n -Allow $allowR -Deny $denyR) { $filtered += $n.Trim() }
  }
  $filtered = @($filtered | Sort-Object -Unique)

  $checksObjects = @()
  foreach ($ci in $checkItems) {
    $ctx = $ci.context
    if (-not (Context-Passes -Context $ctx -Allow $allowR -Deny $denyR)) { continue }
    $o = @{ context = $ctx }
    if ($null -ne $ci.app_id -and "$($ci.app_id)".Trim() -ne "") { $o.app_id = [int]$ci.app_id }
    $checksObjects += $o
  }
  $seen = @{}
  $checksObjectsU = @()
  foreach ($o in $checksObjects) {
    $key = if ($o.ContainsKey("app_id")) { "$($o.context)||$($o.app_id)" } else { "$($o.context)||" }
    if (-not $seen.ContainsKey($key)) { $seen[$key] = $true; $checksObjectsU += $o }
  }

  if ($filtered.Count -gt 0) {
    Write-Host "    Context-like names (paste list):"
    $textLines.Add("    Context-like names (paste list):")
    $filtered | ForEach-Object { Write-Host "      - $_"; $textLines.Add("      - $_") }
  } else {
    Write-Host "    Context-like names: (none found)"
    $textLines.Add("    Context-like names: (none found)")
  }

  if ($checksObjectsU.Count -gt 0) {
    Write-Host "    Checks objects (preferred):"
    $textLines.Add("    Checks objects (preferred):")
    foreach ($o in $checksObjectsU) {
      $line = if ($o.ContainsKey("app_id")) { "      - context=$($o.context) app_id=$($o.app_id)" } else { "      - context=$($o.context)" }
      Write-Host $line
      $textLines.Add($line)
    }
  } else {
    Write-Host "    Checks objects: (none)"
    $textLines.Add("    Checks objects: (none)")
  }

  if ($statusItems.Count -gt 0) {
    Write-Host "    Combined statuses:"
    $textLines.Add("    Combined statuses:")
    $statusItems | Sort-Object context -Unique | ForEach-Object {
      $who = if ($_.creator_login) { " (by $($_.creator_login))" } else { "" }
      $line = "      - $($_.context)$who"
      Write-Host $line
      $textLines.Add($line)
    }
  } else {
    Write-Host "    Combined statuses: (none)"
    $textLines.Add("    Combined statuses: (none)")
  }

  if ($checkItems.Count -gt 0) {
    Write-Host "    Check runs:"
    $textLines.Add("    Check runs:")
    $checkItems | Sort-Object context -Unique | ForEach-Object {
      $meta = ""
      if ($_.app_slug -or $null -ne $_.app_id) {
        $meta = " (app=$($_.app_slug) id=$($_.app_id))"
      }
      $line = "      - $($_.context)$meta"
      Write-Host $line
      $textLines.Add($line)
    }
  } else {
    Write-Host "    Check runs: (none)"
    $textLines.Add("    Check runs: (none)")
  }

  if ($droppedCheckItems.Count -gt 0) {
    Write-Host "    Dropped check runs (skipped/neutral):"
    $textLines.Add("    Dropped check runs (skipped/neutral):")
    $droppedCheckItems | Sort-Object context -Unique | ForEach-Object {
      $meta = ""
      if ($_.app_slug -or $null -ne $_.app_id) {
        $meta = " (app=$($_.app_slug) id=$($_.app_id) status=$($_.status) conclusion=$($_.conclusion))"
      } else {
        $meta = " (status=$($_.status) conclusion=$($_.conclusion))"
      }
      $line = "      - $($_.context)$meta"
      Write-Host $line
      $textLines.Add($line)
    }
  }

  Write-Host ""
  $textLines.Add("")

  $report += [pscustomobject]@{
    branch = $branch
    head_sha = $sha
    exclude_app_slugs = $excludeSlugsN
    status_items = $statusItems
    check_items = $checkItems
    dropped_check_items = $droppedCheckItems
    status_contexts = @($statusContexts)
    check_run_names = @($checkNames)
    combined = @($allNames)
    filtered_recommended = @($filtered)
    checks_objects = $checksObjectsU
    allowlist_regex = Normalize-StringArray $AllowlistRegex
    denylist_regex = Normalize-StringArray $DenylistRegex
  }
}

if ($OutJson) {
  $dir = Split-Path -Parent $OutJson
  if ($dir) { New-Item -ItemType Directory -Force $dir | Out-Null }
  $report | ConvertTo-Json -Depth 200 | Set-Content -Encoding UTF8 $OutJson
  Write-Host "📄 Wrote: $OutJson"
}

if ($OutText) {
  $dir = Split-Path -Parent $OutText
  if ($dir) { New-Item -ItemType Directory -Force $dir | Out-Null }
  $textLines | Set-Content -Encoding UTF8 $OutText
  Write-Host "📄 Wrote: $OutText"
}
