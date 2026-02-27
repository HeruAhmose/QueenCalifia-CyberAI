#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Apply strong branch protection for PR-gated environments (staging + production) using GitHub CLI.

.DESCRIPTION
  Requires:
    - GitHub CLI (gh)
    - Authenticated session: gh auth login (or GH_TOKEN env var)

  Uses:
    PUT /repos/{owner}/{repo}/branches/{branch}/protection

  Optionally auto-detects the exact required status checks from the latest commit on
  each branch head. When possible, it prefers the newer `required_status_checks.checks`
  objects (context + app_id) to avoid name collisions across GitHub Apps.

.EXAMPLE
  pwsh ./scripts/github/protect_branches.ps1 -Owner "YOURORG" -Repo "QueenCalifia-CyberAI"

.EXAMPLE
  # Auto-detect required checks from each branch head, then apply
  pwsh ./scripts/github/protect_branches.ps1 -AutoDetectStatusChecks

.EXAMPLE
  # Auto-detect but only keep checks that start with "ci /" or "argocd"
  pwsh ./scripts/github/protect_branches.ps1 -AutoDetectStatusChecks `
    -AllowlistRegex '^ci\s*/', '^argocd'

.EXAMPLE
  # Auto-detect, exclude external apps, produce a JSON report without applying
  pwsh ./scripts/github/protect_branches.ps1 -AutoDetectStatusChecks `
    -ExcludeAppSlugs 'dependabot','some-external-app' `
    -DryRun -ReportPath artifacts/branch-protection-payload.json
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
  [int] $Approvals = 2,

  [Parameter(Mandatory = $false)]
  [bool] $EnforceAdmins = $true,

  [Parameter(Mandatory = $false)]
  [bool] $RequireCodeOwnerReviews = $true,

  [Parameter(Mandatory = $false)]
  [bool] $DismissStaleReviews = $true,

  [Parameter(Mandatory = $false)]
  [bool] $RequireConversationResolution = $true,

  [Parameter(Mandatory = $false)]
  [bool] $RequiredLinearHistory = $true,

  [Parameter(Mandatory = $false)]
  [bool] $AllowForcePushes = $false,

  [Parameter(Mandatory = $false)]
  [bool] $AllowDeletions = $false,

  # Manual lists (used when -AutoDetectStatusChecks is NOT set, or used as fallback if detection returns none)
  [Parameter(Mandatory = $false)]
  [string[]] $StatusChecksStaging = @("ci / lockfiles", "ci / k8s-validate"),

  [Parameter(Mandatory = $false)]
  [string[]] $StatusChecksProduction = @("ci / lockfiles", "ci / k8s-validate", "argocd-healthcheck / argocd-healthcheck"),

  # Auto-detect contexts from branch head (recommended)
  [Parameter(Mandatory = $false)]
  [switch] $AutoDetectStatusChecks,

  # Optional filters for detected checks (regex, case-insensitive).
  # If AllowlistRegex is provided, a check must match at least one allowlist pattern.
  # Any check matching a denylist pattern is removed.
  [Parameter(Mandatory = $false)]
  [string[]] $AllowlistRegex = @(),

  [Parameter(Mandatory = $false)]
  [string[]] $DenylistRegex = @(),

  # Exclude check-runs emitted by specific GitHub Apps (app slug).
  # Useful to avoid accidentally requiring external integrations.
  [Parameter(Mandatory = $false)]
  [string[]] $ExcludeAppSlugs = @(),

  # Use newer required_status_checks.checks objects when possible (context + app_id).
  # If disabled, only required_status_checks.contexts is used.
  [Parameter(Mandatory = $false)]
  [bool] $UseChecksObjects = $true,

  # When checks objects exist, keep contexts limited to non-check-run contexts (e.g. legacy commit statuses),
  # reducing the chance of context name collisions.
  [Parameter(Mandatory = $false)]
  [bool] $PreferChecksObjects = $true,

  # Always-include (appended after detection/manual lists)
  [Parameter(Mandatory = $false)]
  [string[]] $ExtraStatusChecksStaging = @(),

  [Parameter(Mandatory = $false)]
  [string[]] $ExtraStatusChecksProduction = @(),

  [Parameter(Mandatory = $false)]
  [switch] $DryRun,

  # If set, writes a JSON array describing the exact payload(s) used.
  [Parameter(Mandatory = $false)]
  [string] $ReportPath = ""
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

function Apply-RegexFilters([string[]] $Items, [string[]] $Allow, [string[]] $Deny) {
  $allowR = New-RegexList $Allow
  $denyR  = New-RegexList $Deny

  $filtered = @()
  foreach ($it in (Normalize-StringArray $Items)) {
    if (Context-Passes -Context $it -Allow $allowR -Deny $denyR) {
      $filtered += $it.Trim()
    }
  }
  return @($filtered | Sort-Object -Unique)
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

function Get-DetectedChecksForRef([string] $Ref, [string[]] $ExcludedSlugs) {
  $sha = GhApiScalar "/repos/$Owner/$Repo/commits/$Ref" ".sha"
  if (-not $sha) { return $null }

  $excluded = Normalize-SlugArray $ExcludedSlugs

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
        if ($excluded -contains $creatorSlug) { continue }
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
        if ($excluded -contains $slugL) { continue }
      }

      # Drop "skipped" / "neutral" check-runs so we don't require checks that didn't truly run.
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
  $checkRunNames  = @($checkItems  | ForEach-Object { $_.context }) | Sort-Object -Unique
  $all = @($statusContexts + $checkRunNames) | Sort-Object -Unique

  return [pscustomobject]@{
    ref = $Ref
    sha = $sha
    status_items = $statusItems
    check_items = $checkItems
    dropped_check_items = $droppedCheckItems
    status_contexts = $statusContexts
    check_run_names = $checkRunNames
    all_context_like_names = $all
  }
}

function Build-ChecksObjects([object[]] $CheckItems, [regex[]] $Allow, [regex[]] $Deny) {
  $objs = @()
  foreach ($it in ($CheckItems ?? @())) {
    $ctx = ($it.context ?? "").ToString().Trim()
    if (-not (Context-Passes -Context $ctx -Allow $Allow -Deny $Deny)) { continue }

    $o = @{ context = $ctx }
    if ($null -ne $it.app_id -and "$($it.app_id)".Trim() -ne "") {
      $o.app_id = [int]$it.app_id
    }

    $objs += $o
  }

  $seen = @{}
  $unique = @()
  foreach ($o in $objs) {
    $key = if ($o.ContainsKey("app_id")) { "$($o.context)||$($o.app_id)" } else { "$($o.context)||" }
    if (-not $seen.ContainsKey($key)) {
      $seen[$key] = $true
      $unique += $o
    }
  }
  return @($unique)
}

function To-JsonBody([hashtable] $Payload) {
  return ($Payload | ConvertTo-Json -Depth 50)
}

function Invoke-GhApiPutJson([string] $Endpoint, [string] $JsonBody) {
  Assert-Command "gh"
  $headers = @(
    "Accept: application/vnd.github+json",
    "X-GitHub-Api-Version: 2022-11-28"
  )

  if ($DryRun) {
    Write-Host "==> DRY RUN: gh api PUT $Endpoint"
    Write-Host $JsonBody
    return
  }

  $args = @("api", "--method", "PUT")
  foreach ($h in $headers) { $args += @("-H", $h) }
  $args += @($Endpoint, "--input", "-")

  $JsonBody | & gh @args | Out-Host
}

$resolved = Resolve-RepoNwo
$Owner = $resolved[0]
$Repo = $resolved[1]

$allowR = New-RegexList $AllowlistRegex
$denyR  = New-RegexList $DenylistRegex
$excludeSlugsN = Normalize-SlugArray $ExcludeAppSlugs

Write-Host "==> Repo: $Owner/$Repo"
Write-Host "==> Branches: $($Branches -join ', ')"
if ($AutoDetectStatusChecks) {
  Write-Host "==> Status checks: auto-detect enabled"
  if ($excludeSlugsN.Count -gt 0) { Write-Host "    ExcludeAppSlugs: $($excludeSlugsN -join '; ')" }
  if ((Normalize-StringArray $AllowlistRegex).Count -gt 0) { Write-Host "    AllowlistRegex: $($AllowlistRegex -join '; ')" }
  if ((Normalize-StringArray $DenylistRegex).Count -gt 0)  { Write-Host "    DenylistRegex:  $($DenylistRegex -join '; ')" }
  Write-Host "    UseChecksObjects: $UseChecksObjects (PreferChecksObjects=$PreferChecksObjects)"
}

$reportItems = @()

foreach ($branch in $Branches) {
  $branch = ($branch ?? "").Trim()
  if (-not $branch) { continue }

  $manualContexts = if ($branch -eq "production") { $StatusChecksProduction } else { $StatusChecksStaging }
  $manualContexts = Normalize-StringArray $manualContexts

  $extra = if ($branch -eq "production") { $ExtraStatusChecksProduction } else { $ExtraStatusChecksStaging }
  $extra = Normalize-StringArray $extra

  $detected = $null
  $contexts = @()
  $checksObjs = @()

  if ($AutoDetectStatusChecks) {
    $detected = Get-DetectedChecksForRef -Ref $branch -ExcludedSlugs $excludeSlugsN

    if ($detected -and $detected.all_context_like_names.Count -gt 0) {
      $allFiltered = @()
      foreach ($c in $detected.all_context_like_names) {
        if (Context-Passes -Context $c -Allow $allowR -Deny $denyR) { $allFiltered += $c.Trim() }
      }
      $allFiltered = @($allFiltered | Sort-Object -Unique)

      $statusOnlyFiltered = @()
      foreach ($c in $detected.status_contexts) {
        if (Context-Passes -Context $c -Allow $allowR -Deny $denyR) { $statusOnlyFiltered += $c.Trim() }
      }
      $statusOnlyFiltered = @($statusOnlyFiltered | Sort-Object -Unique)

      if ($UseChecksObjects) {
        $checksObjs = Build-ChecksObjects -CheckItems $detected.check_items -Allow $allowR -Deny $denyR
      }

      if ($PreferChecksObjects -and $checksObjs.Count -gt 0) {
        $contexts = $statusOnlyFiltered
      } else {
        $contexts = $allFiltered
      }
    }

    if ($contexts.Count -eq 0 -and $checksObjs.Count -eq 0) {
      Write-Host ""
      Write-Warning "Auto-detect produced no checks/contexts for '$branch'. Falling back to manual lists (if any)."
      $contexts = $manualContexts
      $checksObjs = @()
    }
  } else {
    $contexts = $manualContexts
  }

  $contexts = @($contexts + $extra) | Where-Object { ($_ ?? "").Trim() -ne "" } | ForEach-Object { $_.Trim() } | Sort-Object -Unique

  $payloadRequired = @{
    strict = $true
    contexts = $contexts
  }
  if ($UseChecksObjects -and $checksObjs.Count -gt 0) {
    $payloadRequired.checks = $checksObjs
  }

  $payload = @{
    required_status_checks = $payloadRequired
    enforce_admins = [bool]$EnforceAdmins
    required_pull_request_reviews = @{
      dismiss_stale_reviews           = [bool]$DismissStaleReviews
      require_code_owner_reviews      = [bool]$RequireCodeOwnerReviews
      required_approving_review_count = [int]$Approvals
    }
    restrictions = $null
    required_linear_history = [bool]$RequiredLinearHistory
    allow_force_pushes = [bool]$AllowForcePushes
    allow_deletions = [bool]$AllowDeletions
    required_conversation_resolution = [bool]$RequireConversationResolution
  }

  $endpoint = "/repos/$Owner/$Repo/branches/$branch/protection"

  $reportItems += [pscustomobject]@{
    branch = $branch
    endpoint = $endpoint
    payload = $payload
    required_status_contexts = $contexts
    required_status_checks_objects = $checksObjs
    auto_detected = [bool]$AutoDetectStatusChecks
    detected_sha = if ($detected) { $detected.sha } else { "" }
    detected_status_contexts = if ($detected) { $detected.status_contexts } else { @() }
    detected_check_run_names = if ($detected) { $detected.check_run_names } else { @() }
    detected_dropped_check_run_names = if ($detected) { @($detected.dropped_check_items | ForEach-Object { $_.context }) } else { @() }
    exclude_app_slugs = $excludeSlugsN
    allowlist_regex = Normalize-StringArray $AllowlistRegex
    denylist_regex = Normalize-StringArray $DenylistRegex
    extra_contexts = $extra
    fallback_manual_contexts = $manualContexts
    use_checks_objects = [bool]$UseChecksObjects
    prefer_checks_objects = [bool]$PreferChecksObjects
  }

  Write-Host ""
  Write-Host "==> Protecting: $branch"
  if ($detected) {
    $short = $detected.sha.Substring(0, [Math]::Min(7, $detected.sha.Length))
    Write-Host "    HEAD: $short"
  }
  Write-Host "    Required contexts: $($contexts -join '; ')"
  if ($UseChecksObjects -and $checksObjs.Count -gt 0) {
    $pretty = @($checksObjs | ForEach-Object { if ($_.ContainsKey('app_id')) { "$($_.context) (app_id=$($_.app_id))" } else { "$($_.context)" } })
    Write-Host "    Required checks objects: $($pretty -join '; ')"
  }

  $json = To-JsonBody $payload
  Invoke-GhApiPutJson -Endpoint $endpoint -JsonBody $json
}

if ($ReportPath) {
  $dir = Split-Path -Parent $ReportPath
  if ($dir) { New-Item -ItemType Directory -Force $dir | Out-Null }

  $reportItems | ConvertTo-Json -Depth 200 | Set-Content -Encoding UTF8 $ReportPath
  Write-Host ""
  Write-Host "📄 Wrote report: $ReportPath"
}

Write-Host ""
Write-Host "✅ Done. Verify in: Settings → Branches → Branch protection rules"
