#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Compare desired branch protection payload(s) (from protect_branches.ps1 -ReportPath) against the current
  protection on GitHub, producing a human-readable diff.

.DESCRIPTION
  Requires:
    - GitHub CLI (gh)
    - Authenticated session (gh auth login or GH_TOKEN)

  Notes:
    - If a branch has no protection, GET /protection typically returns 404; this script treats that as "none".
    - Output is intentionally focused on the fields this repo sets (reviews, statuses/checks, linear history, etc.)

.EXAMPLE
  pwsh scripts/github/diff_branch_protection.ps1 -ReportPath artifacts/branch-protection-payload.json
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

param(
  [Parameter(Mandatory = $false)]
  [string] $Owner,

  [Parameter(Mandatory = $false)]
  [string] $Repo,

  [Parameter(Mandatory = $false)]
  [string] $ReportPath = "artifacts/branch-protection-payload.json",

  [Parameter(Mandatory = $false)]
  [string] $OutMarkdown = "artifacts/branch-protection-diff.md",

  [Parameter(Mandatory = $false)]
  [string] $OutJson = "artifacts/branch-protection-diff.json"
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

function Normalize-StringArray([object] $Items) {
  if ($null -eq $Items) { return @() }
  $arr = @()
  foreach ($i in @($Items)) {
    $s = ($i ?? "").ToString().Trim()
    if ($s) { $arr += $s }
  }
  return @($arr | Sort-Object -Unique)
}

function Normalize-ChecksObjects([object] $Checks) {
  if ($null -eq $Checks) { return @() }
  $out = @()
  foreach ($c in @($Checks)) {
    if ($null -eq $c) { continue }
    $ctx = ($c.context ?? "").ToString().Trim()
    if (-not $ctx) { continue }
    $o = @{ context = $ctx }
    if ($null -ne $c.app_id -and "$($c.app_id)".Trim() -ne "") {
      try { $o.app_id = [int]$c.app_id } catch { }
    }
    $out += $o
  }

  $seen = @{}
  $uniq = @()
  foreach ($o in $out) {
    $key = if ($o.ContainsKey("app_id")) { "$($o.context)||$($o.app_id)" } else { "$($o.context)||" }
    if (-not $seen.ContainsKey($key)) {
      $seen[$key] = $true
      $uniq += $o
    }
  }

  return @($uniq | Sort-Object @{ Expression = { $_.context } }, @{ Expression = { if ($_.ContainsKey("app_id")) { $_.app_id } else { 0 } } })
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

function Get-BoolEnabled([object] $Obj) {
  if ($null -eq $Obj) { return $false }
  # Some endpoints return { enabled: true }, some return boolean. Handle both.
  if ($Obj -is [bool]) { return [bool]$Obj }
  try {
    if ($null -ne $Obj.enabled) { return [bool]$Obj.enabled }
  } catch {}
  return $false
}

function Normalize-Desired([object] $Payload) {
  $rsc = $Payload.required_status_checks
  $out = [ordered]@{
    enforce_admins = [ordered]@{ enabled = [bool]$Payload.enforce_admins }
    required_linear_history = [ordered]@{ enabled = [bool]$Payload.required_linear_history }
    allow_force_pushes = [ordered]@{ enabled = [bool]$Payload.allow_force_pushes }
    allow_deletions = [ordered]@{ enabled = [bool]$Payload.allow_deletions }
    required_conversation_resolution = [ordered]@{ enabled = [bool]$Payload.required_conversation_resolution }
    required_pull_request_reviews = [ordered]@{
      dismiss_stale_reviews = [bool]$Payload.required_pull_request_reviews.dismiss_stale_reviews
      require_code_owner_reviews = [bool]$Payload.required_pull_request_reviews.require_code_owner_reviews
      required_approving_review_count = [int]$Payload.required_pull_request_reviews.required_approving_review_count
    }
    required_status_checks = [ordered]@{
      strict = [bool]$rsc.strict
      contexts = Normalize-StringArray $rsc.contexts
      checks = Normalize-ChecksObjects $rsc.checks
    }
  }
  return $out
}

function Normalize-Current([object] $Cur) {
  if ($null -eq $Cur) { return $null }

  $rsc = $Cur.required_status_checks
  $out = [ordered]@{
    enforce_admins = [ordered]@{ enabled = (Get-BoolEnabled $Cur.enforce_admins) }
    required_linear_history = [ordered]@{ enabled = (Get-BoolEnabled $Cur.required_linear_history) }
    allow_force_pushes = [ordered]@{ enabled = (Get-BoolEnabled $Cur.allow_force_pushes) }
    allow_deletions = [ordered]@{ enabled = (Get-BoolEnabled $Cur.allow_deletions) }
    required_conversation_resolution = [ordered]@{ enabled = (Get-BoolEnabled $Cur.required_conversation_resolution) }
    required_pull_request_reviews = [ordered]@{
      dismiss_stale_reviews = [bool]($Cur.required_pull_request_reviews.dismiss_stale_reviews ?? $false)
      require_code_owner_reviews = [bool]($Cur.required_pull_request_reviews.require_code_owner_reviews ?? $false)
      required_approving_review_count = [int]($Cur.required_pull_request_reviews.required_approving_review_count ?? 0)
    }
    required_status_checks = [ordered]@{
      strict = [bool]($rsc.strict ?? $false)
      contexts = Normalize-StringArray $rsc.contexts
      checks = Normalize-ChecksObjects $rsc.checks
    }
  }
  return $out
}

function Key-Checks([object] $ChecksObjs) {
  $keys = @()
  foreach ($o in @($ChecksObjs)) {
    if ($null -eq $o) { continue }
    $ctx = ($o.context ?? "").ToString().Trim()
    if (-not $ctx) { continue }
    $app = ""
    try { if ($o.ContainsKey("app_id")) { $app = "$($o.app_id)" } } catch {}
    $keys += "$ctx||$app"
  }
  return @($keys | Sort-Object -Unique)
}

function Set-Diff([string[]] $Current, [string[]] $Desired) {
  $cur = @($Current | Sort-Object -Unique)
  $des = @($Desired | Sort-Object -Unique)
  $add = @($des | Where-Object { $_ -notin $cur })
  $rem = @($cur | Where-Object { $_ -notin $des })
  return [pscustomobject]@{
    add = $add
    remove = $rem
  }
}

function Pretty([object] $v) {
  if ($null -eq $v) { return "(none)" }
  if ($v -is [bool]) { return ($(if ($v) { "true" } else { "false" })) }
  if ($v -is [int] -or $v -is [long]) { return "$v" }
  if ($v -is [string]) { return $v }
  try {
    if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) {
      $arr = @()
      foreach ($i in $v) { $arr += Pretty $i }
      return ($arr -join "; ")
    }
  } catch {}
  try { return ($v | ConvertTo-Json -Depth 20 -Compress) } catch { return "$v" }
}

function Build-RecommendedAllowlistRegex([string[]] $Contexts) {
  $items = @($Contexts | Where-Object { ($_ ?? '').Trim() -ne '' } | ForEach-Object { $_.Trim() })
  if ($items.Count -eq 0) { return @() }

  $prefixCounts = @{}
  foreach ($c in $items) {
    if ($c -match '^(?<p>.+?)\s*/\s*.+$') {
      $p = $Matches['p'].Trim()
      if ($p) { $prefixCounts[$p] = 1 + ([int]($prefixCounts[$p] ?? 0)) }
    }
  }

  $out = New-Object System.Collections.Generic.List[string]
  foreach ($c in ($items | Sort-Object -Unique)) {
    if ($c -match '^(?<p>.+?)\s*/\s*.+$') {
      $p = $Matches['p'].Trim()
      if ($p -and ([int]($prefixCounts[$p] ?? 0)) -ge 2) {
        $esc = [regex]::Escape($p).Replace(' ', '\s+')
        $out.Add(('^{0}\s*/' -f $esc))
        continue
      }
    }
    $escFull = [regex]::Escape($c).Replace(' ', '\s+')
    $out.Add(('^{0}$' -f $escFull))
  }

  return @($out | Sort-Object -Unique)
}


if (-not (Test-Path $ReportPath)) { throw "Missing report: $ReportPath" }

$resolved = Resolve-RepoNwo
$Owner = $resolved[0]
$Repo = $resolved[1]

$dirMd = Split-Path -Parent $OutMarkdown
if ($dirMd) { New-Item -ItemType Directory -Force $dirMd | Out-Null }
$dirJs = Split-Path -Parent $OutJson
if ($dirJs) { New-Item -ItemType Directory -Force $dirJs | Out-Null }

$items = Get-Content $ReportPath -Raw | ConvertFrom-Json -Depth 200
if ($items -isnot [System.Collections.IEnumerable]) { $items = @($items) }

$md = New-Object System.Collections.Generic.List[string]
$md.Add("# Branch protection diff")
$md.Add("")
$md.Add("Repo: **$Owner/$Repo**")
$md.Add("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ssK')")
$md.Add("")
$diffReport = @()

foreach ($it in $items) {
  $branch = ($it.branch ?? "").ToString().Trim()
  if (-not $branch) { continue }

  $endpoint = ($it.endpoint ?? "").ToString().Trim()
  if (-not $endpoint) { $endpoint = "/repos/$Owner/$Repo/branches/$branch/protection" }

  $desiredNorm = Normalize-Desired $it.payload
  $currentRaw = GhApiJson $endpoint
  $currentNorm = Normalize-Current $currentRaw

  $md.Add("## $branch")
  $md.Add("")

  if ($null -eq $currentNorm) {
    $md.Add("Current: *(no protection detected)*")
  } else {
    $md.Add("Current: *(protected)*")
  }
  $md.Add("")

  $rows = @()
  $fields = @(
    @{ k = "enforce_admins.enabled"; a = { param($x) $x.enforce_admins.enabled } },
    @{ k = "required_pull_request_reviews.required_approving_review_count"; a = { param($x) $x.required_pull_request_reviews.required_approving_review_count } },
    @{ k = "required_pull_request_reviews.require_code_owner_reviews"; a = { param($x) $x.required_pull_request_reviews.require_code_owner_reviews } },
    @{ k = "required_pull_request_reviews.dismiss_stale_reviews"; a = { param($x) $x.required_pull_request_reviews.dismiss_stale_reviews } },
    @{ k = "required_conversation_resolution.enabled"; a = { param($x) $x.required_conversation_resolution.enabled } },
    @{ k = "required_linear_history.enabled"; a = { param($x) $x.required_linear_history.enabled } },
    @{ k = "allow_force_pushes.enabled"; a = { param($x) $x.allow_force_pushes.enabled } },
    @{ k = "allow_deletions.enabled"; a = { param($x) $x.allow_deletions.enabled } },
    @{ k = "required_status_checks.strict"; a = { param($x) $x.required_status_checks.strict } }
  )

  foreach ($f in $fields) {
    $desV = & $f.a $desiredNorm
    $curV = if ($null -eq $currentNorm) { "(none)" } else { & $f.a $currentNorm }
    $same = if ($null -eq $currentNorm) { $false } else { (Pretty $curV) -eq (Pretty $desV) }
    $rows += [pscustomobject]@{
      Field = $f.k
      Current = Pretty $curV
      Desired = Pretty $desV
      Match = if ($same) { "✅" } else { "❌" }
    }
  }

  $md.Add("| Field | Current | Desired | Match |")
  $md.Add("|---|---|---|---|")
  foreach ($r in $rows) {
    $md.Add("| $($r.Field) | $($r.Current) | $($r.Desired) | $($r.Match) |")
  }
  $md.Add("")

  $curContexts = if ($null -eq $currentNorm) { @() } else { @($currentNorm.required_status_checks.contexts) }
  $desContexts = @($desiredNorm.required_status_checks.contexts)
  $ctxDiff = Set-Diff -Current $curContexts -Desired $desContexts

  $curChecksKeys = if ($null -eq $currentNorm) { @() } else { Key-Checks $currentNorm.required_status_checks.checks }
  $desChecksKeys = Key-Checks $desiredNorm.required_status_checks.checks
  $chkDiff = Set-Diff -Current $curChecksKeys -Desired $desChecksKeys

  $md.Add("### Required contexts")
  $md.Add("")
  $md.Add("- Add: $(($ctxDiff.add).Count)")
  if ($ctxDiff.add.Count -gt 0) { $md.Add("  - " + ($ctxDiff.add -join "`n  - ")) }
  $md.Add("- Remove: $(($ctxDiff.remove).Count)")
  if ($ctxDiff.remove.Count -gt 0) { $md.Add("  - " + ($ctxDiff.remove -join "`n  - ")) }
  $md.Add("")

  $md.Add("### Required checks objects (context + app_id)")
  $md.Add("")
  $md.Add("- Add: $(($chkDiff.add).Count)")
  if ($chkDiff.add.Count -gt 0) { $md.Add("  - " + ($chkDiff.add -join "`n  - ")) }
  $md.Add("- Remove: $(($chkDiff.remove).Count)")
  if ($chkDiff.remove.Count -gt 0) { $md.Add("  - " + ($chkDiff.remove -join "`n  - ")) }
  $md.Add("")

  $allDesiredContexts = @()
  $allDesiredContexts += @($desiredNorm.required_status_checks.contexts)
  $allDesiredContexts += @($desiredNorm.required_status_checks.checks | ForEach-Object { $_.context })
  $allDesiredContexts = @($allDesiredContexts | Where-Object { ($_ ?? '').Trim() -ne '' } | ForEach-Object { $_.Trim() } | Sort-Object -Unique)
  $recAllow = Build-RecommendedAllowlistRegex -Contexts $allDesiredContexts

  $md.Add('### Recommended allowlist_regex')
  $md.Add('')
  if ($recAllow.Count -eq 0) {
    $md.Add('*(none)*')
  } else {
    $csv = ($recAllow -join ',')
    $md.Add('Paste into workflow input **allowlist_regex** (comma-separated):')
    $md.Add('')
    $md.Add('`' + $csv + '`')
    $md.Add('')
    foreach ($r in $recAllow) { $md.Add('- `' + $r + '`') }
  }
  $md.Add('')

  $diffReport += [pscustomobject]@{
    branch = $branch
    endpoint = $endpoint
    current_exists = [bool]($null -ne $currentNorm)
    fields = $rows
    contexts = $ctxDiff
    checks_objects = $chkDiff
    recommended_allowlist_regex = $recAllow
    recommended_allowlist_regex_csv = ($recAllow -join ',')
  }
}

$mdText = ($md -join "`n")
$mdText | Set-Content -Encoding UTF8 $OutMarkdown
$diffReport | ConvertTo-Json -Depth 200 | Set-Content -Encoding UTF8 $OutJson

Write-Host "📄 Wrote: $OutMarkdown"
Write-Host "📄 Wrote: $OutJson"