#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Update a repo from a zip/folder drop-in, safely (refuse gitlinks/submodules), then branch+commit+push+PR.

.DESCRIPTION
  - Refuses sources that contain nested ".git" directories or a ".gitmodules" file.
  - Refuses to proceed if the repo index contains any gitlinks (mode 160000) after overlay.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

param(
  [Parameter(Mandatory=$true)] [string] $RepoPath,
  [Parameter(Mandatory=$true)] [string] $Source,
  [string] $Branch = "chore/qc-update",
  [string] $CommitMessage = "Update from patch bundle",
  [switch] $OpenPR,
  [switch] $NoVerifyPush,
  [switch] $AllowDirty,
  [string] $Remote = "origin"
)

function Assert-Cmd([string] $Name) {
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) { throw "Missing dependency: $Name" }
}

function Exec([string] $File, [string[]] $Args) {
  $p = Start-Process -FilePath $File -ArgumentList $Args -NoNewWindow -Wait -PassThru
  if ($p.ExitCode -ne 0) { throw "Command failed ($File): $($Args -join ' ')" }
}

function Resolve-SourceRoot([string] $Path) {
  if (-not (Test-Path $Path)) { throw "Source not found: $Path" }
  if ($Path.ToLower().EndsWith(".zip")) {
    $tmp = Join-Path $env:TEMP ("qc_patch_" + [Guid]::NewGuid().ToString("n"))
    New-Item -ItemType Directory -Force $tmp | Out-Null
    Expand-Archive -Path $Path -DestinationPath $tmp -Force
    return $tmp
  }
  return (Resolve-Path $Path).Path
}

function Pick-ContentRoot([string] $Root) {
  $children = Get-ChildItem -LiteralPath $Root -Force
  $dirs = @($children | Where-Object { $_.PSIsContainer })
  if ($dirs.Count -eq 1) {
    $cand = $dirs[0].FullName
    foreach ($m in @(".github","helm","k8s","scripts","docs")) {
      if (Test-Path (Join-Path $cand $m)) { return $cand }
    }
  }
  return $Root
}

function Assert-NoEmbeddedReposOrSubmodules([string] $Root) {
  if (Test-Path (Join-Path $Root ".gitmodules")) {
    throw "Refusing: source contains .gitmodules (submodule config). Remove it and retry."
  }
  $gitDirs = @(Get-ChildItem -LiteralPath $Root -Directory -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -ieq ".git" })
  if ($gitDirs.Count -gt 0) {
    $sample = ($gitDirs | Select-Object -First 5 | ForEach-Object { $_.FullName }) -join "`n"
    throw "Refusing: source contains nested .git directories (embedded repo). Examples:`n$sample"
  }
}

function Copy-Overlay([string] $From, [string] $To) {
  $items = Get-ChildItem -LiteralPath $From -Force
  $robocopy = Get-Command robocopy -ErrorAction SilentlyContinue
  foreach ($it in $items) {
    if ($it.Name -eq ".git") { continue }

    if ($it.PSIsContainer) {
      if (Test-Path (Join-Path $it.FullName ".git")) { throw "Refusing: embedded repo folder: $($it.FullName)" }
      $dstDir = Join-Path $To $it.Name
      New-Item -ItemType Directory -Force $dstDir | Out-Null
      if ($robocopy) {
        $null = & robocopy $it.FullName $dstDir /E /XO /R:2 /W:1 /NFL /NDL /NJH /NJS /NP /XD ".git"
      } else {
        Copy-Item -LiteralPath $it.FullName -Destination $dstDir -Recurse -Force
      }
    } else {
      if ($it.Name -ieq ".gitmodules") { throw "Refusing: source contains .gitmodules." }
      Copy-Item -LiteralPath $it.FullName -Destination (Join-Path $To $it.Name) -Force
    }
  }
}

function Assert-RepoHasNoGitlinksOrSubmodules() {
  $lines = git ls-files --stage
  $gitlinks = @($lines | Select-String -Pattern '^\s*160000\s' -AllMatches | ForEach-Object { $_.Line })
  if ($gitlinks.Count -gt 0) {
    $gitlinks | ForEach-Object { Write-Host $_ }
    throw "Refusing: repo index contains gitlinks/submodules (mode 160000). Remove them and retry."
  }
  if (Test-Path ".gitmodules") { throw "Refusing: repo contains .gitmodules. Remove it and retry." }
}

Assert-Cmd git
Assert-Cmd gh

$repo = (Resolve-Path $RepoPath).Path
Push-Location $repo
try {
  if (-not $AllowDirty) {
    $dirty = git status --porcelain
    if ($dirty) { throw "Repo has uncommitted changes. Commit/stash first, or rerun with -AllowDirty." }
  }

  $zipCandidate = if (Test-Path $Source) { $Source } elseif (Test-Path ($Source + ".zip")) { $Source + ".zip" } else { $null }
  if (-not $zipCandidate) { throw "Source not found: $Source (or $Source.zip)" }

  $srcExtracted = Resolve-SourceRoot $zipCandidate
  $srcRoot = Pick-ContentRoot $srcExtracted

  Assert-NoEmbeddedReposOrSubmodules $srcRoot

  Exec git @("checkout","-B",$Branch)
  Copy-Overlay -From $srcRoot -To $repo

  Assert-RepoHasNoGitlinksOrSubmodules
  Exec git @("add","-A")
  Assert-RepoHasNoGitlinksOrSubmodules

  $status = git status --porcelain
  if (-not $status) { Write-Host "Nothing to commit."; return }

  Exec git @("commit","-m",$CommitMessage)

  $pushArgs = @("push","-u",$Remote,$Branch)
  if ($NoVerifyPush) { $pushArgs += "--no-verify" }
  Exec git $pushArgs

  if ($OpenPR) { Exec gh @("pr","create","--fill","--head",$Branch) }

  Write-Host "✅ Done."
} finally {
  Pop-Location
}
