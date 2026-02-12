# Branch protection (staging + production)

This repo is designed for **PR-only** changes to environment branches.

## One-command setup (recommended)

Requirements:
- GitHub CLI (`gh`)
- Authenticated: `gh auth login` (or `GH_TOKEN` env var with repo admin perms)

From repo root:

```powershell
pwsh ./scripts/github/protect_branches.ps1 -Owner "YOURORG" -Repo "QueenCalifia-CyberAI" -AutoDetectStatusChecks
```

What this does:
- Require PRs + **2 approvals**
- Require **Code Owner** reviews
- Require **conversation resolution**
- Require **linear history**
- Block force-push + delete
- **Auto-detect required check contexts** from `staging` + `production` HEAD commits (no copy/paste)

Optional filtering (regex, case-insensitive):

```powershell
pwsh ./scripts/github/protect_branches.ps1 -AutoDetectStatusChecks `
  -AllowlistRegex '^ci\s*/','^argocd' `
  -DenylistRegex 'codecov'
```

## Find the exact check context strings

### Local
```powershell
pwsh ./scripts/github/print_check_contexts.ps1 -Branches staging,production -OutText artifacts/check-contexts.txt
```

### GitHub Action (no local setup)
Actions → **Print check contexts (artifact)** → Run workflow  
Downloads:
- `artifacts/check-contexts.txt`
- `artifacts/check-contexts.json`

## One-click GitHub Action

Actions → **Protect branches (one click)** → Run workflow

Required secret:
- `GH_TOKEN`: a PAT or fine-grained token with **repo admin** permission (branch protection write)

Recommended settings:
- `auto_detect_checks=true` (default)
- optionally set allow/deny regex to keep the “must-pass” list tight

## Dry-run review (artifact)

Actions → **Protect branches (dry run)** → Run workflow

Downloads:
- `branch-protection-payload.json` (exact REST payload(s) per branch)


## Avoid requiring external integrations

If auto-detect sees checks from third-party GitHub Apps and you don't want those to be required:

```powershell
pwsh ./scripts/github/protect_branches.ps1 -AutoDetectStatusChecks `
  -ExcludeAppSlugs 'dependabot','some-external-app'
```

## Prefer `checks` objects (context + app_id)

By default the script will populate `required_status_checks.checks` (when possible) to avoid name
collisions across apps, while keeping `contexts` limited to non-check-run contexts.

Disable if you only want legacy `contexts`:

```powershell
pwsh ./scripts/github/protect_branches.ps1 -AutoDetectStatusChecks -UseChecksObjects:$false
```
