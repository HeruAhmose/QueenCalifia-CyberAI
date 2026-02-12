#!/usr/bin/env bash
set -euo pipefail

branch="${GITHUB_REF_NAME:-}"
base="${BASE_BRANCH:-main}"

if [[ -z "$branch" ]]; then
  echo "GITHUB_REF_NAME is empty; nothing to do." >&2
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI (gh) is required in this workflow." >&2
  exit 1
fi

# If an open PR already exists for this head branch, do nothing.
existing="$(gh pr list --state open --head "$branch" --base "$base" --json number --jq '.[0].number' || true)"
if [[ -n "${existing:-}" && "${existing:-null}" != "null" ]]; then
  echo "PR already open for branch '$branch' -> '$base' (#$existing)."
  exit 0
fi

title="chore(image-updater): update images"
body=$'Automated image tag update from Argo CD Image Updater.

- Head: '"$branch"$'
- Base: '"$base"$'

Review & merge to promote.'

gh pr create --head "$branch" --base "$base" --title "$title" --body "$body"
echo "Opened PR for '$branch' -> '$base'."
