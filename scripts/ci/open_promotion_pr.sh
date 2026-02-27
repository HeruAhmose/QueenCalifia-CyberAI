#!/usr/bin/env sh
set -eu

BASE="production"
HEAD="staging"

if gh pr list --base "$BASE" --head "$HEAD" --state open --json number --jq 'length' | grep -q '^[1-9]'; then
  echo "✅ Promotion PR already open: $HEAD -> $BASE"
  exit 0
fi

TITLE="chore(release): promote staging -> production"
BODY="Automated promotion PR.

- Source: staging
- Target: production

Merging this PR triggers Argo CD auto-sync on production."
gh pr create --base "$BASE" --head "$HEAD" --title "$TITLE" --body "$BODY"
echo "✅ Opened promotion PR: $HEAD -> $BASE"
