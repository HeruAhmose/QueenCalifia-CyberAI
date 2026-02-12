#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <version>"
  exit 2
fi

VERSION="$1"
python scripts/release/sync_versions.py "${VERSION}"
