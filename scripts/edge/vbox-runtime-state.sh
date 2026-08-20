#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="${QC_EDGE_REPO_ROOT:-/opt/queen-califia}"
exec "$REPO_ROOT/scripts/edge/runtime-state.sh" "$@"
