#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="${QC_EDGE_REPO_ROOT:-/opt/queen-califia}"
case "${SSH_ORIGINAL_COMMAND:-}" in
  ACTIVATE|STATUS|STOP|RESTART)
    exec sudo -n "$REPO_ROOT/scripts/edge/hyperv-control-root.sh" "$SSH_ORIGINAL_COMMAND"
    ;;
  *)
    echo "Queen Califia Hyper-V control key permits only ACTIVATE, STATUS, STOP, or RESTART." >&2
    exit 2
    ;;
esac
