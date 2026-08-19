#!/usr/bin/env bash
set -euo pipefail

if [[ "${QC_EDGE_RUNTIME_GATE:-0}" == "1" ]]; then
  gate="${QC_EDGE_RUNTIME_GATE_FILE:-/var/lib/queen-califia/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED}"
  [[ -f "$gate" ]] || { echo "Sovereign Edge runtime gate is closed: $gate missing" >&2; exit 78; }
  [[ "$(tr -d '\r\n' < "$gate")" == "AUTHORIZED" ]] || { echo "Sovereign Edge runtime gate is closed: invalid authorization marker" >&2; exit 78; }
  python /opt/queen-califia/scripts/edge/validate-runtime-env.py
fi

exec "$@"
