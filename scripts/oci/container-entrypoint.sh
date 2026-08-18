#!/usr/bin/env bash
set -euo pipefail

if [[ "${QC_OCI_RUNTIME_GATE:-0}" == "1" ]]; then
  gate="${QC_OCI_RUNTIME_GATE_FILE:-/var/lib/queen-califia/cutover/OCI_RUNTIME_AUTHORIZED}"
  [[ -f "$gate" ]] || { echo "OCI runtime gate is closed: $gate missing" >&2; exit 78; }
  [[ "$(tr -d '\r\n' < "$gate")" == "AUTHORIZED" ]] || { echo "OCI runtime gate is closed: invalid authorization marker" >&2; exit 78; }
  case "${QC_DATABASE_URL:-${DATABASE_URL:-}}" in
    postgresql://*|postgres://*) ;;
    *) echo "OCI runtime requires PostgreSQL authority" >&2; exit 78 ;;
  esac
fi

exec "$@"
