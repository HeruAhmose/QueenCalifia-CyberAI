#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${QC_EDGE_REPO_ROOT:-/opt/queen-califia}"
STATE_ROOT="${QC_EDGE_STATE_ROOT:-/srv/queen-califia}"
RUNTIME_UNIT="queen-califia-edge.service"
AUTH_MARKER="$STATE_ROOT/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED"
ACTION="${1:-}"

[[ "${EUID}" -eq 0 ]] || { echo "root control required" >&2; exit 1; }
[[ "$(systemd-detect-virt -v 2>/dev/null || true)" == "microsoft" ]] || {
  echo "HYPERV_CONTROL=NOT_APPLICABLE" >&2
  exit 2
}

print_status() {
  printf 'CONTROL_PLANE=systemd-hyperv-v1\n'
  if [[ ! -f "$AUTH_MARKER" || "$(tr -d '\r\n' < "$AUTH_MARKER" 2>/dev/null || true)" != "AUTHORIZED" ]]; then
    printf 'QUEEN_CALIFIA=BLOCKED\n'
    printf 'DETAIL=runtime authorization gate is closed\n'
    return 78
  fi
  if "$REPO_ROOT/scripts/edge/activate-runtime.sh" status >/dev/null 2>&1; then
    printf 'QUEEN_CALIFIA=READY\n'
    return 0
  fi
  case "$(systemctl is-active "$RUNTIME_UNIT" 2>/dev/null || true)" in
    failed) printf 'QUEEN_CALIFIA=FAILED\n' ;;
    activating) printf 'QUEEN_CALIFIA=STARTING\n' ;;
    *) printf 'QUEEN_CALIFIA=DEGRADED\n' ;;
  esac
  return 1
}

case "$ACTION" in
  STATUS) print_status ;;
  ACTIVATE)
    if [[ ! -f "$AUTH_MARKER" || "$(tr -d '\r\n' < "$AUTH_MARKER" 2>/dev/null || true)" != "AUTHORIZED" ]]; then
      printf 'CONTROL_PLANE=systemd-hyperv-v1\nQUEEN_CALIFIA=BLOCKED\nDETAIL=runtime authorization gate is closed\n'
      exit 78
    fi
    systemctl reset-failed "$RUNTIME_UNIT" >/dev/null 2>&1 || true
    systemctl start "$RUNTIME_UNIT"
    print_status
    ;;
  STOP)
    if systemctl is-active --quiet "$RUNTIME_UNIT"; then
      systemctl stop "$RUNTIME_UNIT"
    else
      "$REPO_ROOT/scripts/edge/activate-runtime.sh" stop
    fi
    printf 'CONTROL_PLANE=systemd-hyperv-v1\nQUEEN_CALIFIA=STOPPED\n'
    ;;
  RESTART)
    if [[ ! -f "$AUTH_MARKER" || "$(tr -d '\r\n' < "$AUTH_MARKER" 2>/dev/null || true)" != "AUTHORIZED" ]]; then
      printf 'CONTROL_PLANE=systemd-hyperv-v1\nQUEEN_CALIFIA=BLOCKED\nDETAIL=runtime authorization gate is closed\n'
      exit 78
    fi
    systemctl reset-failed "$RUNTIME_UNIT" >/dev/null 2>&1 || true
    systemctl restart "$RUNTIME_UNIT"
    print_status
    ;;
  *) echo "usage: hyperv-control-root.sh {ACTIVATE|STATUS|STOP|RESTART}" >&2; exit 2 ;;
esac
