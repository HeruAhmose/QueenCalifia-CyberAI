#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${QC_EDGE_REPO_ROOT:-/opt/queen-califia}"
COMMAND_KEY="/QueenCalifia/SovereignEdge/Command"
ACK_KEY="/QueenCalifia/SovereignEdge/CommandAck"
RUNTIME_UNIT="queen-califia-edge.service"
RUN_DIR="/run/queen-califia-edge"
LAST_FILE="$RUN_DIR/last-command"
STATE_HELPER="$REPO_ROOT/scripts/edge/vbox-runtime-state.sh"

[[ "${EUID}" -eq 0 ]] || exit 1
command -v VBoxControl >/dev/null 2>&1 || exit 0
mkdir -p "$RUN_DIR"
chmod 0700 "$RUN_DIR"

raw="$(VBoxControl guestproperty enumerate --patterns "$COMMAND_KEY" 2>/dev/null || true)"
value="$(printf '%s\n' "$raw" | sed -n 's/^Name: [^,]*, value: \([^,]*\), timestamp:.*$/\1/p' | head -n 1)"
[[ -n "$value" ]] || exit 0

if [[ ! "$value" =~ ^(ACTIVATE|STOP|RESTART|STATUS)\|([0-9A-Fa-f-]{36})$ ]]; then
  exit 0
fi

verb="${BASH_REMATCH[1]}"
nonce="${BASH_REMATCH[2]}"
last="$(cat "$LAST_FILE" 2>/dev/null || true)"
[[ "$last" != "$value" ]] || exit 0
printf '%s\n' "$value" >"$LAST_FILE"
chmod 0600 "$LAST_FILE"

rc=0
case "$verb" in
  ACTIVATE)
    unit_state="$(systemctl is-active "$RUNTIME_UNIT" 2>/dev/null || true)"
    case "$unit_state" in
      active)
        if ! "$REPO_ROOT/scripts/edge/activate-runtime.sh" status >/dev/null 2>&1; then
          systemctl restart "$RUNTIME_UNIT" || rc=$?
        fi
        ;;
      activating)
        rc=0
        ;;
      *)
        systemctl reset-failed "$RUNTIME_UNIT" >/dev/null 2>&1 || true
        systemctl start "$RUNTIME_UNIT" || rc=$?
        ;;
    esac
    ;;
  STOP)
    if systemctl is-active --quiet "$RUNTIME_UNIT"; then
      systemctl stop "$RUNTIME_UNIT" || rc=$?
    else
      "$REPO_ROOT/scripts/edge/activate-runtime.sh" stop || rc=$?
    fi
    ;;
  RESTART)
    systemctl reset-failed "$RUNTIME_UNIT" >/dev/null 2>&1 || true
    systemctl restart "$RUNTIME_UNIT" || rc=$?
    ;;
  STATUS)
    "$REPO_ROOT/scripts/edge/activate-runtime.sh" status || rc=$?
    ;;
esac

VBoxControl guestproperty set "$ACK_KEY" "$verb|$nonce|$rc" >/dev/null 2>&1 || true

if [[ "$rc" -ne 0 && "$rc" -ne 78 ]]; then
  "$STATE_HELPER" FAILED "host command $verb failed" >/dev/null 2>&1 || true
fi

# The dispatcher itself stays healthy; command success/failure is carried in the
# acknowledgement and runtime state so the polling timer is not poisoned by an
# intentionally fail-closed activation (for example, authorization rc=78).
exit 0
