#!/usr/bin/env bash
set -euo pipefail

STATE="${1:-UNKNOWN}"
DETAIL="${2:-}"
REPO_ROOT="${QC_EDGE_REPO_ROOT:-/opt/queen-califia}"
PREFIX="/QueenCalifia/SovereignEdge"

case "$STATE" in
  STARTING|READY|BLOCKED|FAILED|STOPPING|STOPPED|DEGRADED) ;;
  *)
    echo "invalid Queen Califia runtime state: $STATE" >&2
    exit 2
    ;;
esac

printf 'QC_EDGE_STATE=%s\n' "$STATE"
[[ -z "$DETAIL" ]] || printf 'QC_EDGE_DETAIL=%s\n' "$DETAIL"

# Runtime state publication is observability only. It must never become an
# authorization or availability dependency. Publish VirtualBox guest properties
# only when VirtualBox is the active hypervisor; stale VBox binaries on another
# hypervisor are explicitly ignored.
virt="$(systemd-detect-virt -v 2>/dev/null || true)"
[[ "$virt" == "oracle" ]] || exit 0
command -v VBoxControl >/dev/null 2>&1 || exit 0

set_prop() {
  local key="$1"
  local value="$2"
  VBoxControl guestproperty set "$key" "$value" >/dev/null 2>&1 || true
}

updated_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
updated_epoch="$(date -u +%s)"
boot_id="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || printf unknown)"
git_head="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || printf unknown)"

set_prop "$PREFIX/ControlPlane" "systemd-v1"
set_prop "$PREFIX/State" "$STATE"
set_prop "$PREFIX/Detail" "$DETAIL"
set_prop "$PREFIX/UpdatedUTC" "$updated_utc"
set_prop "$PREFIX/UpdatedEpoch" "$updated_epoch"
set_prop "$PREFIX/BootId" "$boot_id"
set_prop "$PREFIX/GitHead" "$git_head"
