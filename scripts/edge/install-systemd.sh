#!/usr/bin/env bash
set -euo pipefail

[[ "${EUID}" -eq 0 ]] || { echo "Run as root (sudo)." >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CANONICAL_ROOT="/opt/queen-califia"

if [[ "$REPO_ROOT" != "$CANONICAL_ROOT" ]]; then
  echo "Sovereign Edge boot services require the canonical repository path: $CANONICAL_ROOT" >&2
  echo "Current repository path: $REPO_ROOT" >&2
  exit 2
fi

for file in \
  queen-califia-edge.service \
  queen-califia-edge-command.service \
  queen-califia-edge-command.timer \
  queen-califia-edge-watchdog.service \
  queen-califia-edge-watchdog.timer; do
  src="$REPO_ROOT/deploy/edge/systemd/$file"
  [[ -f "$src" ]] || { echo "missing systemd unit: $src" >&2; exit 2; }
  install -m 0644 "$src" "/etc/systemd/system/$file"
done

for script in \
  scripts/edge/activate-runtime.sh \
  scripts/edge/command-dispatch.sh \
  scripts/edge/vbox-runtime-state.sh; do
  chmod 0755 "$REPO_ROOT/$script"
done

systemctl daemon-reload
systemctl enable queen-califia-edge.service
systemctl enable --now queen-califia-edge-watchdog.timer

if command -v VBoxControl >/dev/null 2>&1; then
  systemctl enable --now queen-califia-edge-command.timer
  "$REPO_ROOT/scripts/edge/activate-runtime.sh" status >/dev/null 2>&1 || true
  systemctl is-active queen-califia-edge-command.timer >/dev/null
  echo "VIRTUALBOX_HOST_CONTROL=ENABLED"
else
  systemctl disable --now queen-califia-edge-command.timer >/dev/null 2>&1 || true
  echo "VIRTUALBOX_HOST_CONTROL=NOT_APPLICABLE"
fi

systemctl is-enabled queen-califia-edge.service >/dev/null
systemctl is-active queen-califia-edge-watchdog.timer >/dev/null

echo "QC_EDGE_SYSTEMD_INSTALL=PASS"
echo "The runtime service is enabled for boot and remains fail-closed until the existing authorization marker contains AUTHORIZED."
