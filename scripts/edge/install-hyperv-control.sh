#!/usr/bin/env bash
set -euo pipefail

[[ "${EUID}" -eq 0 ]] || { echo "Run as root (sudo)." >&2; exit 1; }
REPO_ROOT="${QC_EDGE_REPO_ROOT:-/opt/queen-califia}"
CONTROL_USER="${QC_HYPERV_CONTROL_USER:-qcadmin}"
PUBLIC_KEY="${1:-}"

[[ "$(systemd-detect-virt -v 2>/dev/null || true)" == "microsoft" ]] || {
  echo "Hyper-V control installation requires the Microsoft hypervisor." >&2
  exit 2
}
[[ "$PUBLIC_KEY" =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/=]+([[:space:]].*)?$ ]] || {
  echo "Expected one ssh-ed25519 public key argument." >&2
  exit 2
}
getent passwd "$CONTROL_USER" >/dev/null || { echo "missing control user: $CONTROL_USER" >&2; exit 2; }

chmod 0755 "$REPO_ROOT/scripts/edge/hyperv-control.sh" "$REPO_ROOT/scripts/edge/hyperv-control-root.sh"

home="$(getent passwd "$CONTROL_USER" | cut -d: -f6)"
ssh_dir="$home/.ssh"
auth_keys="$ssh_dir/authorized_keys"
install -d -m 0700 -o "$CONTROL_USER" -g "$CONTROL_USER" "$ssh_dir"
touch "$auth_keys"
chown "$CONTROL_USER:$CONTROL_USER" "$auth_keys"
chmod 0600 "$auth_keys"

marker='queen-califia-hyperv-control'
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
grep -v "$marker" "$auth_keys" >"$tmp" || true
printf 'restrict,command="%s/scripts/edge/hyperv-control.sh" %s %s\n' "$REPO_ROOT" "$PUBLIC_KEY" "$marker" >>"$tmp"
install -m 0600 -o "$CONTROL_USER" -g "$CONTROL_USER" "$tmp" "$auth_keys"

sudoers="/etc/sudoers.d/queen-califia-hyperv-control"
cat >"$sudoers" <<EOF2
$CONTROL_USER ALL=(root) NOPASSWD: $REPO_ROOT/scripts/edge/hyperv-control-root.sh ACTIVATE
$CONTROL_USER ALL=(root) NOPASSWD: $REPO_ROOT/scripts/edge/hyperv-control-root.sh STATUS
$CONTROL_USER ALL=(root) NOPASSWD: $REPO_ROOT/scripts/edge/hyperv-control-root.sh STOP
$CONTROL_USER ALL=(root) NOPASSWD: $REPO_ROOT/scripts/edge/hyperv-control-root.sh RESTART
EOF2
chmod 0440 "$sudoers"
visudo -cf "$sudoers" >/dev/null

echo "HYPERV_CONTROL_INSTALL=PASS"
echo "The control key is restricted to four forced commands and cannot create or modify the production authorization marker."
