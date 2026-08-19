#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

ADMIN_CIDR="${QC_ADMIN_CIDR:-}"
[[ -n "$ADMIN_CIDR" ]] || { echo "QC_ADMIN_CIDR is required (private LAN/VPN CIDR allowed to SSH)." >&2; exit 2; }
python3 - "$ADMIN_CIDR" <<'PY'
import ipaddress, sys
net = ipaddress.ip_network(sys.argv[1], strict=False)
if not net.is_private:
    raise SystemExit("QC_ADMIN_CIDR must be a private network; refusing public SSH allow rule")
print(f"admin network accepted: {net}")
PY

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl git jq openssl age ufw fail2ban unattended-upgrades \
  docker.io docker-compose-v2

systemctl enable --now docker
systemctl enable --now fail2ban
systemctl enable --now unattended-upgrades

ROOT="${QC_EDGE_STATE_ROOT:-/srv/queen-califia}"
install -d -m 0750 -o root -g root "$ROOT"
for dir in app app/cutover app/legacy backups evidence valkey pki; do
  install -d -m 0750 -o root -g root "$ROOT/$dir"
done
install -d -m 0755 -o root -g root "$ROOT/pki/valkey"
chown -R 10001:10001 "$ROOT/app" "$ROOT/valkey"

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow from "$ADMIN_CIDR" to any port 22 proto tcp
ufw --force enable

cat >/etc/sysctl.d/99-queen-califia-edge.conf <<'EOF'
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.tcp_syncookies=1
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
fs.protected_hardlinks=1
fs.protected_symlinks=1
vm.overcommit_memory=1
EOF
sysctl --system >/dev/null

cat >/etc/fail2ban/jail.d/queen-califia-sshd.local <<'EOF'
[sshd]
enabled = true
bantime = 1h
findtime = 10m
maxretry = 5
EOF
systemctl restart fail2ban

# The runtime authorization marker is deliberately never created by bootstrap.
test ! -e "$ROOT/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED"

echo "Sovereign Edge host bootstrap complete."
echo "Inbound firewall: DENY by default; SSH allowed only from $ADMIN_CIDR; no HTTP/HTTPS/Valkey/PostgreSQL host ports opened."
echo "Valkey host prerequisite applied: vm.overcommit_memory=1."
echo "Before production candidacy: verify full-disk encryption, BIOS restore-after-power-loss, UPS behavior, and Cloudflare Tunnel egress on TCP/UDP 7844."
