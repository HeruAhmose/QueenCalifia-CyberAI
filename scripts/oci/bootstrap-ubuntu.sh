#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl git jq openssl age ufw fail2ban unattended-upgrades \
  docker.io docker-compose-v2

systemctl enable --now docker
systemctl enable --now fail2ban
systemctl enable --now unattended-upgrades

install -d -m 0750 -o root -g root /srv/queen-califia
for dir in postgres redis app app/cutover app/legacy backups caddy caddy/data caddy/config; do
  install -d -m 0750 -o root -g root "/srv/queen-califia/${dir}"
done

# Container UIDs: postgres=999 in the official image, Redis commonly 999,
# Queen Califia application=10001. Ownership is intentionally explicit.
chown -R 999:999 /srv/queen-califia/postgres /srv/queen-califia/redis
chown -R 10001:10001 /srv/queen-califia/app

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw limit 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

cat >/etc/sysctl.d/99-queen-califia.conf <<'EOF'
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
EOF
sysctl --system >/dev/null

echo "OCI host bootstrap complete."
echo "IMPORTANT: also restrict the OCI VCN ingress rules to TCP 22, 80 and 443; host UFW does not replace cloud firewall policy."
echo "Runtime authorization marker was NOT created. PostgreSQL/Redis may be staged, but API/worker remain fail-closed."
