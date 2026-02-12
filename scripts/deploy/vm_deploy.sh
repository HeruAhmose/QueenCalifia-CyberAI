#!/usr/bin/env bash
set -euo pipefail

# One-click-ish deploy to a single Linux VM over SSH.
# Expects env:
#   DEPLOY_HOST, DEPLOY_USER, DEPLOY_SSH_KEY, DEPLOY_SSH_PORT(optional)
#   QC_DOMAIN, QC_EMAIL
#   QC_API_KEY_PEPPER, QC_AUDIT_HMAC_KEY
# Optional:
#   DEPLOY_REF (git ref), QC_ACME (0/1), QC_HTTP_PORT, QC_HTTPS_PORT
#
# Notes:
# - Assumes Ubuntu/Debian-like host. Installs Docker if missing.
# - Uses docker compose edge stack (docker-compose.prod.edge.yml).

DEPLOY_SSH_PORT="${DEPLOY_SSH_PORT:-22}"
DEPLOY_REF="${DEPLOY_REF:-main}"
QC_ACME="${QC_ACME:-1}"
QC_HTTP_PORT="${QC_HTTP_PORT:-80}"
QC_HTTPS_PORT="${QC_HTTPS_PORT:-443}"

required=(
  DEPLOY_HOST DEPLOY_USER DEPLOY_SSH_KEY
  QC_DOMAIN QC_EMAIL QC_API_KEY_PEPPER QC_AUDIT_HMAC_KEY
)
for v in "${required[@]}"; do
  if [[ -z "${!v:-}" ]]; then
    echo "ERROR: missing env var: $v" >&2
    exit 2
  fi
done

SSH="ssh -i "$DEPLOY_SSH_KEY" -p "$DEPLOY_SSH_PORT" -o StrictHostKeyChecking=accept-new"
SCP="scp -i "$DEPLOY_SSH_KEY" -P "$DEPLOY_SSH_PORT" -o StrictHostKeyChecking=accept-new"

REMOTE_DIR="/opt/queen-califia"
REMOTE_ENV="$REMOTE_DIR/.env"

echo "==> Connecting to ${DEPLOY_USER}@${DEPLOY_HOST}:${DEPLOY_SSH_PORT}"
eval $SSH "$DEPLOY_USER@$DEPLOY_HOST" "echo 'connected'"

echo "==> Preparing host (docker, git, folder)"
eval $SSH "$DEPLOY_USER@$DEPLOY_HOST" "sudo mkdir -p '$REMOTE_DIR' && sudo chown -R $DEPLOY_USER:$DEPLOY_USER '$REMOTE_DIR'"

# Install docker if missing
eval $SSH "$DEPLOY_USER@$DEPLOY_HOST" "command -v docker >/dev/null 2>&1 || (curl -fsSL https://get.docker.com | sudo sh)"
# Ensure compose plugin
eval $SSH "$DEPLOY_USER@$DEPLOY_HOST" "docker compose version >/dev/null 2>&1 || sudo apt-get update -y && sudo apt-get install -y docker-compose-plugin"

# Get/Update repo
eval $SSH "$DEPLOY_USER@$DEPLOY_HOST" "cd '$REMOTE_DIR' &&   if [[ ! -d .git ]]; then     git init && git remote add origin https://github.com/${GITHUB_REPOSITORY:-HeruAhmose/QueenCalifia-CyberAI}.git;   fi &&   git fetch --all --tags && git checkout -f '$DEPLOY_REF' && git reset --hard 'origin/$DEPLOY_REF' 2>/dev/null || true"

# Render .env locally then upload
tmpenv="$(mktemp)"
cat >"$tmpenv"<<EOF
QC_DOMAIN=${QC_DOMAIN}
QC_EMAIL=${QC_EMAIL}
QC_HTTP_PORT=${QC_HTTP_PORT}
QC_HTTPS_PORT=${QC_HTTPS_PORT}

QC_API_KEY_PEPPER=${QC_API_KEY_PEPPER}
QC_AUDIT_HMAC_KEY=${QC_AUDIT_HMAC_KEY}

# Set to 1 only for first bootstrap if you need to generate keys.json for compose.
QC_ALLOW_INSECURE_BOOTSTRAP=${QC_ALLOW_INSECURE_BOOTSTRAP:-0}

# Safe-by-default scanning
QC_DENY_PUBLIC_TARGETS=${QC_DENY_PUBLIC_TARGETS:-1}
QC_SCAN_ALLOWLIST=${QC_SCAN_ALLOWLIST:-10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8}

# Optional CORS
QC_CORS_ORIGINS=${QC_CORS_ORIGINS:-}

# Proxy chain trust (Ingress/LB). Usually 1, sometimes 2.
QC_PROXY_TRUSTED_HOPS=${QC_PROXY_TRUSTED_HOPS:-1}
EOF

echo "==> Uploading .env"
eval $SCP "$tmpenv" "$DEPLOY_USER@$DEPLOY_HOST:$REMOTE_ENV"
rm -f "$tmpenv"
eval $SSH "$DEPLOY_USER@$DEPLOY_HOST" "chmod 600 '$REMOTE_ENV'"

echo "==> Starting stack"
profile=""
if [[ "$QC_ACME" == "1" ]]; then
  profile="--profile acme"
fi

eval $SSH "$DEPLOY_USER@$DEPLOY_HOST" "cd '$REMOTE_DIR' && sudo docker compose -f docker-compose.prod.edge.yml $profile up -d --build"

echo "==> Status"
eval $SSH "$DEPLOY_USER@$DEPLOY_HOST" "cd '$REMOTE_DIR' && sudo docker compose -f docker-compose.prod.edge.yml ps"

echo "==> Done."
echo "Next: run preflight from your machine:"
echo "  QC_DOMAIN=$QC_DOMAIN QC_HTTP_PORT=$QC_HTTP_PORT QC_HTTPS_PORT=$QC_HTTPS_PORT ./scripts/preflight_prod.sh"
