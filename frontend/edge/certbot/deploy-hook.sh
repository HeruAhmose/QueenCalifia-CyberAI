#!/usr/bin/env sh
set -eu

DOMAIN="${1:-${QC_DOMAIN:-}}"
if [ -z "${DOMAIN:-}" ]; then
  echo "deploy-hook: missing domain" >&2
  exit 2
fi

SRC_DIR="/etc/letsencrypt/live/${DOMAIN}"
DST_DIR="/etc/nginx/certs"

mkdir -p "$DST_DIR"

if [ ! -s "${SRC_DIR}/fullchain.pem" ] || [ ! -s "${SRC_DIR}/privkey.pem" ]; then
  echo "[certbot] No cert material found for ${DOMAIN} in ${SRC_DIR}" >&2
  exit 0
fi

cp "${SRC_DIR}/fullchain.pem" "${DST_DIR}/fullchain.pem"
cp "${SRC_DIR}/privkey.pem" "${DST_DIR}/privkey.pem"

chmod 0644 "${DST_DIR}/fullchain.pem" || true
chmod 0600 "${DST_DIR}/privkey.pem" || true

echo "[certbot] Deployed cert for ${DOMAIN} -> ${DST_DIR}"
