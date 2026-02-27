#!/usr/bin/env sh
set -eu

DOMAIN="${QC_DOMAIN:-${1:-}}"
EMAIL="${QC_EMAIL:-}"

if [ -z "${DOMAIN:-}" ] || [ -z "${EMAIL:-}" ]; then
  echo "Missing QC_DOMAIN and/or QC_EMAIL. Set them in .env and re-run with --profile acme." >&2
  exit 2
fi

WEBROOT="/var/www/certbot"
STAGING="${QC_LETSENCRYPT_STAGING:-0}"
RENEW_INTERVAL="${QC_CERTBOT_RENEW_INTERVAL_SECONDS:-43200}"
RSA_KEY_SIZE="${QC_CERTBOT_RSA_KEY_SIZE:-4096}"

SERVER_ARGS=""
if [ "$STAGING" = "1" ]; then
  SERVER_ARGS="--staging"
fi

mkdir -p "$WEBROOT"

issue_if_missing() {
  if [ ! -s "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ] || [ ! -s "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" ]; then
    echo "[certbot] Issuing certificate for ${DOMAIN}"
    certbot certonly --webroot -w "$WEBROOT"       $SERVER_ARGS       --email "$EMAIL" --agree-tos --no-eff-email       -d "$DOMAIN"       --rsa-key-size "$RSA_KEY_SIZE"       --non-interactive
  fi
}

deploy() {
  /bin/sh /opt/certbot/deploy-hook.sh "$DOMAIN"
}

issue_if_missing
deploy

echo "[certbot] Starting renew loop (every ${RENEW_INTERVAL}s)"
while :; do
  certbot renew --webroot -w "$WEBROOT"     --deploy-hook "/bin/sh /opt/certbot/deploy-hook.sh ${DOMAIN}"     --quiet || true
  sleep "$RENEW_INTERVAL"
done
