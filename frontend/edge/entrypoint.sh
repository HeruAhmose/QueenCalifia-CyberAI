#!/usr/bin/env sh
set -eu

QC_HTTP_PORT="${QC_HTTP_PORT:-8080}"
QC_HTTPS_PORT="${QC_HTTPS_PORT:-8443}"
QC_API_UPSTREAM="${QC_API_UPSTREAM:-api:5000}"

QC_TLS_CN="${QC_TLS_CN:-localhost}"
QC_TLS_DAYS="${QC_TLS_DAYS:-3650}"
QC_CERT_RELOAD_INTERVAL_SECONDS="${QC_CERT_RELOAD_INTERVAL_SECONDS:-300}"

CERT_DIR="/etc/nginx/certs"
SRC_DIR="/secrets/tls"

CERT="${CERT_DIR}/fullchain.pem"
KEY="${CERT_DIR}/privkey.pem"

mkdir -p "$CERT_DIR" /var/www/certbot

if [ -s "${SRC_DIR}/fullchain.pem" ] && [ -s "${SRC_DIR}/privkey.pem" ]; then
  echo "[edge] Using mounted TLS certs from ${SRC_DIR}"
  cp "${SRC_DIR}/fullchain.pem" "$CERT"
  cp "${SRC_DIR}/privkey.pem" "$KEY"
fi

if [ ! -s "$CERT" ] || [ ! -s "$KEY" ]; then
  echo "[edge] TLS certs not found; generating self-signed cert (CN=${QC_TLS_CN})"
  cat > /tmp/openssl.cnf <<EOF
[ req ]
default_bits       = 2048
distinguished_name = req_distinguished_name
req_extensions     = v3_req
prompt             = no

[ req_distinguished_name ]
CN = ${QC_TLS_CN}

[ v3_req ]
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${QC_TLS_CN}
DNS.2 = localhost
IP.1  = 127.0.0.1
EOF

  openssl req -x509 -nodes -newkey rsa:2048     -keyout "$KEY"     -out "$CERT"     -days "$QC_TLS_DAYS"     -config /tmp/openssl.cnf     -extensions v3_req >/dev/null 2>&1
fi

export QC_HTTP_PORT QC_HTTPS_PORT QC_API_UPSTREAM
envsubst '${QC_HTTP_PORT} ${QC_HTTPS_PORT} ${QC_API_UPSTREAM}'   < /etc/nginx/templates/default.conf.template   > /etc/nginx/conf.d/default.conf

nginx -g 'daemon off;' &
NGINX_PID="$!"

reload_loop() {
  last_cert_mtime=""
  last_key_mtime=""
  while kill -0 "$NGINX_PID" >/dev/null 2>&1; do
    if [ -s "$CERT" ] && [ -s "$KEY" ]; then
      cert_mtime="$(stat -c %Y "$CERT" 2>/dev/null || echo 0)"
      key_mtime="$(stat -c %Y "$KEY" 2>/dev/null || echo 0)"
      if [ -n "$last_cert_mtime" ] && { [ "$cert_mtime" != "$last_cert_mtime" ] || [ "$key_mtime" != "$last_key_mtime" ]; }; then
        echo "[edge] TLS cert changed; reloading nginx"
        nginx -s reload || true
      fi
      last_cert_mtime="$cert_mtime"
      last_key_mtime="$key_mtime"
    fi
    sleep "$QC_CERT_RELOAD_INTERVAL_SECONDS"
  done
}

reload_loop &
WATCH_PID="$!"

trap 'kill "$WATCH_PID" >/dev/null 2>&1 || true; kill "$NGINX_PID" >/dev/null 2>&1 || true' INT TERM

wait "$NGINX_PID"
