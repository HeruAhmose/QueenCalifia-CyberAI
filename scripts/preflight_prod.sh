#!/usr/bin/env bash
set -euo pipefail

# scripts/preflight_prod.sh
#
# Production preflight for the edge (ACME HTTP-01):
# - DNS sanity (A/AAAA)
# - Port reachability (80/443 or custom)
# - HTTP->HTTPS redirect behavior
# - ACME webroot challenge path served correctly (writes a temp file into the edge container)
# - TLS handshake info
#
# Usage:
#   QC_DOMAIN=example.com QC_HTTP_PORT=80 QC_HTTPS_PORT=443 ./scripts/preflight_prod.sh
#   ./scripts/preflight_prod.sh --domain example.com --compose docker-compose.prod.edge.yml

DOMAIN="${QC_DOMAIN:-}"
HTTP_PORT="${QC_HTTP_PORT:-80}"
HTTPS_PORT="${QC_HTTPS_PORT:-443}"
COMPOSE_FILE="docker-compose.prod.edge.yml"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2;;
    --http-port) HTTP_PORT="$2"; shift 2;;
    --https-port) HTTPS_PORT="$2"; shift 2;;
    --compose) COMPOSE_FILE="$2"; shift 2;;
    -h|--help)
      echo "Usage: $0 [--domain DOMAIN] [--http-port 80] [--https-port 443] [--compose docker-compose.prod.edge.yml]"
      exit 0
      ;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

if [[ -z "$DOMAIN" ]]; then
  echo "ERROR: QC_DOMAIN (or --domain) is required." >&2
  exit 2
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing dependency: $1" >&2; exit 2; }; }
need curl
need docker
need openssl

echo "== QueenCalifia preflight =="
echo "Domain: $DOMAIN"
echo "HTTP : $HTTP_PORT"
echo "HTTPS: $HTTPS_PORT"
echo "Compose: $COMPOSE_FILE"
echo

dns_ips() {
  if command -v dig >/dev/null 2>&1; then
    dig +short A "$DOMAIN" || true
    dig +short AAAA "$DOMAIN" || true
  elif command -v getent >/dev/null 2>&1; then
    getent ahosts "$DOMAIN" | awk '{print $1}' | sort -u || true
  else
    echo "(no dig/getent available)"
  fi
}

echo "-> DNS resolution"
IPS="$(dns_ips | tr '\n' ' ' | xargs || true)"
echo "DNS IPs: ${IPS:-<none>}"

PUB_IP=""
if PUB_IP="$(curl -fsS https://api.ipify.org 2>/dev/null)"; then
  echo "Public IP (ipify): $PUB_IP"
  if [[ -n "$IPS" ]] && ! grep -q "$PUB_IP" <<<"$IPS"; then
    echo "WARN: Public IP does not match DNS A/AAAA results. Verify load balancer/NAT."
  fi
else
  echo "WARN: Could not fetch public IP (ipify). Skipping IP vs DNS check."
fi
echo

tcp_check() {
  local host="$1" port="$2"
  if command -v nc >/dev/null 2>&1; then
    nc -z -w 3 "$host" "$port" >/dev/null 2>&1
    return $?
  fi

  python - <<'PY' "$host" "$port"
import socket, sys
host = sys.argv[1]
port = int(sys.argv[2])
s = socket.socket()
s.settimeout(3.0)
try:
    s.connect((host, port))
except Exception:
    sys.exit(1)
finally:
    try: s.close()
    except Exception: pass
sys.exit(0)
PY
}

echo "-> TCP reachability"
if tcp_check "$DOMAIN" "$HTTP_PORT"; then
  echo "OK: $DOMAIN:$HTTP_PORT reachable"
else
  echo "ERROR: $DOMAIN:$HTTP_PORT not reachable" >&2
  exit 2
fi

if tcp_check "$DOMAIN" "$HTTPS_PORT"; then
  echo "OK: $DOMAIN:$HTTPS_PORT reachable"
else
  echo "ERROR: $DOMAIN:$HTTPS_PORT not reachable" >&2
  exit 2
fi
echo

echo "-> Redirect behavior (/) should be HTTP -> HTTPS"
HTTP_URL="http://$DOMAIN:$HTTP_PORT/"
REDIR="$(curl -sS -o /dev/null -D - "$HTTP_URL" | awk 'tolower($1)=="location:"{print $2}' | tr -d '\r' | tail -n1 || true)"
CODE="$(curl -sS -o /dev/null -w "%{http_code}" "$HTTP_URL" || true)"
echo "HTTP status: ${CODE:-<none>}"
echo "Location   : ${REDIR:-<none>}"
if [[ "$CODE" != "301" && "$CODE" != "308" ]]; then
  echo "WARN: expected 301/308 from HTTP /. Got: $CODE"
fi
if [[ -n "$REDIR" ]] && [[ "$REDIR" != https://* ]]; then
  echo "WARN: expected Location to start with https://"
fi
echo

echo "-> ACME challenge path sanity (no redirect, exact content)"
EDGE_ID="$(docker compose -f "$COMPOSE_FILE" ps -q edge 2>/dev/null || true)"
if [[ -z "$EDGE_ID" ]]; then
  echo "ERROR: edge container not running. Start it first:" >&2
  echo "  docker compose -f $COMPOSE_FILE up -d" >&2
  exit 2
fi

TOKEN="qc-preflight-$(date +%s)-$RANDOM"
CONTENT="queen-califia-preflight-$RANDOM"
CHAL_PATH="/var/www/certbot/.well-known/acme-challenge/$TOKEN"

docker compose -f "$COMPOSE_FILE" exec -T edge sh -lc "mkdir -p /var/www/certbot/.well-known/acme-challenge && echo '$CONTENT' > '$CHAL_PATH'"

CHAL_URL="http://$DOMAIN:$HTTP_PORT/.well-known/acme-challenge/$TOKEN"
BODY="$(curl -fsS "$CHAL_URL" || true)"
if [[ "$BODY" != "$CONTENT" ]]; then
  echo "ERROR: ACME webroot check failed." >&2
  echo "Expected: $CONTENT" >&2
  echo "Got     : ${BODY:0:200}" >&2
  docker compose -f "$COMPOSE_FILE" exec -T edge sh -lc "rm -f '$CHAL_PATH'" || true
  exit 2
fi
echo "OK: challenge file served correctly"

docker compose -f "$COMPOSE_FILE" exec -T edge sh -lc "rm -f '$CHAL_PATH'" || true
echo

echo "-> TLS handshake (summary)"
set +e
openssl s_client -connect "$DOMAIN:$HTTPS_PORT" -servername "$DOMAIN" -brief </dev/null 2>/dev/null | sed -n '1,25p'
set -e
echo

echo "-> API readiness over HTTPS"
READY_URL="https://$DOMAIN:$HTTPS_PORT/readyz"
READY_CODE="$(curl -ksS -o /dev/null -w "%{http_code}" "$READY_URL" || true)"
echo "GET /readyz => $READY_CODE"
if [[ "$READY_CODE" != "200" ]]; then
  echo "WARN: /readyz is not ready yet (expected 200). Check API + Redis." >&2
else
  echo "OK: /readyz is ready"
fi

echo
echo "✅ Preflight complete."
