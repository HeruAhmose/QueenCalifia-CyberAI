#!/bin/sh
set -eu

: "${GRAFANA_URL:=http://grafana:3000}"
: "${GRAFANA_USER:=admin}"
: "${GRAFANA_PASS:=admin}"
: "${QC_ALERT_WEBHOOK_BEARER_TOKEN:?QC_ALERT_WEBHOOK_BEARER_TOKEN required}"
: "${WEBHOOK_LAST_URL:=http://webhook-receiver:8080/last}"

echo "[smoketest] waiting for grafana..."
i=0
until curl -sf "${GRAFANA_URL}/api/health" >/dev/null; do
  i=$((i+1))
  if [ "$i" -gt 90 ]; then
    echo "[smoketest] grafana not ready"
    exit 1
  fi
  sleep 2
done

echo "[smoketest] calling receivers/test..."
payload=$(cat <<EOF
{
  "receivers": [{
    "name": "qc-webhook-test",
    "grafana_managed_receiver_configs": [{
      "uid": "qc-webhook-test",
      "name": "qc-webhook-test",
      "type": "webhook",
      "settings": {
        "url": "http://webhook-receiver:8080/webhook",
        "httpMethod": "POST",
        "authorization_scheme": "Bearer",
        "authorization_credentials": "${QC_ALERT_WEBHOOK_BEARER_TOKEN}"
      }
    }]
  }]
}
EOF
)

# Test contact point via Grafana API endpoint documented by Grafana Labs.
# https://grafana.com/blog/new-in-grafana-8-2-test-contact-points-for-alerts-before-they-fire/
resp="$(curl -sS -u "${GRAFANA_USER}:${GRAFANA_PASS}" -H "Content-Type: application/json" -d "$payload"       "${GRAFANA_URL}/api/alertmanager/grafana/config/api/v1/receivers/test")"

echo "$resp" | grep -q '"status":"ok"' || {
  echo "[smoketest] receiver test did not return ok"
  echo "$resp"
  exit 1
}

echo "[smoketest] verifying webhook receiver observed auth header..."
j=0
while [ "$j" -lt 60 ]; do
  last="$(curl -sS "${WEBHOOK_LAST_URL}" || true)"
  echo "$last" | grep -q '"seen":true' || { sleep 1; j=$((j+1)); continue; }
  echo "$last" | grep -q '"auth_ok":true' && exit 0
  echo "[smoketest] webhook seen but auth mismatch"
  echo "$last"
  exit 1
done

echo "[smoketest] webhook was not observed"
exit 1
