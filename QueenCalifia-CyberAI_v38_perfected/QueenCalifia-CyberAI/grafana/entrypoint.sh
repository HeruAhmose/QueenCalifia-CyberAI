#!/bin/sh
set -eu

SRC="${QC_GRAFANA_PROVISIONING_SRC:-/etc/grafana/provisioning-src}"
DST="${QC_GRAFANA_PROVISIONING_DST:-/etc/grafana/provisioning}"

mkdir -p "$DST"

if [ -d "$SRC" ]; then
  (cd "$SRC" && find . -type f -print) | while read -r f; do
    mkdir -p "$DST/$(dirname "$f")"
    cp "$SRC/$f" "$DST/$f"
  done
fi

ALERT_DIR="$DST/alerting"
mkdir -p "$ALERT_DIR"

# Optional: provision a default webhook contact point + notification policy.
# Secrets are injected via Grafana's env interpolation ($VARNAME) so they are not written to disk.
if [ -n "${QC_ALERT_WEBHOOK_URL:-}" ]; then
  cat > "$ALERT_DIR/qc-contactpoints-webhook.yaml" <<'EOF'
# config file version
apiVersion: 1
contactPoints:
  - orgId: 1
    name: qc-webhook
    receivers:
      - uid: qc-webhook-1
        type: webhook
        disableResolveMessage: false
        settings:
          url: $QC_ALERT_WEBHOOK_URL
          httpMethod: POST
EOF

  if [ -n "${QC_ALERT_WEBHOOK_BEARER_TOKEN:-}" ]; then
    cat >> "$ALERT_DIR/qc-contactpoints-webhook.yaml" <<'EOF'
          authorization_scheme: Bearer
          authorization_credentials: $QC_ALERT_WEBHOOK_BEARER_TOKEN
EOF
  fi

  cat > "$ALERT_DIR/qc-notification-policies.yaml" <<'EOF'
# config file version
apiVersion: 1
policies:
  - orgId: 1
    receiver: qc-webhook
    group_by:
      - grafana_folder
      - alertname
EOF
else
  rm -f "$ALERT_DIR/qc-contactpoints-webhook.yaml" "$ALERT_DIR/qc-notification-policies.yaml" || true
fi

if [ "${QC_ENTRYPOINT_NO_EXEC:-0}" = "1" ]; then
  exit 0
fi

exec /run.sh
