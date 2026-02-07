# Grafana webhook smoke test (provisioned contact point)

This compose profile validates the *provisioned* `qc-webhook` contact point end-to-end:

1) Grafana boots and provisions `qc-webhook` from `grafana/entrypoint.sh`
2) The smoke test fetches the provisioned contact point via `/api/v1/provisioning/contact-points?name=qc-webhook`
3) It forces a test notification via Grafana's receiver test API
4) The smoke test also validates receiver config parity (URL, httpMethod, disableResolveMessage, auth scheme)
5) The local webhook receiver asserts it saw `Authorization: Bearer <token>`

## Run

```bash
export QC_ALERT_WEBHOOK_BEARER_TOKEN="smoke-token"
# Optional override; defaults to the local webhook receiver URL
export QC_ALERT_WEBHOOK_URL="http://webhook-receiver:8080/webhook"

docker compose --profile smoketest up --build --abort-on-container-exit --exit-code-from grafana-smoketest
```
