#!/usr/bin/env bash
set -euo pipefail

ROOT="${QC_EDGE_STATE_ROOT:-/srv/queen-califia}"
REPO="${QC_EDGE_REPO_ROOT:-/opt/queen-califia}"
ENV_FILE="${QC_EDGE_ENV_FILE:-${REPO}/.env.edge}"
COMPOSE_FILE="${QC_EDGE_COMPOSE_FILE:-${REPO}/deploy/edge/docker-compose.edge.yml}"
GATE="$ROOT/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED"

# Recovery is allowed only for a runtime that was explicitly authorized already.
# This watchdog never creates, edits, or repairs the authorization marker.
if [[ ! -f "$GATE" || "$(tr -d '\r\n' < "$GATE")" != "AUTHORIZED" ]]; then
  echo "Sovereign Edge watchdog: authorization gate closed; no runtime recovery attempted"
  exit 0
fi
[[ -f "$ENV_FILE" ]] || { echo "Sovereign Edge watchdog: missing $ENV_FILE" >&2; exit 2; }

compose=(docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE")

health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' queen-califia-valkey 2>/dev/null || true)"
if [[ "$health" != "healthy" ]]; then
  echo "Sovereign Edge watchdog: recovering Valkey"
  "${compose[@]}" up -d valkey
fi

health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' queen-califia-api 2>/dev/null || true)"
if [[ "$health" != "healthy" ]]; then
  echo "Sovereign Edge watchdog: recovering API"
  "${compose[@]}" up -d api
fi

for service in worker frontend caddy cloudflared; do
  container="queen-califia-${service}"
  running="$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)"
  if [[ "$running" != "true" ]]; then
    echo "Sovereign Edge watchdog: recovering $service"
    "${compose[@]}" up -d "$service"
  fi
done
