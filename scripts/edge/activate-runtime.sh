#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-start}"
REPO_ROOT="${QC_EDGE_REPO_ROOT:-/opt/queen-califia}"
STATE_ROOT="${QC_EDGE_STATE_ROOT:-/srv/queen-califia}"
ENV_FILE="${QC_EDGE_ENV_FILE:-$REPO_ROOT/.env.edge}"
COMPOSE_FILE="${QC_EDGE_COMPOSE_FILE:-$REPO_ROOT/deploy/edge/docker-compose.edge.yml}"
AUTH_MARKER="$STATE_ROOT/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED"
STATE_HELPER="$REPO_ROOT/scripts/edge/vbox-runtime-state.sh"

[[ "${EUID}" -eq 0 ]] || { echo "Queen Califia runtime control must run as root/systemd." >&2; exit 1; }
[[ -d "$REPO_ROOT" ]] || { echo "missing Queen Califia repository: $REPO_ROOT" >&2; exit 2; }
[[ -x "$STATE_HELPER" ]] || { echo "missing runtime state helper: $STATE_HELPER" >&2; exit 2; }

export QC_EDGE_REPO_ROOT="$REPO_ROOT"
export QC_EDGE_STATE_ROOT="$STATE_ROOT"
export QC_EDGE_ENV_FILE="$ENV_FILE"
export QC_EDGE_COMPOSE_FILE="$COMPOSE_FILE"

signal_state() {
  "$STATE_HELPER" "$1" "${2:-}" || true
}

compose() {
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
}

require_runtime_contract() {
  [[ -f "$ENV_FILE" ]] || {
    signal_state BLOCKED "missing .env.edge"
    echo "missing runtime environment: $ENV_FILE" >&2
    exit 78
  }
  [[ -f "$COMPOSE_FILE" ]] || {
    signal_state FAILED "missing edge compose file"
    echo "missing compose file: $COMPOSE_FILE" >&2
    exit 2
  }
  [[ -f "$AUTH_MARKER" && "$(tr -d '\r\n' < "$AUTH_MARKER")" == "AUTHORIZED" ]] || {
    signal_state BLOCKED "runtime authorization gate is closed"
    echo "runtime authorization marker missing/invalid: $AUTH_MARKER" >&2
    exit 78
  }

  local rendered
  rendered="$(mktemp)"
  trap 'rm -f "${rendered:-}"' RETURN
  compose config >"$rendered"
  if grep -Eq '^[[:space:]]+ports:' "$rendered"; then
    signal_state FAILED "compose attempted to publish host ports"
    echo "refusing Sovereign Edge runtime with published host ports" >&2
    exit 3
  fi
}

wait_container_health() {
  local name="$1"
  local attempts="${2:-60}"
  local delay="${3:-2}"
  local status=""
  local i
  for i in $(seq 1 "$attempts"); do
    status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$name" 2>/dev/null || true)"
    case "$status" in
      healthy|running) return 0 ;;
      exited|dead) return 1 ;;
    esac
    sleep "$delay"
  done
  return 1
}

assert_no_published_ports() {
  python3 - <<'PY'
import json
import subprocess

names = [
    "queen-califia-valkey",
    "queen-califia-api",
    "queen-califia-worker",
    "queen-califia-frontend",
    "queen-califia-caddy",
    "queen-califia-cloudflared",
]
for name in names:
    result = subprocess.run(["docker", "inspect", name], capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"required container missing after activation: {name}")
    obj = json.loads(result.stdout)[0]
    ports = obj.get("NetworkSettings", {}).get("Ports") or {}
    published = {key: value for key, value in ports.items() if value}
    if published:
        raise SystemExit(f"{name} unexpectedly publishes host ports: {published}")
print("QC_EDGE_HOST_PORTS=NONE")
PY
}

start_runtime() {
  signal_state STARTING "authorized runtime activation in progress"
  require_runtime_contract

  cd "$REPO_ROOT"
  if ! compose up -d; then
    signal_state FAILED "docker compose activation failed"
    return 10
  fi

  if ! wait_container_health queen-califia-valkey 45 2; then
    docker logs --tail 100 queen-califia-valkey >&2 || true
    signal_state FAILED "Valkey did not become healthy"
    return 11
  fi

  if ! wait_container_health queen-califia-api 60 2; then
    docker logs --tail 100 queen-califia-api >&2 || true
    signal_state FAILED "API did not become healthy"
    return 12
  fi

  for name in queen-califia-worker queen-califia-frontend queen-califia-caddy queen-califia-cloudflared; do
    if ! wait_container_health "$name" 45 2; then
      docker logs --tail 100 "$name" >&2 || true
      signal_state FAILED "$name did not become ready"
      return 13
    fi
  done

  if ! docker exec -i queen-califia-api python - <<'PY'
import urllib.request

for url in (
    "http://localhost:5000/healthz",
    "http://localhost:5000/readyz",
    "http://caddy:8080/healthz",
):
    with urllib.request.urlopen(url, timeout=5) as response:
        if response.status != 200:
            raise SystemExit(f"probe failed: {url} -> {response.status}")
print("QC_EDGE_PRIVATE_HEALTH=PASS")
PY
  then
    signal_state FAILED "private API/readiness/Caddy probes failed"
    return 14
  fi

  if ! docker exec queen-califia-worker celery -A celery_app.celery_app inspect ping --timeout=10 | grep -qi pong; then
    signal_state FAILED "Celery worker ping failed"
    return 15
  fi

  if ! assert_no_published_ports; then
    signal_state FAILED "host-port isolation verification failed"
    return 16
  fi

  signal_state READY "authorized runtime healthy"
  echo "QUEEN_CALIFIA=READY"
}

stop_runtime() {
  signal_state STOPPING "runtime stop requested"
  if [[ -f "$ENV_FILE" && -f "$COMPOSE_FILE" ]]; then
    cd "$REPO_ROOT"
    compose stop cloudflared caddy frontend worker api valkey || {
      signal_state FAILED "runtime stop failed"
      return 20
    }
  fi
  signal_state STOPPED "runtime stopped"
  echo "QUEEN_CALIFIA=STOPPED"
}

status_runtime() {
  if [[ ! -f "$AUTH_MARKER" || "$(tr -d '\r\n' < "$AUTH_MARKER" 2>/dev/null || true)" != "AUTHORIZED" ]]; then
    signal_state BLOCKED "runtime authorization gate is closed"
    return 78
  fi

  local api=""
  local tunnel=""
  api="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' queen-califia-api 2>/dev/null || true)"
  tunnel="$(docker inspect -f '{{.State.Status}}' queen-califia-cloudflared 2>/dev/null || true)"
  if [[ "$api" == "healthy" && "$tunnel" == "running" ]]; then
    signal_state READY "authorized runtime healthy"
    return 0
  fi
  signal_state DEGRADED "runtime is not fully ready"
  return 1
}

case "$ACTION" in
  start|activate) start_runtime ;;
  stop) stop_runtime ;;
  restart)
    stop_runtime
    start_runtime
    ;;
  status) status_runtime ;;
  *)
    echo "usage: activate-runtime.sh [start|stop|restart|status]" >&2
    exit 2
    ;;
esac
