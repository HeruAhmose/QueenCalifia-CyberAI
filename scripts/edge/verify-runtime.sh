#!/usr/bin/env bash
set -euo pipefail

MODE="${1:---preauth}"
case "$MODE" in
  --preauth|--authorized) ;;
  *) echo "usage: verify-runtime.sh [--preauth|--authorized]" >&2; exit 2 ;;
esac

ROOT="${QC_EDGE_STATE_ROOT:-/srv/queen-califia}"
ENV_FILE="${QC_EDGE_ENV_FILE:-.env.edge}"
COMPOSE_FILE="${QC_EDGE_COMPOSE_FILE:-deploy/edge/docker-compose.edge.yml}"
[[ -f "$ENV_FILE" ]] || { echo "missing $ENV_FILE" >&2; exit 2; }
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a
compose=(docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE")

"${compose[@]}" config >/tmp/qc-edge-compose.rendered.yml
if grep -Eq '^[[:space:]]+ports:' /tmp/qc-edge-compose.rendered.yml; then
  echo "refusing Sovereign Edge runtime with published host ports" >&2
  exit 3
fi

"${compose[@]}" up -d valkey
for _ in $(seq 1 30); do
  status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' queen-califia-valkey 2>/dev/null || true)"
  [[ "$status" == "healthy" ]] && break
  sleep 2
done
[[ "$(docker inspect -f '{{.State.Health.Status}}' queen-califia-valkey)" == "healthy" ]] || { docker logs queen-califia-valkey; exit 4; }

docker exec queen-califia-valkey valkey-cli --tls \
  --cacert /run/valkey-pki/ca.crt \
  --cert /run/valkey-pki/health.crt \
  --key /run/valkey-pki/health.key \
  -h 127.0.0.1 -p 6379 ping | grep -qx PONG

if docker exec queen-califia-valkey valkey-cli -h 127.0.0.1 -p 6379 ping >/tmp/qc-edge-plaintext.out 2>/tmp/qc-edge-plaintext.err; then
  echo "plaintext Valkey unexpectedly accepted a request" >&2
  exit 5
fi

if [[ "$MODE" == "--authorized" ]]; then
  gate="$ROOT/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED"
  [[ -f "$gate" && "$(tr -d '\r\n' < "$gate")" == "AUTHORIZED" ]] || { echo "runtime authorization marker missing/invalid" >&2; exit 6; }

  "${compose[@]}" up -d --build
  for _ in $(seq 1 45); do
    status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' queen-califia-api 2>/dev/null || true)"
    [[ "$status" == "healthy" ]] && break
    sleep 2
  done
  [[ "$(docker inspect -f '{{.State.Health.Status}}' queen-califia-api)" == "healthy" ]] || { docker logs queen-califia-api; exit 7; }

  docker exec -i queen-califia-api python - <<'PY'
import urllib.request
for url in ("http://localhost:5000/healthz", "http://localhost:5000/readyz", "http://caddy:8080/healthz"):
    with urllib.request.urlopen(url, timeout=5) as response:
        if response.status != 200:
            raise SystemExit(f"probe failed: {url} -> {response.status}")
print("API, readiness, and private Caddy route verified")
PY

  docker exec queen-califia-worker celery -A celery_app.celery_app inspect ping --timeout=10 | grep -qi pong
  [[ "$(docker inspect -f '{{.State.Running}}' queen-califia-cloudflared)" == "true" ]] || { echo "cloudflared container is not running" >&2; exit 8; }

  [[ "${QC_DATABASE_DIRECT_URL:-}" == *"sslmode=require"* && "${QC_DATABASE_DIRECT_URL:-}" != *"-pooler."* ]] || { echo "QC_DATABASE_DIRECT_URL must be direct Neon TLS" >&2; exit 9; }
  pg_version="$(docker run --rm postgres:18-alpine psql "$QC_DATABASE_DIRECT_URL" -Atqc "SHOW server_version")"
  [[ "$pg_version" == 18.* ]] || { echo "expected Neon PostgreSQL 18, got $pg_version" >&2; exit 9; }
fi

python3 - <<'PY'
import json, subprocess
names = ["queen-califia-valkey", "queen-califia-api", "queen-califia-worker", "queen-califia-frontend", "queen-califia-caddy", "queen-califia-cloudflared"]
for name in names:
    result = subprocess.run(["docker", "inspect", name], capture_output=True, text=True)
    if result.returncode != 0:
        continue
    obj = json.loads(result.stdout)[0]
    ports = obj.get("NetworkSettings", {}).get("Ports") or {}
    published = {k:v for k,v in ports.items() if v}
    if published:
        raise SystemExit(f"{name} unexpectedly publishes host ports: {published}")
print("no Sovereign Edge container publishes a host port")
PY

mkdir -p "$ROOT/evidence"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence="$ROOT/evidence/runtime-${stamp}.json"
MODE="$MODE" EVIDENCE="$evidence" ROOT="$ROOT" python3 - <<'PY'
import hashlib, json, os, pathlib, subprocess, datetime
root = pathlib.Path(os.environ["ROOT"])
pki = root / "pki" / "valkey"
def sh(*args):
    return subprocess.check_output(args, text=True).strip()
def fingerprint(path):
    out = sh("openssl", "x509", "-in", str(path), "-noout", "-fingerprint", "-sha256")
    return out.split("=", 1)[1]
containers = {}
for name in ("queen-califia-valkey", "queen-califia-api", "queen-califia-worker", "queen-califia-frontend", "queen-califia-caddy", "queen-califia-cloudflared"):
    r = subprocess.run(["docker", "inspect", "-f", "{{.Id}}", name], capture_output=True, text=True)
    if r.returncode == 0:
        containers[name] = r.stdout.strip()
compose = pathlib.Path("/tmp/qc-edge-compose.rendered.yml").read_bytes()
record = {
    "schema": 1,
    "mode": os.environ["MODE"],
    "captured_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "boot_id": pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    "git_head": sh("git", "rev-parse", "HEAD"),
    "compose_sha256": hashlib.sha256(compose).hexdigest(),
    "valkey_ca_sha256_fingerprint": fingerprint(pki / "ca.crt"),
    "containers": containers,
    "claims": {
        "no_host_ports_published": True,
        "valkey_tls_verified": True,
        "valkey_plaintext_refused": True,
        "authorized_runtime_probed": os.environ["MODE"] == "--authorized"
    }
}
path = pathlib.Path(os.environ["EVIDENCE"])
path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
path.chmod(0o600)
print(path)
PY

echo "SOVEREIGN_EDGE_RUNTIME_EVIDENCE=$evidence"
