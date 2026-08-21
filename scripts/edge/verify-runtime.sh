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
gate="$ROOT/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED"

if [[ "$MODE" == "--preauth" ]]; then
  [[ ! -e "$gate" ]] || { echo "preauthorization proof refused: runtime authorization marker already exists" >&2; exit 6; }
else
  [[ -f "$gate" && "$(tr -d '\r\n' < "$gate")" == "AUTHORIZED" ]] || { echo "runtime authorization marker missing/invalid" >&2; exit 6; }
fi

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

# Prove every intended client identity is accepted by the final Valkey authority.
for client in health api worker; do
  docker exec queen-califia-valkey valkey-cli --tls \
    --cacert /run/valkey-pki/ca.crt \
    --cert "/run/valkey-pki/${client}.crt" \
    --key "/run/valkey-pki/${client}.key" \
    -h 127.0.0.1 -p 6379 ping | grep -qx PONG
done

# mTLS is mandatory: CA trust without a client certificate must not authenticate.
if docker exec queen-califia-valkey valkey-cli --tls \
  --cacert /run/valkey-pki/ca.crt \
  -h 127.0.0.1 -p 6379 ping >/tmp/qc-edge-no-client-cert.out 2>/tmp/qc-edge-no-client-cert.err; then
  echo "Valkey TLS unexpectedly accepted a client without a client certificate" >&2
  exit 5
fi

if docker exec queen-califia-valkey valkey-cli -h 127.0.0.1 -p 6379 ping >/tmp/qc-edge-plaintext.out 2>/tmp/qc-edge-plaintext.err; then
  echo "plaintext Valkey unexpectedly accepted a request" >&2
  exit 5
fi

if [[ "$MODE" == "--preauth" ]]; then
  # A preauthorization proof may start the queue authority only. Application runtime
  # must remain absent until the protected authorization transition is complete.
  for name in queen-califia-api queen-califia-worker queen-califia-frontend queen-califia-caddy queen-califia-cloudflared; do
    running="$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || true)"
    [[ "$running" != "true" ]] || {
      echo "preauthorization proof refused: unauthorized application container is running: $name" >&2
      exit 6
    }
  done
  [[ ! -e "$gate" ]] || { echo "preauthorization proof invalidated: runtime authorization marker appeared during proof" >&2; exit 6; }
else
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

if [[ "$MODE" == "--preauth" ]]; then
  [[ ! -e "$gate" ]] || { echo "preauthorization evidence refused: runtime authorization marker appeared before evidence write" >&2; exit 6; }
fi

mkdir -p "$ROOT/evidence"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence="$ROOT/evidence/runtime-${stamp}.json"
MODE="$MODE" EVIDENCE="$evidence" ROOT="$ROOT" ENV_FILE="$ENV_FILE" COMPOSE_FILE="$COMPOSE_FILE" python3 - <<'PY'
import datetime
import hashlib
import json
import os
import pathlib
import socket
import subprocess

root = pathlib.Path(os.environ["ROOT"])
pki = root / "pki" / "valkey"
gate = root / "app" / "cutover" / "SOVEREIGN_EDGE_RUNTIME_AUTHORIZED"


def sh(*args):
    return subprocess.check_output(args, text=True).strip()


def fingerprint(path):
    out = sh("openssl", "x509", "-in", str(path), "-noout", "-fingerprint", "-sha256")
    return out.split("=", 1)[1].lower().replace(":", "")


def host_identity_fingerprint():
    values = [socket.gethostname()]
    for path in (
        pathlib.Path("/etc/machine-id"),
        pathlib.Path("/sys/class/dmi/id/product_uuid"),
        pathlib.Path("/sys/class/dmi/id/board_serial"),
    ):
        try:
            value = path.read_text(encoding="utf-8", errors="replace").strip()
        except (FileNotFoundError, PermissionError, OSError):
            value = ""
        if value:
            values.append(value)
    digest = hashlib.sha256()
    for value in values:
        digest.update(value.encode("utf-8", errors="replace"))
        digest.update(b"\0")
    return digest.hexdigest()


containers = {}
running_application_containers = []
for name in ("queen-califia-valkey", "queen-califia-api", "queen-califia-worker", "queen-califia-frontend", "queen-califia-caddy", "queen-califia-cloudflared"):
    r = subprocess.run(["docker", "inspect", name], capture_output=True, text=True)
    if r.returncode != 0:
        continue
    obj = json.loads(r.stdout)[0]
    containers[name] = obj.get("Id", "")
    if name != "queen-califia-valkey" and obj.get("State", {}).get("Running") is True:
        running_application_containers.append(name)

repo_status = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True, check=True)
compose = pathlib.Path("/tmp/qc-edge-compose.rendered.yml").read_bytes()
cert_fingerprints = {
    name: fingerprint(pki / f"{name}.crt")
    for name in ("ca", "server", "health", "api", "worker")
}
mode = os.environ["MODE"]
record = {
    "schema": "queen-califia-sovereign-edge-runtime-evidence-v2",
    "mode": mode,
    "captured_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "boot_id": pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    "host_identity_fingerprint_sha256": host_identity_fingerprint(),
    "git_head": sh("git", "rev-parse", "HEAD"),
    "repository_clean": repo_status.stdout.strip() == "",
    "paths": {
        "state_root": str(root.resolve()),
        "environment_file": str(pathlib.Path(os.environ["ENV_FILE"]).resolve()),
        "compose_file": str(pathlib.Path(os.environ["COMPOSE_FILE"]).resolve()),
    },
    "authorization_marker_present": gate.exists(),
    "compose_sha256": hashlib.sha256(compose).hexdigest(),
    "valkey_certificate_fingerprints_sha256": cert_fingerprints,
    "containers": containers,
    "running_application_containers": running_application_containers,
    "claims": {
        "no_host_ports_published": True,
        "valkey_tls_verified": True,
        "valkey_plaintext_refused": True,
        "valkey_client_certificate_required": True,
        "valkey_health_client_verified": True,
        "valkey_api_client_verified": True,
        "valkey_worker_client_verified": True,
        "unauthorized_application_runtime_absent": mode == "--preauth" and not running_application_containers,
        "authorized_runtime_probed": mode == "--authorized",
    },
}
path = pathlib.Path(os.environ["EVIDENCE"])
if path.exists():
    raise SystemExit(f"refusing to overwrite existing runtime evidence: {path}")
path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
path.chmod(0o600)
print(path)
PY

echo "SOVEREIGN_EDGE_RUNTIME_EVIDENCE=$evidence"
