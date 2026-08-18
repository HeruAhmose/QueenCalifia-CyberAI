#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "deploy/edge/docker-compose.edge.yml"
VALKEY = ROOT / "deploy/edge/valkey.conf"
DOCKERFILE = ROOT / "deploy/edge/Dockerfile"
ENTRYPOINT = ROOT / "scripts/edge/container-entrypoint.sh"
VALIDATOR = ROOT / "scripts/edge/validate-runtime-env.py"
BOOTSTRAP = ROOT / "scripts/edge/bootstrap-ubuntu.sh"
PKI = ROOT / "scripts/edge/generate-valkey-mtls.sh"
STATE = ROOT / "config/sovereign-edge-deployment-state.json"
TOPOLOGY = ROOT / "config/runtime-state-topology.json"


def require(text: str, *needles: str) -> None:
    missing = [x for x in needles if x not in text]
    if missing:
        raise SystemExit(f"Sovereign Edge invariant missing: {missing}")


compose = COMPOSE.read_text(encoding="utf-8")
require(
    compose,
    "valkey/valkey:9.1.1-alpine3.24",
    'user: "10001:10001"',
    "cloudflare/cloudflared:2026.7.3",
    "container_name: queen-califia-api",
    "container_name: queen-califia-worker",
    "container_name: queen-califia-valkey",
    "container_name: queen-califia-cloudflared",
    "QC_EDGE_RUNTIME_GATE: \"1\"",
    "QC_EDGE_POSTGRES_PROVIDER: neon",
    "QC_DATABASE_CONNECTION_MODE: pooled",
    "rediss://valkey:6379/0?",
    "ssl_cert_reqs=required",
    "ssl_ca_certs=/run/valkey-pki/ca.crt",
    "internal: true",
    'command: ["tunnel", "--no-autoupdate", "run", "--token"',
)
for forbidden in (
    "ports:",
    "80:80",
    "443:443",
    "6379:6379",
    "5432:5432",
    "redis://",
    "postgres:16-alpine",
    "postgres:18-alpine",
    "redis:7-alpine",
    "replicas:",
    "scale:",
):
    if forbidden in compose:
        raise SystemExit(f"Sovereign Edge compose contains forbidden topology: {forbidden}")

valkey = VALKEY.read_text(encoding="utf-8")
require(
    valkey,
    "port 0",
    "tls-port 6379",
    "tls-auth-clients yes",
    "tls-cert-file /run/valkey-pki/server.crt",
    "tls-key-file /run/valkey-pki/server.key",
    "tls-ca-cert-file /run/valkey-pki/ca.crt",
    "appendonly yes",
    "appendfsync everysec",
)

require(
    DOCKERFILE.read_text(encoding="utf-8"),
    "FROM python:3.12-slim",
    "USER 10001:10001",
    "scripts/edge/container-entrypoint.sh",
)
require(ENTRYPOINT.read_text(encoding="utf-8"), "SOVEREIGN_EDGE_RUNTIME_AUTHORIZED", "validate-runtime-env.py", "exit 78")
require(
    VALIDATOR.read_text(encoding="utf-8"),
    "-pooler.",
    "sslmode",
    "rediss",
    "ssl_certfile",
    "ssl_keyfile",
    "ssl_ca_certs",
    "QC_CELERY_BROKER_URL",
    "QC_CELERY_RESULT_BACKEND",
)
require(
    BOOTSTRAP.read_text(encoding="utf-8"),
    "ufw default deny incoming",
    "QC_ADMIN_CIDR",
    "no HTTP/HTTPS/Valkey/PostgreSQL host ports opened",
)
require(PKI.read_text(encoding="utf-8"), "QueenCalifia Sovereign Edge Valkey CA", "serverAuth", "clientAuth", "10001:10001")

topology = json.loads(TOPOLOGY.read_text(encoding="utf-8"))
if topology.get("multi_replica_api_permitted") is not False:
    raise SystemExit("#72 must not permit multi-replica API")
completion = topology.get("completion_gate", {})
for key in ("read_only_root_filesystem_enabled", "multi_replica_api_enabled", "backup_restore_tested", "rolling_update_tested"):
    if completion.get(key) is not False:
        raise SystemExit(f"Sovereign Edge must not prematurely close topology gate: {key}")

state = json.loads(STATE.read_text(encoding="utf-8"))
if state.get("target") != "sovereign-local-edge" or state.get("deployment_role") != "production-candidate":
    raise SystemExit("Sovereign Edge must be a production candidate")
if state.get("preferred_production_candidate") is not True or state.get("production_authorized") is not False:
    raise SystemExit("preferred candidacy must not imply production authorization")
host = state.get("host", {})
if host.get("provisioned") is not False or host.get("identity_verified") is not False:
    raise SystemExit("local host must remain unprovisioned/unverified until machine evidence exists")
if host.get("api_replicas") != 1 or host.get("worker_replicas") != 1:
    raise SystemExit("Sovereign Edge must keep exactly one API and one worker")
ingress = state.get("ingress", {})
if ingress.get("provider") != "cloudflare-tunnel" or ingress.get("outbound_only") is not True:
    raise SystemExit("ingress must be outbound-only Cloudflare Tunnel")
if ingress.get("host_http_ports_published") is not False or ingress.get("tunnel_provisioned") is not False:
    raise SystemExit("ingress must not claim host ports or a provisioned tunnel")
pg = state.get("postgresql", {})
if pg.get("provider") != "neon" or pg.get("project_id") != "delicate-poetry-25758881" or pg.get("postgresql_major") != 18:
    raise SystemExit("Sovereign Edge must retain verified isolated Neon PG18 authority")
if pg.get("authoritative_application_state") is not True or pg.get("tls_required") is not True:
    raise SystemExit("Neon must remain authoritative application state over TLS")
queue = state.get("queue", {})
if queue.get("provider") != "self-hosted-valkey" or queue.get("scope") != "host-local-private-docker-network":
    raise SystemExit("queue must be self-hosted Valkey on the private host network")
for key in ("tls_required", "mutual_tls_required", "plaintext_port_disabled", "aof_persistence_required"):
    if queue.get(key) is not True:
        raise SystemExit(f"queue invariant must remain true: {key}")
if queue.get("internet_exposed") is not False or queue.get("authoritative_application_state") is not False:
    raise SystemExit("Valkey must not be Internet exposed or authoritative application state")
if queue.get("pki_generated") is not False or queue.get("authority_verified") is not False:
    raise SystemExit("queue evidence must remain false until generated/verified on the real host")
runtime = state.get("runtime", {})
for key in ("runtime_authorized", "health_probes_verified", "celery_task_completion_verified", "scanner_postgres_writes_verified", "restart_persistence_verified", "reboot_persistence_verified"):
    if runtime.get(key) is not False:
        raise SystemExit(f"runtime evidence gate must remain false: {key}")
for key in ("production_cutover_complete", "ha_authorized", "read_only_root_filesystem_authorized", "legacy_storage_retirement_authorized"):
    if state.get(key) is not False:
        raise SystemExit(f"production safety gate must remain false: {key}")
loss = state.get("historical_sources", {}).get("render_live_scanner_qc_scans_db", {})
if loss.get("status") != "unrecoverable-unverified" or loss.get("verified_absent") is not False or loss.get("captured") is not False:
    raise SystemExit("Render qc_scans.db evidence truth must remain unrecoverable-unverified")

print("Sovereign Edge guard verified: private mTLS Valkey, outbound-only tunnel, Neon PG18 authority, all production evidence gates closed")
