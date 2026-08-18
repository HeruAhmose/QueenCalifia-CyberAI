#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "deploy/oci/docker-compose.oci.yml"
DOCKERFILE = ROOT / "deploy/oci/Dockerfile"
ENTRYPOINT = ROOT / "scripts/oci/container-entrypoint.sh"
VALIDATOR = ROOT / "scripts/oci/validate-runtime-env.py"
TOPOLOGY = ROOT / "config/runtime-state-topology.json"
OCI_STATE = ROOT / "config/oci-deployment-state.json"
BACKUP = ROOT / "scripts/oci/backup-postgres.sh"
RESTORE = ROOT / "scripts/oci/restore-postgres.sh"


def require(text: str, *needles: str) -> None:
    missing = [x for x in needles if x not in text]
    if missing:
        raise SystemExit(f"OCI deployment invariant missing: {missing}")


compose = COMPOSE.read_text(encoding="utf-8")
require(
    compose,
    "caddy:2.10.2-alpine",
    "container_name: queen-califia-api",
    "container_name: queen-califia-worker",
    'profiles: ["runtime"]',
    "QC_PRODUCTION: \"1\"",
    "QC_USE_CELERY: \"1\"",
    "QC_REQUIRE_REDIS: \"1\"",
    "QC_OCI_POSTGRES_PROVIDER: neon",
    "QC_DATABASE_CONNECTION_MODE: pooled",
    "QC_OCI_RUNTIME_GATE: \"1\"",
)
for forbidden in ("postgres:16-alpine", "redis:7-alpine", "redis://redis:6379", "container_name: queen-califia-postgres"):
    if forbidden in compose:
        raise SystemExit(f"OCI fallback must not embed local state authority: {forbidden}")
if "replicas:" in compose or "scale:" in compose:
    raise SystemExit("OCI fallback must not introduce replica/scale settings while #72 is open")
if "/opt/render/" in compose:
    raise SystemExit("OCI deployment must be independent from Render runtime paths")

require(
    DOCKERFILE.read_text(encoding="utf-8"),
    "FROM python:3.12-slim",
    "USER 10001:10001",
    "ENTRYPOINT [\"/opt/queen-califia/scripts/oci/container-entrypoint.sh\"]",
)
require(ENTRYPOINT.read_text(encoding="utf-8"), "OCI_RUNTIME_AUTHORIZED", "validate-runtime-env.py", "exit 78")
require(
    VALIDATOR.read_text(encoding="utf-8"),
    "sslmode",
    "-pooler.",
    "rediss",
    "ssl_cert_reqs",
    "QC_CELERY_BROKER_URL",
    "QC_CELERY_RESULT_BACKEND",
)
require(BACKUP.read_text(encoding="utf-8"), "postgres:18-alpine", "QC_DATABASE_DIRECT_URL", "-pooler.")
require(RESTORE.read_text(encoding="utf-8"), "postgres:18-alpine", "QC_RESTORE_DATABASE_URL", "zero public base tables")

topology = json.loads(TOPOLOGY.read_text(encoding="utf-8"))
if topology.get("multi_replica_api_permitted") is not False:
    raise SystemExit("#72 topology must remain single-replica before production evidence closes")
completion = topology.get("completion_gate", {})
for key in ("read_only_root_filesystem_enabled", "multi_replica_api_enabled", "backup_restore_tested", "rolling_update_tested"):
    if completion.get(key) is not False:
        raise SystemExit(f"OCI fallback must not prematurely close topology gate: {key}")

state = json.loads(OCI_STATE.read_text(encoding="utf-8"))
if state.get("target") != "oci-always-free" or state.get("deployment_role") != "historical-fallback":
    raise SystemExit("OCI profile must be retained only as a historical fallback")
if state.get("preferred_production_candidate") is not False:
    raise SystemExit("OCI must not remain the preferred production candidate")
if state.get("superseded_by") != "sovereign-local-edge":
    raise SystemExit("OCI fallback must identify the Sovereign Local Edge successor")
if state.get("production_authorized") is not False:
    raise SystemExit("OCI fallback must remain unauthorized")
app = state.get("application_host", {})
if app.get("provisioned") is not False or app.get("instance_identity_verified") is not False:
    raise SystemExit("OCI host must remain unprovisioned/unverified")
if app.get("api_replicas") != 1 or app.get("worker_replicas") != 1:
    raise SystemExit("OCI fallback must keep exactly one API and one worker")
pg = state.get("postgresql", {})
if pg.get("provider") != "neon" or pg.get("project_id") != "delicate-poetry-25758881" or pg.get("postgresql_major") != 18:
    raise SystemExit("OCI fallback must retain the isolated Neon PostgreSQL 18 contract")
queue = state.get("queue", {})
if queue.get("service_provisioned") is not False or queue.get("authority_verified") is not False:
    raise SystemExit("OCI fallback must not claim a provisioned queue")
for key in ("runtime_authorized", "production_cutover_complete", "ha_authorized", "read_only_root_filesystem_authorized", "legacy_storage_retirement_authorized"):
    if state.get(key) is not False:
        raise SystemExit(f"OCI fallback safety gate must remain false: {key}")
loss = state.get("historical_sources", {}).get("render_live_scanner_qc_scans_db", {})
if loss.get("status") != "unrecoverable-unverified" or loss.get("verified_absent") is not False or loss.get("captured") is not False:
    raise SystemExit("Render qc_scans.db evidence truth must remain unrecoverable-unverified")

print("OCI deployment guard verified: historical fallback only; no provisioned authority; all production gates closed")
