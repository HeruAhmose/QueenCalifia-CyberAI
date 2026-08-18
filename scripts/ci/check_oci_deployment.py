#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "deploy/oci/docker-compose.oci.yml"
DOCKERFILE = ROOT / "deploy/oci/Dockerfile"
ENTRYPOINT = ROOT / "scripts/oci/container-entrypoint.sh"
TOPOLOGY = ROOT / "config/runtime-state-topology.json"
OCI_STATE = ROOT / "config/oci-deployment-state.json"


def require(text: str, *needles: str) -> None:
    missing = [x for x in needles if x not in text]
    if missing:
        raise SystemExit(f"OCI deployment invariant missing: {missing}")


compose = COMPOSE.read_text(encoding="utf-8")
require(
    compose,
    "postgres:16-alpine",
    "caddy:2.10.2-alpine",
    "container_name: queen-califia-api",
    'profiles: ["state", "runtime"]',
    'profiles: ["runtime"]',
    "QC_PRODUCTION: \"1\"",
    "QC_USE_CELERY: \"1\"",
    "QC_REQUIRE_REDIS: \"1\"",
    "QC_DATABASE_URL: postgresql://",
    "QC_OCI_RUNTIME_GATE: \"1\"",
    "QC_OCI_STATE_ROOT:-/srv/queen-califia",
    "80:80",
    "443:443",
)
if "replicas:" in compose or "scale:" in compose:
    raise SystemExit("OCI Compose must not introduce replica/scale settings while #72 is open")
if "/opt/render/" in compose:
    raise SystemExit("OCI deployment must be independent from Render runtime paths")

require(
    DOCKERFILE.read_text(encoding="utf-8"),
    "FROM python:3.12-slim",
    "USER 10001:10001",
    "OQS_INSTALL_DIR=/opt/queen-califia/liboqs",
    "ENTRYPOINT [\"/opt/queen-califia/scripts/oci/container-entrypoint.sh\"]",
)
require(
    ENTRYPOINT.read_text(encoding="utf-8"),
    "OCI_RUNTIME_AUTHORIZED",
    "OCI runtime requires PostgreSQL authority",
    "exit 78",
)

topology = json.loads(TOPOLOGY.read_text(encoding="utf-8"))
if topology.get("architecture_state") != "sqlite-single-writer":
    raise SystemExit("#72 topology must remain sqlite-single-writer before production evidence closes")
if topology.get("multi_replica_api_permitted") is not False:
    raise SystemExit("OCI migration must not enable multi-replica API")
completion = topology.get("completion_gate", {})
for key in (
    "read_only_root_filesystem_enabled",
    "multi_replica_api_enabled",
    "backup_restore_tested",
    "rolling_update_tested",
):
    if completion.get(key) is not False:
        raise SystemExit(f"OCI migration must not prematurely close topology gate: {key}")

state = json.loads(OCI_STATE.read_text(encoding="utf-8"))
if state.get("target") != "oci-always-free":
    raise SystemExit("OCI deployment state target must be oci-always-free")
if state.get("deployment_role") != "production-candidate":
    raise SystemExit("OCI profile must be classified as production-candidate")
if state.get("preferred_production_candidate") is not True:
    raise SystemExit("OCI must remain the preferred free-tier production candidate")
if state.get("production_eligible_by_provider_policy") is not True:
    raise SystemExit("OCI provider-policy eligibility must remain explicitly recorded")
if state.get("production_authorized") is not False:
    raise SystemExit("production candidate status must not imply production authorization")
if state.get("supported_platforms") != ["linux/arm64", "linux/amd64"]:
    raise SystemExit("OCI deployment must explicitly support arm64 and amd64")
if state.get("api_replicas") != 1:
    raise SystemExit("OCI deployment state must declare exactly one API replica")
for key in (
    "runtime_authorized",
    "ha_authorized",
    "read_only_root_filesystem_authorized",
    "legacy_storage_retirement_authorized",
):
    if state.get(key) is not False:
        raise SystemExit(f"OCI deployment safety gate must remain false: {key}")
if state.get("render_blueprint_retained") is not True:
    raise SystemExit("render.yaml must remain retained during OCI migration")
render_loss = state.get("historical_sources", {}).get("render_live_scanner_qc_scans_db")
if not isinstance(render_loss, dict) or render_loss.get("status") != "unrecoverable-unverified":
    raise SystemExit("Render qc_scans.db must remain unrecoverable-unverified")
if render_loss.get("verified_absent") is not False or render_loss.get("captured") is not False:
    raise SystemExit("Render qc_scans.db must not be represented as captured or verified absent")

print("OCI deployment guard verified: production candidate only, single API, PostgreSQL/Celery, runtime authorization closed, HA gates closed.")
