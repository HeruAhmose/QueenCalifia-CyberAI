#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "config/managed-free-deployment-state.json"
CONTRACT = ROOT / "deploy/managed/northflank-service-contract.json"
DOCKERFILE = ROOT / "deploy/managed/Dockerfile"
ENV_EXAMPLE = ROOT / "deploy/managed/.env.managed.example"
ENTRYPOINT = ROOT / "scripts/managed/container-entrypoint.sh"
VALIDATOR = ROOT / "scripts/managed/validate_runtime_env.py"
TOPOLOGY = ROOT / "config/runtime-state-topology.json"


def fail(message: str) -> None:
    raise SystemExit(message)


state = json.loads(STATE.read_text(encoding="utf-8"))
if state.get("target") != "managed-free":
    fail("managed-free state target is invalid")
if state.get("preferred_target") is not False:
    fail("Northflank Developer Sandbox must not be the preferred production target")
if state.get("deployment_role") != "staging-evaluation" or state.get("production_eligible") is not False:
    fail("Northflank Developer Sandbox must remain staging/evaluation only")
app = state.get("application_host", {})
if app.get("provider") != "northflank" or app.get("api_replicas") != 1 or app.get("worker_replicas") != 1:
    fail("managed staging target must declare one Northflank API and one worker")
if app.get("plan") != "developer-sandbox" or app.get("production_eligible") is not False:
    fail("Developer Sandbox must remain explicitly non-production")
pg = state.get("postgresql", {})
if pg.get("provider") != "neon" or pg.get("project_name") != "QueenCalifia-CyberAI":
    fail("managed target must use the isolated QueenCalifia Neon project")
if pg.get("postgresql_major") != 18 or pg.get("tls_required") is not True:
    fail("managed target must record the real Neon PostgreSQL 18 TLS contract")
if pg.get("credentials_committed") is not False:
    fail("database credentials must never be committed")
queue = state.get("queue", {})
if queue.get("provider") != "aiven-valkey" or queue.get("protocol") != "rediss":
    fail("managed queue must use TLS Aiven Valkey")
if queue.get("tls_certificate_verification_required") is not True:
    fail("managed queue must require certificate verification")
if queue.get("production_sla_assumed") is not False:
    fail("free queue profile must not imply a production SLA")
for key in (
    "runtime_authorized",
    "ha_authorized",
    "read_only_root_filesystem_authorized",
    "legacy_storage_retirement_authorized",
    "production_cutover_complete",
):
    if state.get(key) is not False:
        fail(f"managed deployment safety gate must remain false: {key}")
loss = state.get("historical_sources", {}).get("render_live_scanner_qc_scans_db", {})
if loss.get("status") != "unrecoverable-unverified" or loss.get("verified_absent") is not False or loss.get("captured") is not False:
    fail("Render qc_scans.db evidence truth must remain unrecoverable-unverified")

contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
services = contract.get("services", [])
if len(services) != 2:
    fail("Northflank free staging profile must consume exactly two services")
by_name = {service.get("name"): service for service in services}
api = by_name.get("queen-califia-api", {})
worker = by_name.get("queen-califia-worker", {})
if api.get("instances") != 1 or worker.get("instances") != 1:
    fail("API and worker instances must each remain exactly one")
if api.get("public") is not True or worker.get("public") is not False:
    fail("only API may expose a public port")
if contract.get("autoscaling_authorized") is not False or contract.get("ha_authorized") is not False:
    fail("autoscaling and HA must remain unauthorized")

for path in (DOCKERFILE, ENTRYPOINT, VALIDATOR, ENV_EXAMPLE):
    if not path.is_file():
        fail(f"missing managed deployment file: {path.relative_to(ROOT)}")

validator = VALIDATOR.read_text(encoding="utf-8")
for needle in (
    "QC_MANAGED_RUNTIME_AUTHORIZED",
    "sslmode",
    "rediss",
    "ssl_cert_reqs",
    "-pooler.",
):
    if needle not in validator:
        fail(f"managed runtime validator missing invariant: {needle}")

env_example = ENV_EXAMPLE.read_text(encoding="utf-8")
if "QC_MANAGED_RUNTIME_AUTHORIZED=AUTHORIZED" in env_example:
    fail("example environment must not pre-authorize runtime")
if "CHANGE_ME" not in env_example:
    fail("example environment must contain placeholders, not live credentials")

topology = json.loads(TOPOLOGY.read_text(encoding="utf-8"))
if topology.get("multi_replica_api_permitted") is not False:
    fail("#72 must continue to prohibit multi-replica API")
completion = topology.get("completion_gate", {})
for key in (
    "backup_restore_tested",
    "rolling_update_tested",
    "read_only_root_filesystem_enabled",
    "multi_replica_api_enabled",
):
    if completion.get(key) is not False:
        fail(f"managed staging profile must not prematurely close topology gate: {key}")

print("managed-free staging guard verified: Northflank sandbox non-production, Neon PG18, TLS Valkey, one API, one worker, all cutover/HA gates closed")
