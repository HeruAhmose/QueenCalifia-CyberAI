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
DB_BACKUP = ROOT / "scripts/edge/backup-postgres.sh"
DB_RESTORE = ROOT / "scripts/edge/restore-postgres.sh"
HOST_BACKUP = ROOT / "scripts/edge/backup-host-state.sh"
VERIFY_RUNTIME = ROOT / "scripts/edge/verify-runtime.sh"
REBOOT_PROOF = ROOT / "scripts/edge/reboot-persistence-proof.sh"
WATCHDOG = ROOT / "scripts/edge/health-watchdog.sh"
WATCHDOG_SERVICE = ROOT / "deploy/edge/systemd/queen-califia-edge-watchdog.service"
WATCHDOG_TIMER = ROOT / "deploy/edge/systemd/queen-califia-edge-watchdog.timer"
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
    "-h 127.0.0.1 -p 6379 ping",
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
    "protected-mode no",
    "port 0",
    "tls-port 6379",
    "tls-auth-clients yes",
    "tls-cert-file /run/valkey-pki/server.crt",
    "tls-key-file /run/valkey-pki/server.key",
    "tls-ca-cert-file /run/valkey-pki/ca.crt",
    "appendonly yes",
    "appendfsync everysec",
)
if "protected-mode no" in valkey:
    for required in ("port 0", "tls-auth-clients yes"):
        if required not in valkey:
            raise SystemExit(f"protected-mode no requires Valkey invariant: {required}")
    if "internal: true" not in compose or "ports:" in compose:
        raise SystemExit("protected-mode no requires an internal-only queue network with zero published host ports")

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
    "vm.overcommit_memory=1",
    "no HTTP/HTTPS/Valkey/PostgreSQL host ports opened",
)
require(
    PKI.read_text(encoding="utf-8"),
    "QueenCalifia Sovereign Edge Valkey CA",
    "serverAuth",
    "clientAuth",
    "subjectAltName=DNS:valkey,IP:127.0.0.1",
    "10001:10001",
)
require(DB_BACKUP.read_text(encoding="utf-8"), "postgres:18-alpine", "QC_DATABASE_DIRECT_URL", "sslmode=require", "-pooler.", "age -R")
require(DB_RESTORE.read_text(encoding="utf-8"), "QC_RESTORE_DATABASE_URL", "zero public base tables", "postgres:18-alpine", "pg_restore", "age -d")
require(HOST_BACKUP.read_text(encoding="utf-8"), "app evidence valkey pki", "age -R", "sha256sum")
require(
    VERIFY_RUNTIME.read_text(encoding="utf-8"),
    "--preauth",
    "--authorized",
    "-h 127.0.0.1 -p 6379",
    "plaintext Valkey unexpectedly accepted a request",
    "docker exec -i queen-califia-api python -",
    "SHOW server_version",
    "no Sovereign Edge container publishes a host port",
)
require(
    REBOOT_PROOF.read_text(encoding="utf-8"),
    "SOVEREIGN_EDGE_RUNTIME_AUTHORIZED",
    "-h 127.0.0.1 -p 6379",
    "/proc/sys/kernel/random/boot_id",
    "boot ID did not change",
    "qc:edge:reboot-proof",
    "Valkey AOF reboot persistence failed",
)
require(
    WATCHDOG.read_text(encoding="utf-8"),
    "authorization gate closed; no runtime recovery attempted",
    "never creates, edits, or repairs the authorization marker",
    "for service in worker frontend caddy cloudflared",
    'container="queen-califia-${service}"',
)
require(WATCHDOG_SERVICE.read_text(encoding="utf-8"), "NoNewPrivileges=true", "ProtectSystem=strict", "/run/docker.sock")
require(WATCHDOG_TIMER.read_text(encoding="utf-8"), "OnBootSec=2min", "OnUnitActiveSec=1min", "Persistent=true")

topology = json.loads(TOPOLOGY.read_text(encoding="utf-8"))
if topology.get("multi_replica_api_permitted") is not False:
    raise SystemExit("#72 must not permit multi-replica API")
completion = topology.get("completion_gate", {})
for key in ("read_only_root_filesystem_enabled", "multi_replica_api_enabled", "backup_restore_tested", "rolling_update_tested"):
    if completion.get(key) is not False:
        raise SystemExit(f"Sovereign Edge must not prematurely close topology gate: {key}")

state = json.loads(STATE.read_text(encoding="utf-8"))
if state.get("version") != 2:
    raise SystemExit("Sovereign Edge deployment state must use the Hyper-V-aware v2 evidence schema")
if state.get("target") != "sovereign-local-edge" or state.get("deployment_role") != "production-candidate":
    raise SystemExit("Sovereign Edge must be a production candidate")
if state.get("preferred_production_candidate") is not True or state.get("production_authorized") is not False:
    raise SystemExit("preferred candidacy must not imply production authorization")

host = state.get("host", {})
required_host = {
    "operating_system": "ubuntu-server",
    "deployment_form": "hyperv-virtual-machine",
    "hypervisor": "hyperv",
    "vm_name": "QueenCalifia-Sovereign-Edge-HyperV",
    "guest_hostname": "qc-edge-01",
    "control_plane": "systemd-hyperv-v1",
    "control_plane_verified": True,
    "restricted_forced_command_key_verified": True,
    "preauthorization_evidence_path": "/srv/queen-califia/evidence/runtime-20260821T095053Z.json",
    "preauthorization_evidence_git_head": "4f2f6949a723ed034db3ccd7196b77c8df3ae99c",
    "dedicated_physical_host_required_for_final_production": True,
}
for key, expected in required_host.items():
    if host.get(key) != expected:
        raise SystemExit(f"Hyper-V production-candidate evidence mismatch: host.{key}")
for key in ("provisioned", "identity_verified", "full_disk_encryption_verified", "firewall_default_deny_incoming_verified"):
    if host.get(key) is not True:
        raise SystemExit(f"verified final-host evidence must remain recorded: host.{key}")
for key in ("bios_restore_after_power_loss_verified", "ups_verified"):
    if host.get(key) is not False:
        raise SystemExit(f"manual physical-host control must remain false until actually tested: host.{key}")
final_host = host.get("final_host_evidence", {})
required_final_host = {
    "schema": "queen-califia-hyperv-final-host-evidence-v2",
    "architecture": "windows-physical-host-with-hyperv-ubuntu-guest",
    "path": "C:\\ProgramData\\QueenCalifia\\evidence\\hyperv-final-host\\hyperv-final-host-v2-20260821T095153Z.json",
    "sha256": "da9f6d5396d4b155876687de9c5a256e1b569f8df37442aa81499721aecbe8bc",
    "git_head": "4f2f6949a723ed034db3ccd7196b77c8df3ae99c",
    "vm_id": "b7a57ed1-4245-454f-b004-9f38196b80aa",
    "automated_host_evidence_ready_for_review": True,
    "manual_controls": "BIOS_AND_UPS_REQUIRED",
}
for key, expected in required_final_host.items():
    if final_host.get(key) != expected:
        raise SystemExit(f"final-host evidence mismatch: host.final_host_evidence.{key}")
if host.get("api_replicas") != 1 or host.get("worker_replicas") != 1:
    raise SystemExit("Sovereign Edge must keep exactly one API and one worker")

ingress = state.get("ingress", {})
if ingress.get("provider") != "cloudflare-tunnel" or ingress.get("outbound_only") is not True:
    raise SystemExit("ingress must be outbound-only Cloudflare Tunnel")
if ingress.get("host_http_ports_published") is not False:
    raise SystemExit("Sovereign Edge must publish zero host HTTP ports")
required_ingress = {
    "tunnel_provisioned": True,
    "tunnel_id": "1aac242e-2e12-4d91-9bbc-149964270d92",
    "tunnel_identity_verified": True,
    "public_hostname": "qc.tamerian-materials.com",
    "public_hostname_verified": True,
    "origin_service": "http://caddy:8080",
    "origin_route_verified": True,
    "connector_registration_verified": True,
    "connector_protocol_verified": "quic",
    "controlled_connector_test_returned_to_dormant": True,
    "dormant_public_response": "cloudflare-1033",
}
for key, expected in required_ingress.items():
    if ingress.get(key) != expected:
        raise SystemExit(f"Cloudflare ingress evidence mismatch: ingress.{key}")

pg = state.get("postgresql", {})
if pg.get("provider") != "neon" or pg.get("project_id") != "delicate-poetry-25758881" or pg.get("postgresql_major") != 18:
    raise SystemExit("Sovereign Edge must retain verified isolated Neon PG18 authority")
if pg.get("authoritative_application_state") is not True or pg.get("tls_required") is not True:
    raise SystemExit("Neon must remain authoritative application state over TLS")
if pg.get("production_migration_verified") is not False:
    raise SystemExit("historical-source migration must remain open while Render qc_scans.db is unrecoverable-unverified")
if pg.get("database_manifest_verified") is not True:
    raise SystemExit("independent source/restore database manifest equality is verified and must remain recorded")
if pg.get("database_manifest_sha256") != "efd4ec38a752f41255309635638aaa1c59e0f59dbd5953c0b7b89871882eaaed":
    raise SystemExit("database manifest evidence digest mismatch")
if pg.get("production_backup_restore_verified") is not True:
    raise SystemExit("independent encrypted PostgreSQL backup/restore proof must remain recorded")
if pg.get("encrypted_backup_sha256") != "20a473c2e5312d357b1cb4fb92691f33bb192f429deba9a5af00e870d81d2ca0":
    raise SystemExit("encrypted PostgreSQL backup digest mismatch")

queue = state.get("queue", {})
if queue.get("provider") != "self-hosted-valkey" or queue.get("scope") != "host-local-private-docker-network":
    raise SystemExit("queue must be self-hosted Valkey on the private host network")
for key in ("tls_required", "mutual_tls_required", "plaintext_port_disabled", "aof_persistence_required"):
    if queue.get(key) is not True:
        raise SystemExit(f"queue invariant must remain true: {key}")
if queue.get("internet_exposed") is not False or queue.get("authoritative_application_state") is not False:
    raise SystemExit("Valkey must not be Internet exposed or authoritative application state")
if queue.get("preauthorization_tls_verified") is not True or queue.get("preauthorization_plaintext_refused") is not True:
    raise SystemExit("fresh preauthorization Valkey TLS/plaintext-refusal evidence must remain recorded")
if queue.get("pki_generated") is not True or queue.get("authority_verified") is not True:
    raise SystemExit("host-bound Valkey PKI and live authority evidence must remain recorded")
authority = queue.get("authority_evidence", {})
required_authority = {
    "schema": "queen-califia-hyperv-final-valkey-authority-evidence-v2",
    "path": "C:\\ProgramData\\QueenCalifia\\evidence\\hyperv-valkey-authority\\hyperv-final-valkey-authority-v2-20260821T095159Z.json",
    "sha256": "87c5627b2e81cd75f5ccc0d019c6b234be35157b8478c0635451a5b8fd78c8b9",
    "git_head": "4f2f6949a723ed034db3ccd7196b77c8df3ae99c",
    "vm_id": "b7a57ed1-4245-454f-b004-9f38196b80aa",
    "cross_host_binding": "NIC_HASH",
    "eligible_for_human_review": True,
    "ledger_updated_by_evidence_tool": False,
    "authorization_updated_by_evidence_tool": False,
}
for key, expected in required_authority.items():
    if authority.get(key) != expected:
        raise SystemExit(f"Valkey authority evidence mismatch: queue.authority_evidence.{key}")

backup = state.get("backup", {})
if backup.get("local_encrypted_host_state_backup_verified") is not True:
    raise SystemExit("fresh local encrypted host-state backup evidence must remain recorded")
if backup.get("local_encrypted_host_state_backup_path") != "/srv/queen-califia/backups/edge-state-20260821T095912Z.tar.age":
    raise SystemExit("local encrypted host-state backup path mismatch")
if backup.get("local_encrypted_host_state_backup_sha256") != "dc0d9c8eda6dcbbbdc6229b9ad1bcfa1ec54aa02a414c681706739aed63ec2ca":
    raise SystemExit("local encrypted host-state backup digest mismatch")
if backup.get("off_host_encrypted_copy_required") is not True:
    raise SystemExit("off-host encrypted copy must remain required")
if backup.get("off_host_encrypted_copy_verified") is not False or backup.get("off_host_evidence_path") is not None or backup.get("off_host_evidence_sha256") is not None:
    raise SystemExit("off-host copy gate must remain open until independent storage proof exists")

runtime = state.get("runtime", {})
if runtime.get("preauthorization_verified") is not True or runtime.get("preauthorization_no_host_ports_published") is not True:
    raise SystemExit("fresh fail-closed preauthorization evidence must remain recorded")
for key in ("runtime_authorized", "health_probes_verified", "celery_task_completion_verified", "scanner_postgres_writes_verified", "restart_persistence_verified", "reboot_persistence_verified"):
    if runtime.get(key) is not False:
        raise SystemExit(f"authorized runtime evidence gate must remain false: {key}")
for key in ("production_cutover_complete", "ha_authorized", "read_only_root_filesystem_authorized", "legacy_storage_retirement_authorized"):
    if state.get(key) is not False:
        raise SystemExit(f"production safety gate must remain false: {key}")
loss = state.get("historical_sources", {}).get("render_live_scanner_qc_scans_db", {})
if loss.get("status") != "unrecoverable-unverified" or loss.get("verified_absent") is not False or loss.get("captured") is not False:
    raise SystemExit("Render qc_scans.db evidence truth must remain unrecoverable-unverified")

print("Sovereign Edge guard verified: final Windows host and host-bound Valkey authority evidence are recorded; local encrypted backup is verified; BIOS/UPS/off-host/historical-source/authorized-runtime/cutover gates remain closed")
