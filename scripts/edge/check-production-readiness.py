#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
STATE_PATH = ROOT / "config/sovereign-edge-deployment-state.json"
TOPOLOGY_PATH = ROOT / "config/runtime-state-topology.json"
AUTH_MARKER = Path("/srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED")
STAGES = ("authorization", "cutover", "ha")


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"READINESS_ERROR=missing required file: {path.relative_to(ROOT)}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"READINESS_ERROR=invalid JSON in {path.relative_to(ROOT)}: {exc}") from exc


def check(gate: str, observed: Any, required: Any, scope: str) -> dict[str, Any]:
    return {
        "gate": gate,
        "ready": observed == required,
        "observed": observed,
        "required": required,
        "scope": scope,
    }


def authorization_checks(state: dict[str, Any]) -> list[dict[str, Any]]:
    host = state.get("host", {})
    ingress = state.get("ingress", {})
    pg = state.get("postgresql", {})
    queue = state.get("queue", {})
    runtime = state.get("runtime", {})
    backup = state.get("backup", {})
    historical = state.get("historical_sources", {}).get("render_live_scanner_qc_scans_db", {})

    checks: list[dict[str, Any]] = []

    for key in ("control_plane_verified", "restricted_forced_command_key_verified"):
        checks.append(check(f"host.{key}", host.get(key), True, "candidate-control-plane"))

    for key in (
        "provisioned",
        "identity_verified",
        "full_disk_encryption_verified",
        "firewall_default_deny_incoming_verified",
        "bios_restore_after_power_loss_verified",
        "ups_verified",
    ):
        checks.append(check(f"host.{key}", host.get(key), True, "final-production-host"))

    for key in (
        "tunnel_provisioned",
        "tunnel_identity_verified",
        "public_hostname_verified",
        "origin_route_verified",
        "connector_registration_verified",
        "controlled_connector_test_returned_to_dormant",
    ):
        checks.append(check(f"ingress.{key}", ingress.get(key), True, "ingress"))
    checks.append(check("ingress.host_http_ports_published", ingress.get("host_http_ports_published"), False, "ingress"))

    for key in ("database_manifest_verified", "production_backup_restore_verified"):
        checks.append(check(f"postgresql.{key}", pg.get(key), True, "postgresql"))
    checks.append(check("postgresql.production_migration_verified", pg.get("production_migration_verified"), True, "historical-source-disposition"))

    historical_resolved = (
        historical.get("captured") is True
        or historical.get("verified_absent") is True
        or historical.get("status") in {"recovered-verified", "provider-verified-absent", "formally-dispositioned"}
    )
    checks.append(
        {
            "gate": "historical_sources.render_live_scanner_qc_scans_db",
            "ready": historical_resolved,
            "observed": {
                "status": historical.get("status"),
                "captured": historical.get("captured"),
                "verified_absent": historical.get("verified_absent"),
            },
            "required": "provider-backed recovery, verified absence, or formal evidence-backed disposition",
            "scope": "historical-source-disposition",
        }
    )

    for key in ("pki_generated", "authority_verified", "preauthorization_tls_verified", "preauthorization_plaintext_refused"):
        checks.append(check(f"queue.{key}", queue.get(key), True, "queue"))

    for key in ("preauthorization_verified", "preauthorization_no_host_ports_published"):
        checks.append(check(f"runtime.{key}", runtime.get(key), True, "preauthorization"))

    # The runbook requires at least one encrypted copy away from the edge host
    # before the authorization marker may be opened. Missing schema is therefore
    # intentionally fail-closed until real evidence is recorded.
    checks.append(
        check(
            "backup.off_host_encrypted_copy_verified",
            backup.get("off_host_encrypted_copy_verified"),
            True,
            "off-host-backup",
        )
    )

    return checks


def cutover_checks(state: dict[str, Any], topology: dict[str, Any]) -> list[dict[str, Any]]:
    runtime = state.get("runtime", {})
    evidence = topology.get("production_cutover_evidence_contract", {})
    checks = authorization_checks(state)

    checks.append(check("production_authorized", state.get("production_authorized"), True, "authorized-runtime"))
    checks.append(check("runtime.runtime_authorized", runtime.get("runtime_authorized"), True, "authorized-runtime"))

    for key in (
        "health_probes_verified",
        "celery_task_completion_verified",
        "scanner_postgres_writes_verified",
        "restart_persistence_verified",
        "reboot_persistence_verified",
    ):
        checks.append(check(f"runtime.{key}", runtime.get(key), True, "authorized-runtime-evidence"))

    for key in (
        "production_source_capture_complete",
        "production_migration_verified",
        "production_disposition_complete",
        "production_backup_restore_verified",
        "production_authority_probes_verified",
        "immutable_evidence_recorded",
    ):
        checks.append(check(f"runtime_state_topology.production_cutover_evidence_contract.{key}", evidence.get(key), True, "production-cutover-evidence"))

    checks.append(check("production_cutover_complete", state.get("production_cutover_complete"), True, "production-cutover"))
    return checks


def ha_checks(state: dict[str, Any], topology: dict[str, Any]) -> list[dict[str, Any]]:
    completion = topology.get("completion_gate", {})
    checks = cutover_checks(state, topology)

    for key in (
        "all_authoritative_database_writers_externalized",
        "backup_restore_tested",
        "concurrent_writer_tested",
        "rolling_update_tested",
        "remaining_writable_paths_enumerated",
        "read_only_root_filesystem_enabled",
        "multi_replica_api_enabled",
    ):
        checks.append(check(f"runtime_state_topology.completion_gate.{key}", completion.get(key), True, "ha-read-only-rootfs"))

    checks.append(check("ha_authorized", state.get("ha_authorized"), True, "ha-read-only-rootfs"))
    checks.append(check("read_only_root_filesystem_authorized", state.get("read_only_root_filesystem_authorized"), True, "ha-read-only-rootfs"))
    checks.append(check("legacy_storage_retirement_authorized", state.get("legacy_storage_retirement_authorized"), True, "ha-read-only-rootfs"))
    return checks


def evaluate(stage: str, state: dict[str, Any], topology: dict[str, Any]) -> dict[str, Any]:
    if stage == "authorization":
        checks = authorization_checks(state)
    elif stage == "cutover":
        checks = cutover_checks(state, topology)
    elif stage == "ha":
        checks = ha_checks(state, topology)
    else:
        raise ValueError(stage)

    blockers = [item for item in checks if not item["ready"]]
    return {
        "schema": "queen-califia-production-readiness-v2",
        "stage": stage,
        "target": state.get("target"),
        "deployment_role": state.get("deployment_role"),
        "authorization_marker_path": str(AUTH_MARKER),
        "ready": not blockers,
        "checks": checks,
        "blockers": blockers,
        "blocker_count": len(blockers),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail-closed Queen Califia production readiness gate.")
    parser.add_argument("--stage", choices=STAGES, default="authorization")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--expect-blocked", action="store_true", help="Succeed only while the selected stage is blocked.")
    group.add_argument("--expect-ready", action="store_true", help="Succeed only when the selected stage is ready.")
    parser.add_argument("--json", action="store_true", help="Emit the complete machine-readable report.")
    args = parser.parse_args()

    report = evaluate(args.stage, load_json(STATE_PATH), load_json(TOPOLOGY_PATH))
    ready = report["ready"]

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        label = args.stage.upper().replace("-", "_")
        print(f"QC_{label}_READINESS={'READY' if ready else 'BLOCKED'}")
        print(f"QC_{label}_READINESS_BLOCKERS={report['blocker_count']}")
        for blocker in report["blockers"]:
            print("BLOCKER=" + json.dumps({
                "gate": blocker["gate"],
                "scope": blocker["scope"],
                "observed": blocker["observed"],
                "required": blocker["required"],
            }, sort_keys=True))

    if args.expect_blocked:
        return 0 if not ready else 4
    if args.expect_ready:
        return 0 if ready else 3
    return 0 if ready else 3


if __name__ == "__main__":
    raise SystemExit(main())
