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


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"READINESS_ERROR=missing required file: {path.relative_to(ROOT)}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"READINESS_ERROR=invalid JSON in {path.relative_to(ROOT)}: {exc}") from exc


def add_check(
    checks: list[dict[str, Any]],
    *,
    gate: str,
    ready: bool,
    observed: Any,
    required: Any,
    scope: str,
) -> None:
    checks.append(
        {
            "gate": gate,
            "ready": bool(ready),
            "observed": observed,
            "required": required,
            "scope": scope,
        }
    )


def evaluate(state: dict[str, Any], topology: dict[str, Any]) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    host = state.get("host", {})
    ingress = state.get("ingress", {})
    pg = state.get("postgresql", {})
    queue = state.get("queue", {})
    runtime = state.get("runtime", {})
    historical = state.get("historical_sources", {}).get("render_live_scanner_qc_scans_db", {})
    completion = topology.get("completion_gate", {})
    cutover = topology.get("production_cutover_evidence_contract", {})

    # Candidate identity/control evidence already proven on Hyper-V.
    for key in ("control_plane_verified", "restricted_forced_command_key_verified"):
        add_check(
            checks,
            gate=f"host.{key}",
            ready=host.get(key) is True,
            observed=host.get(key),
            required=True,
            scope="candidate-control-plane",
        )

    # Final-host trust boundary. Candidate VM evidence must never satisfy these.
    for key in (
        "provisioned",
        "identity_verified",
        "full_disk_encryption_verified",
        "firewall_default_deny_incoming_verified",
        "bios_restore_after_power_loss_verified",
        "ups_verified",
    ):
        add_check(
            checks,
            gate=f"host.{key}",
            ready=host.get(key) is True,
            observed=host.get(key),
            required=True,
            scope="final-production-host",
        )

    # Public ingress evidence must be independently verified before authorization.
    for key in (
        "tunnel_provisioned",
        "tunnel_identity_verified",
        "public_hostname_verified",
        "origin_route_verified",
        "connector_registration_verified",
        "controlled_connector_test_returned_to_dormant",
    ):
        add_check(
            checks,
            gate=f"ingress.{key}",
            ready=ingress.get(key) is True,
            observed=ingress.get(key),
            required=True,
            scope="ingress",
        )

    add_check(
        checks,
        gate="ingress.host_http_ports_published",
        ready=ingress.get("host_http_ports_published") is False,
        observed=ingress.get("host_http_ports_published"),
        required=False,
        scope="ingress",
    )

    # Current PostgreSQL authority/restore proof plus historical-source disposition.
    for key in ("database_manifest_verified", "production_backup_restore_verified"):
        add_check(
            checks,
            gate=f"postgresql.{key}",
            ready=pg.get(key) is True,
            observed=pg.get(key),
            required=True,
            scope="postgresql",
        )

    add_check(
        checks,
        gate="postgresql.production_migration_verified",
        ready=pg.get("production_migration_verified") is True,
        observed=pg.get("production_migration_verified"),
        required=True,
        scope="historical-source-disposition",
    )

    historical_resolved = (
        historical.get("captured") is True
        or historical.get("verified_absent") is True
        or historical.get("status") in {"recovered-verified", "provider-verified-absent", "formally-dispositioned"}
    )
    add_check(
        checks,
        gate="historical_sources.render_live_scanner_qc_scans_db",
        ready=historical_resolved,
        observed={
            "status": historical.get("status"),
            "captured": historical.get("captured"),
            "verified_absent": historical.get("verified_absent"),
        },
        required="provider-backed recovery, verified absence, or formal evidence-backed disposition",
        scope="historical-source-disposition",
    )

    # Final-host Valkey authority and preauthorization transport proof.
    for key in (
        "pki_generated",
        "authority_verified",
        "preauthorization_tls_verified",
        "preauthorization_plaintext_refused",
    ):
        add_check(
            checks,
            gate=f"queue.{key}",
            ready=queue.get(key) is True,
            observed=queue.get(key),
            required=True,
            scope="queue",
        )

    # Evidence that must exist before opening the runtime gate.
    for key in ("preauthorization_verified", "preauthorization_no_host_ports_published"):
        add_check(
            checks,
            gate=f"runtime.{key}",
            ready=runtime.get(key) is True,
            observed=runtime.get(key),
            required=True,
            scope="preauthorization",
        )

    # Topology/cutover evidence must be externally safe before authorization.
    for key in (
        "all_authoritative_database_writers_externalized",
        "backup_restore_tested",
        "concurrent_writer_tested",
        "rolling_update_tested",
        "remaining_writable_paths_enumerated",
    ):
        add_check(
            checks,
            gate=f"runtime_state_topology.completion_gate.{key}",
            ready=completion.get(key) is True,
            observed=completion.get(key),
            required=True,
            scope="runtime-topology",
        )

    for key in (
        "production_source_capture_complete",
        "production_migration_verified",
        "production_disposition_complete",
        "production_backup_restore_verified",
        "production_authority_probes_verified",
        "immutable_evidence_recorded",
    ):
        add_check(
            checks,
            gate=f"runtime_state_topology.production_cutover_evidence_contract.{key}",
            ready=cutover.get(key) is True,
            observed=cutover.get(key),
            required=True,
            scope="production-cutover-evidence",
        )

    blockers = [item for item in checks if not item["ready"]]
    return {
        "schema": "queen-califia-production-readiness-v1",
        "target": state.get("target"),
        "deployment_role": state.get("deployment_role"),
        "production_authorized_recorded": state.get("production_authorized"),
        "runtime_authorized_recorded": runtime.get("runtime_authorized"),
        "authorization_marker_path": str(AUTH_MARKER),
        "ready_for_authorization": not blockers,
        "checks": checks,
        "blockers": blockers,
        "blocker_count": len(blockers),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail-closed Queen Califia production authorization readiness gate."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--expect-blocked",
        action="store_true",
        help="CI mode: succeed only while at least one authorization prerequisite is open.",
    )
    group.add_argument(
        "--expect-ready",
        action="store_true",
        help="Transition mode: succeed only when every authorization prerequisite is satisfied.",
    )
    parser.add_argument("--json", action="store_true", help="Emit the complete machine-readable report.")
    args = parser.parse_args()

    report = evaluate(load_json(STATE_PATH), load_json(TOPOLOGY_PATH))
    ready = report["ready_for_authorization"]

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"QC_PRODUCTION_READINESS={'READY' if ready else 'BLOCKED'}")
        print(f"QC_PRODUCTION_READINESS_BLOCKERS={report['blocker_count']}")
        for blocker in report["blockers"]:
            print(
                "BLOCKER="
                + json.dumps(
                    {
                        "gate": blocker["gate"],
                        "scope": blocker["scope"],
                        "observed": blocker["observed"],
                        "required": blocker["required"],
                    },
                    sort_keys=True,
                )
            )

    if args.expect_blocked:
        return 0 if not ready else 4
    if args.expect_ready:
        return 0 if ready else 3
    return 0 if ready else 3


if __name__ == "__main__":
    raise SystemExit(main())
