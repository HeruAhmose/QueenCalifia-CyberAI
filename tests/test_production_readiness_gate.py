from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/edge/check-production-readiness.py"

spec = importlib.util.spec_from_file_location("qc_production_readiness", SCRIPT)
assert spec is not None and spec.loader is not None
readiness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readiness)


def load_state() -> dict:
    return json.loads((ROOT / "config/sovereign-edge-deployment-state.json").read_text(encoding="utf-8"))


def load_topology() -> dict:
    return json.loads((ROOT / "config/runtime-state-topology.json").read_text(encoding="utf-8"))


def make_authorization_ready(state: dict) -> dict:
    state = copy.deepcopy(state)
    host = state["host"]
    for key in (
        "provisioned",
        "identity_verified",
        "full_disk_encryption_verified",
        "firewall_default_deny_incoming_verified",
        "bios_restore_after_power_loss_verified",
        "ups_verified",
    ):
        host[key] = True

    # Keep migration false to prove a formally evidence-backed disposition can
    # resolve an unrecoverable historical source without falsifying migration.
    state["postgresql"]["production_migration_verified"] = False
    state["queue"]["pki_generated"] = True
    state["queue"]["authority_verified"] = True
    state["historical_sources"]["render_live_scanner_qc_scans_db"].update(
        {
            "status": "formally-dispositioned",
            "captured": False,
            "verified_absent": False,
        }
    )
    state["backup"] = {"off_host_encrypted_copy_verified": True}
    return state


def make_cutover_ready(state: dict, topology: dict) -> tuple[dict, dict]:
    state = make_authorization_ready(state)
    topology = copy.deepcopy(topology)

    state["production_authorized"] = True
    state["runtime"]["runtime_authorized"] = True
    for key in (
        "health_probes_verified",
        "celery_task_completion_verified",
        "scanner_postgres_writes_verified",
        "restart_persistence_verified",
        "reboot_persistence_verified",
    ):
        state["runtime"][key] = True

    for key in (
        "production_source_capture_complete",
        "production_migration_verified",
        "production_disposition_complete",
        "production_backup_restore_verified",
        "production_authority_probes_verified",
        "immutable_evidence_recorded",
    ):
        topology["production_cutover_evidence_contract"][key] = True

    state["production_cutover_complete"] = True
    return state, topology


def test_current_authorization_state_is_fail_closed() -> None:
    report = readiness.evaluate("authorization", load_state(), load_topology())
    assert report["ready"] is False
    assert report["blocker_count"] > 0
    gates = {item["gate"] for item in report["blockers"]}
    assert gates == {
        "host.bios_restore_after_power_loss_verified",
        "host.ups_verified",
        "historical_sources.render_live_scanner_qc_scans_db.disposition",
        "backup.off_host_encrypted_copy_verified",
    }
    assert "host.provisioned" not in gates
    assert "queue.authority_verified" not in gates


def test_formal_historical_disposition_does_not_falsify_migration() -> None:
    state = make_authorization_ready(load_state())
    assert state["postgresql"]["production_migration_verified"] is False

    report = readiness.evaluate("authorization", state, load_topology())
    assert report["ready"] is True, report["blockers"]


def test_authorization_does_not_depend_on_post_authorization_or_ha_evidence() -> None:
    state = make_authorization_ready(load_state())
    topology = load_topology()

    assert state["runtime"]["health_probes_verified"] is False
    assert topology["completion_gate"]["rolling_update_tested"] is False

    report = readiness.evaluate("authorization", state, topology)
    assert report["ready"] is True, report["blockers"]


def test_cutover_requires_authorized_runtime_evidence() -> None:
    state = make_authorization_ready(load_state())
    report = readiness.evaluate("cutover", state, load_topology())
    assert report["ready"] is False
    gates = {item["gate"] for item in report["blockers"]}
    assert "production_authorized" in gates
    assert "runtime.health_probes_verified" in gates
    assert "runtime_state_topology.production_cutover_evidence_contract.production_authority_probes_verified" in gates


def test_ha_requires_cutover_plus_ha_completion() -> None:
    state, topology = make_cutover_ready(load_state(), load_topology())

    cutover = readiness.evaluate("cutover", state, topology)
    assert cutover["ready"] is True, cutover["blockers"]

    ha = readiness.evaluate("ha", state, topology)
    assert ha["ready"] is False
    gates = {item["gate"] for item in ha["blockers"]}
    assert "runtime_state_topology.completion_gate.rolling_update_tested" in gates
    assert "read_only_root_filesystem_authorized" in gates
    assert "ha_authorized" in gates
