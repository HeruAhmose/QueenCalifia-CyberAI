from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/edge/collect-final-host-evidence.py"

spec = importlib.util.spec_from_file_location("qc_final_host_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class MarkerStub:
    def __init__(self, present: bool) -> None:
        self.present = present

    def exists(self) -> bool:
        return self.present

    def __str__(self) -> str:
        return "/srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED"


def patch_common(monkeypatch, *, bare_metal: bool) -> None:
    monkeypatch.setattr(collector, "AUTH_MARKER", MarkerStub(False))
    monkeypatch.setattr(
        collector,
        "virtualization_evidence",
        lambda: {
            "detected": "none" if bare_metal else "microsoft",
            "command_rc": 0,
            "bare_metal": bare_metal,
            "error": None,
        },
    )
    monkeypatch.setattr(
        collector,
        "identity_fingerprint",
        lambda: {
            "fingerprint_sha256": "a" * 64,
            "source_kinds": ["hostname", "machine-id", "dmi-product-uuid"],
            "raw_identifiers_included": False,
        },
    )
    monkeypatch.setattr(
        collector,
        "storage_evidence",
        lambda: {
            "root_source_kind": "block-device",
            "root_chain": [{"name": "dm-0", "type": "crypt", "fstype": ""}],
            "root_storage_encryption_detected": True,
            "root_probe_error": None,
            "swap_count": 0,
            "swap_devices": [],
            "unencrypted_swap_detected": False,
            "swap_probe_error": None,
        },
    )
    monkeypatch.setattr(
        collector,
        "firewall_evidence",
        lambda: {
            "probe_rc": 0,
            "ufw_active": True,
            "default_deny_incoming": True,
            "status_sha256": "b" * 64,
            "raw_rules_included": False,
            "error": None,
        },
    )
    monkeypatch.setattr(
        collector,
        "listener_evidence",
        lambda: {
            "probe_rc": 0,
            "prohibited_ports": [],
            "prohibited_ports_absent": True,
            "observed_port_count": 1,
            "error": None,
        },
    )
    monkeypatch.setattr(
        collector,
        "repository_evidence",
        lambda: {
            "repository": "/opt/queen-califia",
            "head": "c" * 40,
            "head_probe_error": None,
            "clean": True,
            "status_probe_error": None,
        },
    )
    monkeypatch.setattr(
        collector,
        "parse_os_release",
        lambda: {"id": "ubuntu", "version_id": "24.04", "pretty_name": "Ubuntu Server"},
    )


def test_encryption_chain_detects_crypt_and_luks() -> None:
    assert collector.chain_has_encryption([{"type": "crypt", "fstype": ""}]) is True
    assert collector.chain_has_encryption([{"type": "disk", "fstype": "crypto_LUKS"}]) is True
    assert collector.chain_has_encryption([{"type": "disk", "fstype": "ext4"}]) is False


def test_hyperv_candidate_cannot_satisfy_final_host_machine_evidence(monkeypatch) -> None:
    patch_common(monkeypatch, bare_metal=False)
    evidence = collector.build_evidence()
    assert evidence["virtualization"]["bare_metal"] is False
    assert evidence["machine_evidence_ready_for_review"] is False
    assert evidence["ledger_modified"] is False
    assert evidence["authorization_modified"] is False


def test_bare_metal_machine_evidence_still_requires_manual_controls(monkeypatch) -> None:
    patch_common(monkeypatch, bare_metal=True)
    evidence = collector.build_evidence()
    assert evidence["machine_evidence_ready_for_review"] is True
    assert evidence["manual_controls"]["bios_restore_after_power_loss"]["verified"] is False
    assert evidence["manual_controls"]["ups"]["verified"] is False
    assert evidence["manual_controls"]["bios_restore_after_power_loss"]["status"] == "manual-evidence-required"
    assert evidence["manual_controls"]["ups"]["status"] == "manual-evidence-required"


def test_authorization_marker_presence_blocks_machine_readiness(monkeypatch) -> None:
    patch_common(monkeypatch, bare_metal=True)
    monkeypatch.setattr(collector, "AUTH_MARKER", MarkerStub(True))
    evidence = collector.build_evidence()
    assert evidence["authorization_marker"]["present"] is True
    assert evidence["machine_evidence_ready_for_review"] is False


def test_production_paths_are_fixed_constants() -> None:
    assert collector.CANONICAL_REPO_ROOT == Path("/opt/queen-califia")
    assert collector.EVIDENCE_ROOT == Path("/srv/queen-califia/evidence")
