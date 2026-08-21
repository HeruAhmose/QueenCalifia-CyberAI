from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/edge/verify-final-host-manual-controls.py"
spec = importlib.util.spec_from_file_location("qc_final_host_manual_controls", SCRIPT)
assert spec is not None and spec.loader is not None
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def final_host():
    return {
        "schema": "queen-califia-final-host-evidence-v1",
        "machine_evidence_ready_for_review": True,
        "virtualization": {"bare_metal": True},
        "authorization_marker": {"present": False},
        "identity": {"fingerprint_sha256": "a" * 64},
    }


def request():
    return {
        "schema": verifier.REQUEST_SCHEMA,
        "host_identity_fingerprint_sha256": "a" * 64,
        "bios_restore_after_power_loss": {
            "firmware_setting_observed": True,
            "controlled_ac_loss_test_performed": True,
            "automatic_power_restore_observed": True,
            "observed_at_utc": "2026-08-21T04:00:00Z",
            "evidence_reference": "bios-test-20260821",
        },
        "ups": {
            "physical_ups_present": True,
            "controlled_utility_interruption_test_performed": True,
            "host_power_continuity_or_graceful_shutdown_observed": True,
            "post_test_normal_operation_observed": True,
            "observed_at_utc": "2026-08-21T04:10:00Z",
            "evidence_reference": "ups-test-20260821",
        },
        "operator_attestation": verifier.ATTESTATION,
    }


def rejected(req, host, match: str) -> None:
    with pytest.raises(SystemExit, match=match):
        verifier.validate_request(req, host)


def test_valid_manual_control_assertions_are_structurally_accepted() -> None:
    verifier.validate_request(request(), final_host())


def test_wrong_final_host_identity_is_rejected() -> None:
    req = request()
    req["host_identity_fingerprint_sha256"] = "b" * 64
    rejected(req, final_host(), "does not match the final-host identity fingerprint")


def test_virtual_machine_final_host_is_rejected() -> None:
    host = final_host()
    host["virtualization"]["bare_metal"] = False
    rejected(request(), host, "bare-metal final host")


def test_bios_assertions_cannot_be_partial() -> None:
    for field in (
        "firmware_setting_observed",
        "controlled_ac_loss_test_performed",
        "automatic_power_restore_observed",
    ):
        req = copy.deepcopy(request())
        req["bios_restore_after_power_loss"][field] = False
        rejected(req, final_host(), field)


def test_ups_assertions_cannot_be_partial() -> None:
    for field in (
        "physical_ups_present",
        "controlled_utility_interruption_test_performed",
        "host_power_continuity_or_graceful_shutdown_observed",
        "post_test_normal_operation_observed",
    ):
        req = copy.deepcopy(request())
        req["ups"][field] = False
        rejected(req, final_host(), field)


def test_attestation_cannot_claim_automatic_physical_verification() -> None:
    req = request()
    req["operator_attestation"] = "The software verifier proves the physical tests happened."
    rejected(req, final_host(), "physical-test/human-review boundary")
