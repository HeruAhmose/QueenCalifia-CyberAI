#!/usr/bin/env python3
from __future__ import annotations

import py_compile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "scripts/edge/verify-final-host-manual-controls.py"
TESTS = ROOT / "tests/test_final_host_manual_controls.py"


def require(text: str, *needles: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"final-host manual controls contract missing: {missing}")


def main() -> int:
    if not VERIFIER.is_file():
        raise SystemExit("missing final-host manual controls verifier")
    if not TESTS.is_file():
        raise SystemExit("missing final-host manual controls regression tests")

    py_compile.compile(str(VERIFIER), doraise=True)
    text = VERIFIER.read_text(encoding="utf-8")
    require(
        text,
        'DOSSIER_ROOT = EVIDENCE_ROOT / "final-host-manual-controls"',
        'BIOS_EVIDENCE_ROOT = DOSSIER_ROOT / "bios-evidence"',
        'UPS_EVIDENCE_ROOT = DOSSIER_ROOT / "ups-evidence"',
        '"queen-califia-final-host-evidence-v1"',
        "manual controls may only be bound to the selected bare-metal final host",
        "manual-controls request does not match the final-host identity fingerprint",
        "controlled_ac_loss_test_performed",
        "automatic_power_restore_observed",
        "controlled_utility_interruption_test_performed",
        "host_power_continuity_or_graceful_shutdown_observed",
        "at least one retained BIOS evidence file is required",
        "at least one retained UPS evidence file is required",
        '"physical_truth_automatically_verified": False',
        '"human_review_required": True',
        '"automatic_ledger_promotion": False',
        '"authorization_modified": False',
        '"deployment_ledger_modified": False',
        "FINAL_HOST_PHYSICAL_TRUTH_AUTOMATICALLY_VERIFIED=NO",
        "FINAL_HOST_MANUAL_CONTROLS_LEDGER_UPDATED=NO",
        "FINAL_HOST_MANUAL_CONTROLS_AUTHORIZATION_UPDATED=NO",
    )

    for forbidden in (
        "argparse",
        "sys.argv",
        "sovereign-edge-deployment-state.json",
        '"physical_truth_automatically_verified": True',
        '"automatic_ledger_promotion": True',
        "AUTH_MARKER.write_text",
        "AUTH_MARKER.unlink",
    ):
        if forbidden in text:
            raise SystemExit(f"manual-control verifier contains forbidden automatic-authority surface: {forbidden}")

    tests = TESTS.read_text(encoding="utf-8")
    require(
        tests,
        "test_valid_manual_control_assertions_are_structurally_accepted",
        "test_wrong_final_host_identity_is_rejected",
        "test_virtual_machine_final_host_is_rejected",
        "test_bios_assertions_cannot_be_partial",
        "test_ups_assertions_cannot_be_partial",
        "test_attestation_cannot_claim_automatic_physical_verification",
    )

    print(
        "Final-host manual controls guard verified: BIOS/UPS dossiers require physical-test assertions and retained evidence, "
        "must bind to the selected bare-metal host, remain human-reviewed, and cannot mutate authorization or ledger state"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
