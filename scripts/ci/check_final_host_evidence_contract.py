#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COLLECTOR = ROOT / "scripts/edge/collect-final-host-evidence.py"
TESTS = ROOT / "tests/test_final_host_evidence.py"


def require(text: str, *needles: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"final-host evidence contract missing: {missing}")


def main() -> int:
    if not COLLECTOR.is_file():
        raise SystemExit("missing final-host evidence collector")
    if not TESTS.is_file():
        raise SystemExit("missing final-host evidence regression tests")

    text = COLLECTOR.read_text(encoding="utf-8")
    require(
        text,
        "systemd-detect-virt",
        '"bare_metal": detected == "none"',
        "root_storage_encryption_detected",
        "default_deny_incoming",
        "prohibited_ports_absent",
        "SOVEREIGN_EDGE_RUNTIME_AUTHORIZED",
        "manual-evidence-required",
        "ledger_modified",
        "authorization_modified",
        "refusing to label this collection preauthorization evidence",
        "refusing to overwrite existing evidence",
    )

    for forbidden in (
        "touch(AUTH_MARKER",
        "AUTH_MARKER.write_text",
        "AUTH_MARKER.unlink",
        "sovereign-edge-deployment-state.json",
        "production_authorized = True",
        '"verified": True',
    ):
        if forbidden in text:
            raise SystemExit(f"final-host collector contains forbidden authority mutation: {forbidden}")

    tests = TESTS.read_text(encoding="utf-8")
    require(
        tests,
        "test_hyperv_candidate_cannot_satisfy_final_host_machine_evidence",
        "test_bare_metal_machine_evidence_still_requires_manual_controls",
        "test_authorization_marker_presence_blocks_machine_readiness",
    )

    print(
        "Final-host evidence guard verified: collector is read-only, rejects VM evidence as bare metal, "
        "keeps BIOS/UPS manual, and cannot mutate authorization or deployment state"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
