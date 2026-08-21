#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "scripts/edge/verify-render-source-disposition.py"
TESTS = ROOT / "tests/test_render_source_disposition.py"


def require(text: str, *needles: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"Render source disposition contract missing: {missing}")


def main() -> int:
    if not VERIFIER.is_file():
        raise SystemExit("missing Render source disposition verifier")
    if not TESTS.is_file():
        raise SystemExit("missing Render source disposition regression tests")

    text = VERIFIER.read_text(encoding="utf-8")
    require(
        text,
        'EVIDENCE_ROOT = Path("/srv/queen-califia/evidence/render-source-disposition")',
        'FORMER_PATH = "/opt/render/project/src/backend/data/qc_scans.db"',
        '"current_status": "unrecoverable-unverified"',
        '"requested_disposition": "formally-dispositioned"',
        '"provider_recovery_unavailable": True',
        '"verified_absent": False',
        '"captured": False',
        '"production_migration_verified": False',
        '"eligible_for_human_review": True',
        '"automatic_ledger_promotion": False',
        '"authorization_modified": False',
        '"deployment_ledger_modified": False',
        "provider-evidence symlinks are forbidden",
        "refusing to overwrite existing verification",
        "RENDER_SOURCE_LEDGER_UPDATED=NO",
        "RENDER_SOURCE_AUTHORIZATION_UPDATED=NO",
    )

    for forbidden in (
        "argparse",
        "sys.argv",
        "sovereign-edge-deployment-state.json",
        '"verified_absent": True',
        '"captured": True',
        '"production_migration_verified": True',
        '"automatic_ledger_promotion": True',
        "AUTH_MARKER.write_text",
        "AUTH_MARKER.unlink",
    ):
        if forbidden in text:
            raise SystemExit(f"Render disposition verifier contains forbidden authority/path surface: {forbidden}")

    tests = TESTS.read_text(encoding="utf-8")
    require(
        tests,
        "test_valid_formal_disposition_is_review_eligible",
        "test_cannot_claim_verified_absent",
        "test_cannot_claim_capture_or_migration",
        "test_provider_evidence_is_required",
        "test_operator_attestation_cannot_rewrite_history",
    )

    print(
        "Render source disposition guard verified: fixed evidence paths, retained provider evidence required, "
        "formal disposition remains review-only, and absence/capture/migration claims remain forbidden"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
