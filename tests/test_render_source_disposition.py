from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/edge/verify-render-source-disposition.py"

spec = importlib.util.spec_from_file_location("qc_render_disposition", SCRIPT)
assert spec is not None and spec.loader is not None
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def valid_request() -> dict:
    return {
        "schema": verifier.REQUEST_SCHEMA,
        "provider": "render",
        "former_path": verifier.FORMER_PATH,
        "current_status": "unrecoverable-unverified",
        "requested_disposition": "formally-dispositioned",
        "provider_recovery_unavailable": True,
        "provider_contact_attempted": True,
        "verified_absent": False,
        "captured": False,
        "production_migration_verified": False,
        "provider_evidence_observed_at_utc": "2026-08-21T04:30:00Z",
        "provider_evidence_reference": "Render support interaction 2026-08-21",
        "disposition_rationale": "Provider-backed evidence indicates the suspended container-local historical source cannot be recovered; retain the loss as explicit historical evidence.",
        "operator_attestation": "I attest that this request does not claim the historical source was recovered, migrated, or verified absent.",
    }


def valid_evidence() -> list[dict]:
    return [{"relative_path_sha256": "a" * 64, "size": 128, "sha256": "b" * 64}]


def test_valid_formal_disposition_is_review_eligible() -> None:
    assert verifier.validate_request(valid_request(), valid_evidence()) == []


def test_cannot_claim_verified_absent() -> None:
    request = valid_request()
    request["verified_absent"] = True
    errors = verifier.validate_request(request, valid_evidence())
    assert any("verified_absent" in error for error in errors)


def test_cannot_claim_capture_or_migration() -> None:
    request = valid_request()
    request["captured"] = True
    request["production_migration_verified"] = True
    errors = verifier.validate_request(request, valid_evidence())
    assert any("captured" in error for error in errors)
    assert any("production_migration_verified" in error for error in errors)


def test_provider_recovery_unavailable_must_be_explicit() -> None:
    request = valid_request()
    request["provider_recovery_unavailable"] = False
    errors = verifier.validate_request(request, valid_evidence())
    assert any("provider_recovery_unavailable" in error for error in errors)


def test_provider_evidence_is_required() -> None:
    errors = verifier.validate_request(valid_request(), [])
    assert any("provider-evidence" in error for error in errors)


def test_operator_attestation_cannot_rewrite_history() -> None:
    request = valid_request()
    request["operator_attestation"] = "Source is gone, treat it as absent."
    errors = verifier.validate_request(request, valid_evidence())
    assert any("operator_attestation" in error for error in errors)
