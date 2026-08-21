#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EVIDENCE_ROOT = Path("/srv/queen-califia/evidence/render-source-disposition")
REQUEST_PATH = EVIDENCE_ROOT / "request.json"
PROVIDER_EVIDENCE_ROOT = EVIDENCE_ROOT / "provider-evidence"
VERIFICATION_PATH = EVIDENCE_ROOT / "verification.json"
AUTH_MARKER = Path("/srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED")
FORMER_PATH = "/opt/render/project/src/backend/data/qc_scans.db"
REQUEST_SCHEMA = "queen-califia-render-source-disposition-request-v1"
OUTPUT_SCHEMA = "queen-califia-render-source-disposition-verification-v1"
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def fail(message: str) -> None:
    raise SystemExit(f"RENDER_DISPOSITION_ERROR={message}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_request(request: dict[str, Any], evidence_records: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []

    exact = {
        "schema": REQUEST_SCHEMA,
        "provider": "render",
        "former_path": FORMER_PATH,
        "current_status": "unrecoverable-unverified",
        "requested_disposition": "formally-dispositioned",
        "provider_recovery_unavailable": True,
        "provider_contact_attempted": True,
        "verified_absent": False,
        "captured": False,
        "production_migration_verified": False,
    }
    for key, expected in exact.items():
        if request.get(key) != expected:
            errors.append(f"{key} must equal {expected!r}")

    observed_at = request.get("provider_evidence_observed_at_utc")
    if not isinstance(observed_at, str) or not UTC_RE.fullmatch(observed_at):
        errors.append("provider_evidence_observed_at_utc must be an explicit UTC timestamp ending in Z")

    reference = request.get("provider_evidence_reference")
    if not isinstance(reference, str) or len(reference.strip()) < 8:
        errors.append("provider_evidence_reference must identify the retained provider interaction")

    summary = request.get("disposition_rationale")
    if not isinstance(summary, str) or len(summary.strip()) < 40:
        errors.append("disposition_rationale must contain a substantive review rationale")

    attestation = request.get("operator_attestation")
    if attestation != "I attest that this request does not claim the historical source was recovered, migrated, or verified absent.":
        errors.append("operator_attestation must preserve the unrecoverable-unverified evidence boundary")

    if not evidence_records:
        errors.append("at least one retained provider-evidence file is required")
    for record in evidence_records:
        if record.get("size", 0) <= 0:
            errors.append("provider-evidence files must be non-empty")
        if not SHA256_RE.fullmatch(str(record.get("sha256", ""))):
            errors.append("provider-evidence file SHA-256 must be lowercase 64-hex")

    return errors


def collect_provider_evidence() -> list[dict[str, Any]]:
    if not PROVIDER_EVIDENCE_ROOT.is_dir():
        fail(f"missing canonical provider evidence directory: {PROVIDER_EVIDENCE_ROOT}")

    records: list[dict[str, Any]] = []
    for path in sorted(PROVIDER_EVIDENCE_ROOT.rglob("*")):
        if path.is_symlink():
            fail("provider-evidence symlinks are forbidden")
        if path.is_dir():
            continue
        if not path.is_file():
            fail("provider-evidence entries must be regular files")
        relative = path.relative_to(PROVIDER_EVIDENCE_ROOT).as_posix()
        records.append(
            {
                "relative_path_sha256": hashlib.sha256(relative.encode("utf-8")).hexdigest(),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return records


def main() -> int:
    if os.geteuid() != 0:
        fail("run as root so the canonical evidence store is read consistently")
    if AUTH_MARKER.exists():
        fail("authorization marker exists; preauthorization disposition verification refused")
    if not REQUEST_PATH.is_file() or REQUEST_PATH.is_symlink():
        fail(f"missing canonical non-symlink request: {REQUEST_PATH}")
    if VERIFICATION_PATH.exists():
        fail(f"refusing to overwrite existing verification: {VERIFICATION_PATH}")

    try:
        request = json.loads(REQUEST_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid request JSON: {exc}")
    if not isinstance(request, dict):
        fail("request JSON must be an object")

    evidence_records = collect_provider_evidence()
    errors = validate_request(request, evidence_records)
    if errors:
        for error in errors:
            print(f"BLOCKER={error}")
        fail(f"disposition request failed validation with {len(errors)} blocker(s)")

    request_sha256 = sha256_file(REQUEST_PATH)
    evidence_set_digest = hashlib.sha256(
        json.dumps(evidence_records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    output = {
        "schema": OUTPUT_SCHEMA,
        "verified_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "former_path": FORMER_PATH,
        "provider": "render",
        "prior_status": "unrecoverable-unverified",
        "requested_disposition": "formally-dispositioned",
        "request_sha256": request_sha256,
        "provider_evidence_file_count": len(evidence_records),
        "provider_evidence_set_sha256": evidence_set_digest,
        "provider_evidence_files": evidence_records,
        "eligible_for_human_review": True,
        "automatic_ledger_promotion": False,
        "verified_absent": False,
        "captured": False,
        "production_migration_verified": False,
        "authorization_modified": False,
        "deployment_ledger_modified": False,
    }

    VERIFICATION_PATH.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(VERIFICATION_PATH, 0o600)
    verification_sha256 = sha256_file(VERIFICATION_PATH)

    print("RENDER_SOURCE_DISPOSITION=ELIGIBLE_FOR_HUMAN_REVIEW")
    print(f"RENDER_SOURCE_DISPOSITION_VERIFICATION={VERIFICATION_PATH}")
    print(f"RENDER_SOURCE_DISPOSITION_VERIFICATION_SHA256={verification_sha256}")
    print("RENDER_SOURCE_VERIFIED_ABSENT=NO")
    print("RENDER_SOURCE_CAPTURED=NO")
    print("RENDER_SOURCE_MIGRATION_VERIFIED=NO")
    print("RENDER_SOURCE_LEDGER_UPDATED=NO")
    print("RENDER_SOURCE_AUTHORIZATION_UPDATED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
