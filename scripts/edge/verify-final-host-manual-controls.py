#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EVIDENCE_ROOT = Path("/srv/queen-califia/evidence")
DOSSIER_ROOT = EVIDENCE_ROOT / "final-host-manual-controls"
REQUEST_PATH = DOSSIER_ROOT / "request.json"
BIOS_EVIDENCE_ROOT = DOSSIER_ROOT / "bios-evidence"
UPS_EVIDENCE_ROOT = DOSSIER_ROOT / "ups-evidence"
VERIFICATION_PATH = DOSSIER_ROOT / "verification.json"
AUTH_MARKER = Path("/srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED")
REQUEST_SCHEMA = "queen-califia-final-host-manual-controls-request-v1"
OUTPUT_SCHEMA = "queen-califia-final-host-manual-controls-verification-v1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
ATTESTATION = (
    "I attest that the BIOS restore-after-power-loss and UPS results in this request describe physical tests "
    "performed on the selected final production host, and that this verifier only prepares those assertions for human review."
)


def fail(message: str) -> None:
    raise SystemExit(f"FINAL_HOST_MANUAL_CONTROLS_ERROR={message}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def newest_final_host() -> Path:
    matches = sorted(
        EVIDENCE_ROOT.glob("final-host-*.json"),
        key=lambda path: path.stat().st_mtime_ns,
        reverse=True,
    )
    if not matches:
        fail("no final-host machine evidence found")
    path = matches[0]
    if path.is_symlink() or not path.is_file():
        fail("latest final-host evidence must be a regular non-symlink file")
    return path


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        fail(f"required JSON must be a regular non-symlink file: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path.name}: {exc}")
    if not isinstance(data, dict):
        fail(f"JSON root must be an object: {path.name}")
    return data


def collect_files(root: Path, label: str) -> list[dict[str, Any]]:
    if not root.is_dir() or root.is_symlink():
        fail(f"missing canonical non-symlink {label} directory: {root}")
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            fail(f"{label} symlinks are forbidden: {path}")
        if not path.is_file():
            continue
        size = path.stat().st_size
        if size <= 0:
            fail(f"{label} evidence files must be non-empty: {path.name}")
        relative = path.relative_to(root).as_posix()
        records.append(
            {
                "relative_path_sha256": hashlib.sha256(relative.encode("utf-8")).hexdigest(),
                "size": size,
                "sha256": sha256_file(path),
            }
        )
    if not records:
        fail(f"at least one retained {label} evidence file is required")
    return records


def validate_request(request: dict[str, Any], final_host: dict[str, Any]) -> None:
    if request.get("schema") != REQUEST_SCHEMA:
        fail("unsupported manual-controls request schema")
    if final_host.get("schema") != "queen-califia-final-host-evidence-v1":
        fail("unsupported final-host evidence schema")
    if final_host.get("machine_evidence_ready_for_review") is not True:
        fail("final-host machine evidence is not ready for review")
    if final_host.get("virtualization", {}).get("bare_metal") is not True:
        fail("manual controls may only be bound to the selected bare-metal final host")
    if final_host.get("authorization_marker", {}).get("present") is not False:
        fail("final-host evidence was not collected with authorization closed")

    final_fp = str(final_host.get("identity", {}).get("fingerprint_sha256") or "")
    requested_fp = str(request.get("host_identity_fingerprint_sha256") or "")
    if not HEX64.fullmatch(final_fp) or requested_fp != final_fp:
        fail("manual-controls request does not match the final-host identity fingerprint")

    for section_name in ("bios_restore_after_power_loss", "ups"):
        section = request.get(section_name)
        if not isinstance(section, dict):
            fail(f"missing {section_name} section")
        observed_at = section.get("observed_at_utc")
        if not isinstance(observed_at, str) or not UTC_RE.fullmatch(observed_at):
            fail(f"{section_name}.observed_at_utc must be UTC ISO-8601 ending in Z")
        reference = section.get("evidence_reference")
        if not isinstance(reference, str) or len(reference.strip()) < 8:
            fail(f"{section_name}.evidence_reference must be substantive")

    bios = request["bios_restore_after_power_loss"]
    for key in (
        "firmware_setting_observed",
        "controlled_ac_loss_test_performed",
        "automatic_power_restore_observed",
    ):
        if bios.get(key) is not True:
            fail(f"bios_restore_after_power_loss.{key} must be true only after the physical test")

    ups = request["ups"]
    for key in (
        "physical_ups_present",
        "controlled_utility_interruption_test_performed",
        "host_power_continuity_or_graceful_shutdown_observed",
        "post_test_normal_operation_observed",
    ):
        if ups.get(key) is not True:
            fail(f"ups.{key} must be true only after the physical test")

    if request.get("operator_attestation") != ATTESTATION:
        fail("operator_attestation must preserve the exact physical-test/human-review boundary")


def main() -> int:
    if os.geteuid() != 0:
        fail("run as root so the preauthorization evidence boundary is evaluated consistently")
    if AUTH_MARKER.exists():
        fail("authorization marker exists; preauthorization manual-control verification refused")
    if VERIFICATION_PATH.exists():
        fail(f"refusing to overwrite existing verification: {VERIFICATION_PATH}")

    final_host_path = newest_final_host()
    final_host = load_json(final_host_path)
    request = load_json(REQUEST_PATH)
    validate_request(request, final_host)
    bios_records = collect_files(BIOS_EVIDENCE_ROOT, "BIOS")
    ups_records = collect_files(UPS_EVIDENCE_ROOT, "UPS")

    record = {
        "schema": OUTPUT_SCHEMA,
        "verified_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "host_identity_fingerprint_sha256": request["host_identity_fingerprint_sha256"],
        "source_final_host_evidence": {
            "name": final_host_path.name,
            "sha256": sha256_file(final_host_path),
        },
        "request_sha256": sha256_file(REQUEST_PATH),
        "bios_evidence_files": bios_records,
        "ups_evidence_files": ups_records,
        "bios_physical_test_assertions_structurally_verified": True,
        "ups_physical_test_assertions_structurally_verified": True,
        "eligible_for_bios_restore_after_power_loss_review": True,
        "eligible_for_ups_review": True,
        "physical_truth_automatically_verified": False,
        "human_review_required": True,
        "automatic_ledger_promotion": False,
        "authorization_modified": False,
        "deployment_ledger_modified": False,
    }
    DOSSIER_ROOT.mkdir(parents=True, exist_ok=True)
    VERIFICATION_PATH.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(VERIFICATION_PATH, 0o600)
    digest = sha256_file(VERIFICATION_PATH)

    print("FINAL_HOST_MANUAL_CONTROLS=ELIGIBLE_FOR_HUMAN_REVIEW")
    print("FINAL_HOST_BIOS_RESTORE_AFTER_POWER_LOSS=ELIGIBLE_FOR_HUMAN_REVIEW")
    print("FINAL_HOST_UPS=ELIGIBLE_FOR_HUMAN_REVIEW")
    print(f"FINAL_HOST_MANUAL_CONTROLS_VERIFICATION={VERIFICATION_PATH}")
    print(f"FINAL_HOST_MANUAL_CONTROLS_VERIFICATION_SHA256={digest}")
    print("FINAL_HOST_PHYSICAL_TRUTH_AUTOMATICALLY_VERIFIED=NO")
    print("FINAL_HOST_MANUAL_CONTROLS_LEDGER_UPDATED=NO")
    print("FINAL_HOST_MANUAL_CONTROLS_AUTHORIZATION_UPDATED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
