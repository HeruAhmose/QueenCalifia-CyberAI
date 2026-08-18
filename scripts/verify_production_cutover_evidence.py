#!/usr/bin/env python3
"""Validate and fingerprint a production-cutover evidence bundle from stdin.

The bundle is intentionally secret-free. This verifier proves that the required
capture, migration, disposition, backup/restore, and authority-probe evidence is
present before an operator may consider removing legacy storage bindings. It
never performs the cutover and never marks topology gates complete.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from typing import Any

KIND = "queen-califia-production-cutover-evidence"
VERSION = 1
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REQUIRED_SOURCES = {
    "primary-runtime-db",
    "evolution-db",
    "threat-intelligence-db",
    "live-scanner-db",
    "api-keys",
    "audit-log",
    "spki",
}
REQUIRED_DISPOSITIONS = {
    "api-keys",
    "audit-log",
    "spki",
    "vulnerability",
    "live-scanner",
}
FORBIDDEN_KEY_FRAGMENTS = (
    "password",
    "passwd",
    "private_key",
    "secret_value",
    "token_value",
    "database_url",
    "connection_string",
    "api_key_value",
)
FORBIDDEN_VALUE_PATTERNS = (
    re.compile(r"postgres(?:ql)?://", re.IGNORECASE),
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
)


def _fail(message: str) -> None:
    raise RuntimeError(message)


def _require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    return value


def _require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(f"{label} must be an array")
    return value


def _require_true(value: Any, label: str) -> None:
    if value is not True:
        _fail(f"{label} must be true")


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        _fail(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _reject_secrets(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_lower = str(key).lower()
            if any(fragment in key_lower for fragment in FORBIDDEN_KEY_FRAGMENTS):
                _fail(f"evidence contains forbidden secret-bearing field at {path}.{key}")
            _reject_secrets(child, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secrets(child, f"{path}[{index}]")
        return
    if isinstance(value, str):
        for pattern in FORBIDDEN_VALUE_PATTERNS:
            if pattern.search(value):
                _fail(f"evidence contains forbidden credential/connection material at {path}")


def _validate_sources(source_capture: dict[str, Any]) -> None:
    _require_true(
        source_capture.get("captured_before_pod_replacement"),
        "source_capture.captured_before_pod_replacement",
    )
    pod_uid = source_capture.get("api_pod_uid")
    if not isinstance(pod_uid, str) or not pod_uid.strip():
        _fail("source_capture.api_pod_uid is required")
    image_digest = source_capture.get("api_image_digest")
    if not isinstance(image_digest, str) or not IMAGE_DIGEST_RE.fullmatch(image_digest):
        _fail("source_capture.api_image_digest must be sha256:<64 lowercase hex>")

    artifacts = _require_list(source_capture.get("artifacts"), "source_capture.artifacts")
    by_name: dict[str, dict[str, Any]] = {}
    for raw in artifacts:
        entry = _require_dict(raw, "source_capture.artifacts[]")
        name = entry.get("name")
        if name in by_name:
            _fail(f"duplicate source artifact evidence: {name}")
        if name not in REQUIRED_SOURCES:
            _fail(f"unrecognized source artifact evidence: {name}")
        status = entry.get("status")
        if status == "captured":
            _require_sha256(entry.get("sha256"), f"source artifact {name}.sha256")
        elif status == "verified-absent":
            _require_true(entry.get("checked"), f"source artifact {name}.checked")
            reason = entry.get("absence_reason")
            if not isinstance(reason, str) or not reason.strip():
                _fail(f"source artifact {name} requires absence_reason")
            if "sha256" in entry:
                _fail(f"verified-absent source artifact {name} must not claim a sha256")
        else:
            _fail(f"source artifact {name} has invalid status")
        by_name[name] = entry
    missing = sorted(REQUIRED_SOURCES - set(by_name))
    if missing:
        _fail(f"missing source artifact evidence: {', '.join(missing)}")


def _validate_dispositions(dispositions: Any) -> None:
    records = _require_list(dispositions, "dispositions")
    seen: set[str] = set()
    for raw in records:
        entry = _require_dict(raw, "dispositions[]")
        kind = entry.get("kind")
        if kind in seen:
            _fail(f"duplicate disposition evidence: {kind}")
        if kind not in REQUIRED_DISPOSITIONS:
            _fail(f"unrecognized disposition evidence: {kind}")
        _require_true(entry.get("verified"), f"disposition {kind}.verified")
        _require_sha256(entry.get("evidence_sha256"), f"disposition {kind}.evidence_sha256")
        seen.add(kind)
    missing = sorted(REQUIRED_DISPOSITIONS - seen)
    if missing:
        _fail(f"missing disposition evidence: {', '.join(missing)}")


def _validate_bundle(bundle: Any) -> dict[str, Any]:
    bundle = _require_dict(bundle, "evidence")
    _reject_secrets(bundle)
    if bundle.get("kind") != KIND or bundle.get("version") != VERSION:
        _fail("unsupported production cutover evidence bundle")
    if bundle.get("environment") != "production":
        _fail("evidence.environment must be production")

    _validate_sources(_require_dict(bundle.get("source_capture"), "source_capture"))

    migration = _require_dict(bundle.get("runtime_migration"), "runtime_migration")
    _require_true(migration.get("verified"), "runtime_migration.verified")
    _require_sha256(migration.get("manifest_sha256"), "runtime_migration.manifest_sha256")

    _validate_dispositions(bundle.get("dispositions"))

    target = _require_dict(bundle.get("target_database"), "target_database")
    _require_true(target.get("empty_before_import"), "target_database.empty_before_import")
    _require_sha256(
        target.get("whole_database_manifest_sha256"),
        "target_database.whole_database_manifest_sha256",
    )

    restore = _require_dict(bundle.get("backup_restore"), "backup_restore")
    _require_true(restore.get("separate_restore_database"), "backup_restore.separate_restore_database")
    _require_true(restore.get("restore_verified"), "backup_restore.restore_verified")
    _require_sha256(restore.get("dump_sha256"), "backup_restore.dump_sha256")
    source_manifest = _require_sha256(
        restore.get("source_manifest_sha256"), "backup_restore.source_manifest_sha256"
    )
    restored_manifest = _require_sha256(
        restore.get("restored_manifest_sha256"), "backup_restore.restored_manifest_sha256"
    )
    if source_manifest != restored_manifest:
        _fail("backup_restore source/restored whole-database manifest digests differ")
    if source_manifest != target["whole_database_manifest_sha256"]:
        _fail("backup_restore source manifest does not match target database manifest")

    probes = _require_dict(bundle.get("post_cutover_authority"), "post_cutover_authority")
    for field in (
        "postgresql_probe_verified",
        "celery_redis_probe_verified",
        "legacy_writes_disabled_verified",
    ):
        _require_true(probes.get(field), f"post_cutover_authority.{field}")

    retention = _require_dict(bundle.get("source_retention"), "source_retention")
    _require_true(retention.get("legacy_sources_preserved"), "source_retention.legacy_sources_preserved")
    if retention.get("legacy_bindings_removed") is not False:
        _fail("source_retention.legacy_bindings_removed must remain false at this evidence gate")

    return bundle


def evidence_sha256(bundle: dict[str, Any]) -> str:
    raw = json.dumps(
        bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def verify_evidence_bundle(bundle: Any) -> dict[str, Any]:
    verified = _validate_bundle(bundle)
    return {
        "verified": True,
        "kind": KIND,
        "version": VERSION,
        "evidence_sha256": evidence_sha256(verified),
        "eligible_for_legacy_binding_removal_review": True,
        "ha_authorized": False,
    }


def main() -> int:
    bundle = json.load(sys.stdin)
    result = verify_evidence_bundle(bundle)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
