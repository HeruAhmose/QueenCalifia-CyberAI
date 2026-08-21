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
AUTH_MARKER = Path("/srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED")
CANONICAL_REPO_ROOT = Path("/opt/queen-califia")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def fail(message: str) -> None:
    raise SystemExit(f"VALKEY_AUTHORITY_EVIDENCE_ERROR={message}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        fail(f"missing canonical non-symlink evidence file: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path.name}: {exc}")
    raise AssertionError


def newest(prefix: str) -> Path:
    matches = sorted(EVIDENCE_ROOT.glob(f"{prefix}-*.json"), key=lambda p: p.stat().st_mtime_ns, reverse=True)
    if not matches:
        fail(f"no {prefix} evidence found")
    path = matches[0]
    if path.is_symlink():
        fail(f"symlink evidence forbidden: {path}")
    return path


def require_bool(record: dict[str, Any], path: tuple[str, ...], expected: bool) -> None:
    current: Any = record
    for key in path:
        if not isinstance(current, dict) or key not in current:
            fail("missing evidence field: " + ".".join(path))
        current = current[key]
    if current is not expected:
        fail(f"evidence field {'.'.join(path)} must be {expected}")


def validate(host: dict[str, Any], pki: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    if host.get("schema") != "queen-califia-final-host-evidence-v1":
        fail("unsupported final-host evidence schema")
    if pki.get("schema") != "queen-califia-final-valkey-pki-evidence-v1":
        fail("unsupported final-Valkey-PKI evidence schema")
    if runtime.get("schema") != "queen-califia-sovereign-edge-runtime-evidence-v2":
        fail("runtime evidence must use v2 host-bound preauthorization schema")
    if runtime.get("mode") != "--preauth":
        fail("runtime evidence is not preauthorization evidence")

    require_bool(host, ("machine_evidence_ready_for_review",), True)
    require_bool(host, ("authorization_marker", "present"), False)
    require_bool(host, ("virtualization", "bare_metal"), True)
    require_bool(pki, ("bare_metal",), True)
    require_bool(pki, ("repository_clean",), True)
    require_bool(pki, ("pki_material_verified",), True)
    require_bool(pki, ("live_valkey_authority_verified",), False)
    require_bool(pki, ("eligible_for_pki_generated_review",), True)
    require_bool(pki, ("eligible_for_authority_verified_review",), False)
    require_bool(runtime, ("authorization_marker_present",), False)
    require_bool(runtime, ("repository_clean",), True)

    for claim in (
        "no_host_ports_published",
        "valkey_tls_verified",
        "valkey_plaintext_refused",
        "valkey_client_certificate_required",
        "valkey_health_client_verified",
        "valkey_api_client_verified",
        "valkey_worker_client_verified",
        "unauthorized_application_runtime_absent",
    ):
        require_bool(runtime, ("claims", claim), True)
    require_bool(runtime, ("claims", "authorized_runtime_probed"), False)

    host_fp = str(host.get("identity", {}).get("fingerprint_sha256") or "")
    pki_fp = str(pki.get("host_identity_fingerprint_sha256") or "")
    runtime_fp = str(runtime.get("host_identity_fingerprint_sha256") or "")
    if not HEX64.fullmatch(host_fp) or host_fp != pki_fp or host_fp != runtime_fp:
        fail("final-host, offline PKI, and live runtime host identity fingerprints do not match")

    host_head = str(host.get("repository", {}).get("head") or "")
    pki_head = str(pki.get("git_head") or "")
    runtime_head = str(runtime.get("git_head") or "")
    if not HEX40.fullmatch(host_head) or host_head != pki_head or host_head != runtime_head:
        fail("final-host, offline PKI, and live runtime Git heads do not match")

    pki_fingerprints = pki.get("certificate_fingerprints_sha256")
    runtime_fingerprints = runtime.get("valkey_certificate_fingerprints_sha256")
    if not isinstance(pki_fingerprints, dict) or not isinstance(runtime_fingerprints, dict):
        fail("certificate fingerprint maps are missing")
    if pki_fingerprints != runtime_fingerprints:
        fail("offline PKI and live runtime certificate fingerprints do not match")

    expected_names = {"ca", "server", "health", "api", "worker"}
    if set(pki_fingerprints) != expected_names:
        fail("unexpected PKI certificate identity set")
    for name, digest in pki_fingerprints.items():
        if not HEX64.fullmatch(str(digest)):
            fail(f"invalid SHA-256 certificate fingerprint for {name}")

    running_apps = runtime.get("running_application_containers")
    if running_apps != []:
        fail("preauthorization runtime evidence contains running application containers")

    boot_id = str(runtime.get("boot_id") or "")
    if not re.fullmatch(r"[0-9a-f-]{36}", boot_id):
        fail("runtime boot_id is invalid")

    return {
        "same_final_host": True,
        "same_repository_head": True,
        "same_valkey_pki": True,
        "live_mtls_authority_verified": True,
        "plaintext_refusal_verified": True,
        "client_certificate_requirement_verified": True,
        "all_intended_client_identities_verified": True,
        "no_host_ports_published_verified": True,
        "unauthorized_application_runtime_absent_verified": True,
        "authorization_marker_absent_verified": True,
        "eligible_for_authority_verified_review": True,
        "automatic_ledger_promotion": False,
        "authorization_modified": False,
        "deployment_ledger_modified": False,
    }


def main() -> int:
    if os.geteuid() != 0:
        fail("run as root so the preauthorization authority boundary is evaluated consistently")
    if AUTH_MARKER.exists():
        fail("authorization marker exists; final Valkey authority evidence binding refused")
    if not (CANONICAL_REPO_ROOT / ".git").exists():
        fail("canonical repository checkout is missing")

    host_path = newest("final-host")
    pki_path = newest("final-valkey-pki")
    runtime_path = newest("runtime")

    host = load_json(host_path)
    pki = load_json(pki_path)
    runtime = load_json(runtime_path)
    validation = validate(host, pki, runtime)

    output = EVIDENCE_ROOT / (
        "final-valkey-authority-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json"
    )
    if output.exists():
        fail(f"refusing to overwrite existing evidence: {output}")

    record = {
        "schema": "queen-califia-final-valkey-authority-evidence-v1",
        "bound_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_evidence": {
            "final_host": {
                "name": host_path.name,
                "sha256": sha256_file(host_path),
            },
            "final_valkey_pki": {
                "name": pki_path.name,
                "sha256": sha256_file(pki_path),
            },
            "runtime_preauthorization": {
                "name": runtime_path.name,
                "sha256": sha256_file(runtime_path),
                "boot_id": runtime.get("boot_id"),
            },
        },
        "host_identity_fingerprint_sha256": runtime.get("host_identity_fingerprint_sha256"),
        "git_head": runtime.get("git_head"),
        "valkey_certificate_fingerprints_sha256": runtime.get("valkey_certificate_fingerprints_sha256"),
        **validation,
    }
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(output, 0o600)
    digest = sha256_file(output)

    print("FINAL_VALKEY_AUTHORITY_EVIDENCE=PASS")
    print("FINAL_VALKEY_AUTHORITY_VERIFIED=ELIGIBLE_FOR_HUMAN_REVIEW")
    print(f"FINAL_VALKEY_AUTHORITY_EVIDENCE_PATH={output}")
    print(f"FINAL_VALKEY_AUTHORITY_EVIDENCE_SHA256={digest}")
    print("FINAL_VALKEY_AUTHORITY_LEDGER_UPDATED=NO")
    print("FINAL_VALKEY_AUTHORIZATION_UPDATED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
