#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EVIDENCE_ROOT = Path("/srv/queen-califia/evidence")
AUTH_MARKER = Path("/srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED")
CANONICAL_REPO_ROOT = Path("/opt/queen-califia")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_CERTS = {"ca", "server", "health", "api", "worker"}


def fail(message: str) -> None:
    raise SystemExit(f"HYPERV_RUNTIME_BINDING_ERROR={message}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        fail(f"required evidence must be a regular non-symlink file: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path.name}: {exc}")
    if not isinstance(data, dict):
        fail(f"JSON root must be an object: {path.name}")
    return data


def newest_runtime() -> Path:
    matches = sorted(EVIDENCE_ROOT.glob("runtime-*.json"), key=lambda p: p.stat().st_mtime_ns, reverse=True)
    if not matches:
        fail("no runtime evidence found")
    return matches[0]


def guest_vm_id() -> str:
    path = Path("/sys/class/dmi/id/product_uuid")
    try:
        value = path.read_text(encoding="utf-8", errors="replace").strip().lower()
    except (FileNotFoundError, PermissionError, OSError):
        value = ""
    if not UUID_RE.fullmatch(value):
        fail("Hyper-V guest DMI product_uuid is missing or invalid")
    return value


def require_bool(record: dict[str, Any], path: tuple[str, ...], expected: bool) -> None:
    current: Any = record
    for key in path:
        if not isinstance(current, dict) or key not in current:
            fail("missing runtime evidence field: " + ".".join(path))
        current = current[key]
    if current is not expected:
        fail(f"runtime evidence field {'.'.join(path)} must be {expected}")


def main() -> int:
    if os.geteuid() != 0:
        fail("run as root so the preauthorization boundary is evaluated consistently")
    if AUTH_MARKER.exists():
        fail("authorization marker exists; Hyper-V runtime binding refused")

    virt = subprocess.run(["systemd-detect-virt", "-v"], capture_output=True, text=True, check=False)
    if virt.returncode != 0 or virt.stdout.strip().lower() != "microsoft":
        fail(f"expected Microsoft virtualization, detected {virt.stdout.strip() or 'unknown'}")

    if not (CANONICAL_REPO_ROOT / ".git").exists():
        fail("canonical repository checkout is missing")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=CANONICAL_REPO_ROOT, text=True).strip()
    if not HEX40.fullmatch(head):
        fail("canonical repository Git head is invalid")
    status = subprocess.check_output(["git", "status", "--porcelain"], cwd=CANONICAL_REPO_ROOT, text=True).strip()
    if status:
        fail("canonical repository checkout must be clean")

    runtime_path = newest_runtime()
    runtime = load_json(runtime_path)
    if runtime.get("schema") != "queen-califia-sovereign-edge-runtime-evidence-v2":
        fail("runtime evidence must use v2 schema")
    if runtime.get("mode") != "--preauth":
        fail("runtime evidence is not preauthorization evidence")
    if runtime.get("git_head") != head:
        fail("runtime evidence Git head differs from current canonical checkout")
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
    if runtime.get("running_application_containers") != []:
        fail("preauthorization runtime evidence contains running application containers")

    guest_fp = str(runtime.get("host_identity_fingerprint_sha256") or "")
    if not HEX64.fullmatch(guest_fp):
        fail("runtime guest host fingerprint is invalid")
    certs = runtime.get("valkey_certificate_fingerprints_sha256")
    if not isinstance(certs, dict) or set(certs) != EXPECTED_CERTS:
        fail("runtime certificate fingerprint identity set is invalid")
    if any(not HEX64.fullmatch(str(v)) for v in certs.values()):
        fail("runtime certificate fingerprint map contains invalid SHA-256 values")

    record = {
        "schema": "queen-califia-hyperv-runtime-binding-evidence-v1",
        "bound_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "virtualization": "microsoft",
        "hyperv_guest_vm_id_raw": guest_vm_id(),
        "guest_host_identity_fingerprint_sha256": guest_fp,
        "git_head": head,
        "runtime_source": {
            "name": runtime_path.name,
            "sha256": sha256_file(runtime_path),
            "boot_id": runtime.get("boot_id"),
        },
        "valkey_certificate_fingerprints_sha256": certs,
        "runtime_preauthorization_claims_verified": True,
        "authorization_marker_absent_verified": True,
        "authorization_modified": False,
        "deployment_ledger_modified": False,
    }

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = EVIDENCE_ROOT / f"hyperv-runtime-binding-{stamp}.json"
    if output.exists():
        fail(f"refusing to overwrite existing evidence: {output}")
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(output, 0o600)
    digest = sha256_file(output)

    print("HYPERV_RUNTIME_BINDING_EVIDENCE=PASS")
    print(f"HYPERV_RUNTIME_BINDING_EVIDENCE_PATH={output}")
    print(f"HYPERV_RUNTIME_BINDING_EVIDENCE_SHA256={digest}")
    print(f"HYPERV_GUEST_VM_ID_RAW={record['hyperv_guest_vm_id_raw']}")
    print("HYPERV_RUNTIME_BINDING_LEDGER_UPDATED=NO")
    print("HYPERV_RUNTIME_BINDING_AUTHORIZATION_UPDATED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
