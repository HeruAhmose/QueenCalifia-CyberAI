#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

AUTH_MARKER = Path("/srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED")
CANONICAL_REPO_ROOT = Path("/opt/queen-califia")
EVIDENCE_ROOT = Path("/srv/queen-califia/evidence")
REQUIRED_COMMANDS = (
    "systemd-detect-virt",
    "findmnt",
    "lsblk",
    "swapon",
    "ufw",
    "ss",
    "git",
)
PROHIBITED_HOST_PORTS = {80, 443, 5432, 6379}


def run(command: list[str], *, cwd: Path | None = None) -> tuple[int, str, str]:
    proc = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def read_optional(path: Path) -> str | None:
    try:
        value = path.read_text(encoding="utf-8", errors="replace").strip()
    except (FileNotFoundError, PermissionError, OSError):
        return None
    return value or None


def sha256_parts(parts: Iterable[str]) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part.encode("utf-8", errors="replace"))
        digest.update(b"\0")
    return digest.hexdigest()


def parse_os_release() -> dict[str, str | None]:
    values: dict[str, str] = {}
    text = read_optional(Path("/etc/os-release")) or ""
    for raw in text.splitlines():
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        values[key] = value.strip().strip('"')
    return {
        "id": values.get("ID"),
        "version_id": values.get("VERSION_ID"),
        "pretty_name": values.get("PRETTY_NAME"),
    }


def virtualization_evidence() -> dict[str, Any]:
    rc, stdout, stderr = run(["systemd-detect-virt"])
    detected = stdout.strip().lower()
    if not detected and rc != 0:
        detected = "none"
    return {
        "detected": detected or "unknown",
        "command_rc": rc,
        "bare_metal": detected == "none",
        "error": stderr or None,
    }


def identity_fingerprint() -> dict[str, Any]:
    sources: list[str] = [socket.gethostname()]
    source_names = ["hostname"]
    for name, path in (
        ("machine-id", Path("/etc/machine-id")),
        ("dmi-product-uuid", Path("/sys/class/dmi/id/product_uuid")),
        ("dmi-board-serial", Path("/sys/class/dmi/id/board_serial")),
    ):
        value = read_optional(path)
        if value:
            sources.append(value)
            source_names.append(name)
    return {
        "fingerprint_sha256": sha256_parts(sources),
        "source_kinds": source_names,
        "raw_identifiers_included": False,
    }


def block_chain(device: str) -> list[dict[str, str]]:
    rc, stdout, _ = run(["lsblk", "-s", "-n", "-o", "NAME,TYPE,FSTYPE", device])
    if rc != 0:
        return []
    rows: list[dict[str, str]] = []
    for raw in stdout.splitlines():
        parts = raw.split(None, 2)
        if not parts:
            continue
        rows.append(
            {
                "name": parts[0],
                "type": parts[1] if len(parts) > 1 else "",
                "fstype": parts[2] if len(parts) > 2 else "",
            }
        )
    return rows


def chain_has_encryption(rows: list[dict[str, str]]) -> bool:
    for row in rows:
        if row.get("type", "").lower() == "crypt":
            return True
        if row.get("fstype", "").lower() in {"crypto_luks", "crypto_luks2"}:
            return True
    return False


def storage_evidence() -> dict[str, Any]:
    rc, root_source, root_error = run(["findmnt", "-n", "-o", "SOURCE", "/"])
    root_chain = block_chain(root_source) if rc == 0 and root_source else []
    root_encrypted = chain_has_encryption(root_chain)

    swap_rc, swap_stdout, swap_error = run(["swapon", "--show=NAME", "--noheadings"])
    swaps = [line.strip() for line in swap_stdout.splitlines() if line.strip()] if swap_rc == 0 else []
    swap_rows: list[dict[str, Any]] = []
    for device in swaps:
        chain = block_chain(device)
        swap_rows.append(
            {
                "device_name_sha256": hashlib.sha256(device.encode("utf-8")).hexdigest(),
                "encryption_detected": chain_has_encryption(chain),
            }
        )

    return {
        "root_source_kind": "block-device" if root_source.startswith("/dev/") else "other",
        "root_chain": root_chain,
        "root_storage_encryption_detected": root_encrypted,
        "root_probe_error": root_error or None,
        "swap_count": len(swaps),
        "swap_devices": swap_rows,
        "unencrypted_swap_detected": any(not item["encryption_detected"] for item in swap_rows),
        "swap_probe_error": swap_error or None,
    }


def firewall_evidence() -> dict[str, Any]:
    rc, stdout, stderr = run(["ufw", "status", "verbose"])
    active = bool(re.search(r"(?mi)^Status:\s*active\s*$", stdout))
    default_deny = bool(re.search(r"(?mi)^Default:\s*deny\s*\(incoming\)", stdout))
    return {
        "probe_rc": rc,
        "ufw_active": active,
        "default_deny_incoming": default_deny,
        "status_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
        "raw_rules_included": False,
        "error": stderr or None,
    }


def listener_evidence() -> dict[str, Any]:
    rc, stdout, stderr = run(["ss", "-H", "-lnt"])
    observed_ports: set[int] = set()
    if rc == 0:
        for raw in stdout.splitlines():
            columns = raw.split()
            if len(columns) < 4:
                continue
            local = columns[3]
            match = re.search(r":(\d+)$", local)
            if match:
                observed_ports.add(int(match.group(1)))
    prohibited = sorted(observed_ports & PROHIBITED_HOST_PORTS)
    return {
        "probe_rc": rc,
        "prohibited_ports": prohibited,
        "prohibited_ports_absent": not prohibited,
        "observed_port_count": len(observed_ports),
        "error": stderr or None,
    }


def repository_evidence() -> dict[str, Any]:
    head_rc, head, head_error = run(["git", "rev-parse", "HEAD"], cwd=CANONICAL_REPO_ROOT)
    dirty_rc, dirty, dirty_error = run(["git", "status", "--porcelain"], cwd=CANONICAL_REPO_ROOT)
    return {
        "repository": str(CANONICAL_REPO_ROOT),
        "head": head if head_rc == 0 else None,
        "head_probe_error": head_error or None,
        "clean": dirty_rc == 0 and dirty == "",
        "status_probe_error": dirty_error or None,
    }


def build_evidence() -> dict[str, Any]:
    marker_present = AUTH_MARKER.exists()
    virt = virtualization_evidence()
    identity = identity_fingerprint()
    storage = storage_evidence()
    firewall = firewall_evidence()
    listeners = listener_evidence()
    repo = repository_evidence()

    machine_ready = all(
        (
            not marker_present,
            virt.get("bare_metal") is True,
            bool(re.fullmatch(r"[0-9a-f]{64}", identity["fingerprint_sha256"])),
            storage.get("root_storage_encryption_detected") is True,
            storage.get("unencrypted_swap_detected") is False,
            firewall.get("ufw_active") is True,
            firewall.get("default_deny_incoming") is True,
            listeners.get("prohibited_ports_absent") is True,
            repo.get("clean") is True,
            bool(re.fullmatch(r"[0-9a-f]{40}", str(repo.get("head") or ""))),
        )
    )

    return {
        "schema": "queen-califia-final-host-evidence-v1",
        "collected_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "collector_euid": os.geteuid(),
        "authorization_marker": {
            "path": str(AUTH_MARKER),
            "present": marker_present,
            "closed_for_preauthorization_collection": not marker_present,
        },
        "operating_system": parse_os_release(),
        "virtualization": virt,
        "identity": identity,
        "storage": storage,
        "firewall": firewall,
        "listeners": listeners,
        "repository": repo,
        "manual_controls": {
            "bios_restore_after_power_loss": {
                "verified": False,
                "status": "manual-evidence-required",
            },
            "ups": {
                "verified": False,
                "status": "manual-evidence-required",
            },
        },
        "machine_evidence_ready_for_review": machine_ready,
        "ledger_modified": False,
        "authorization_modified": False,
    }


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("FINAL_HOST_EVIDENCE_ERROR=run as root so firewall/storage evidence is complete")

    missing = [command for command in REQUIRED_COMMANDS if shutil.which(command) is None]
    if missing:
        raise SystemExit("FINAL_HOST_EVIDENCE_ERROR=missing required commands: " + ",".join(missing))

    if AUTH_MARKER.exists():
        raise SystemExit(
            "FINAL_HOST_EVIDENCE_ERROR=authorization marker exists; refusing to label this collection preauthorization evidence"
        )

    if not (CANONICAL_REPO_ROOT / ".git").exists():
        raise SystemExit(
            f"FINAL_HOST_EVIDENCE_ERROR=canonical repository checkout not found: {CANONICAL_REPO_ROOT}"
        )

    evidence = build_evidence()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = EVIDENCE_ROOT / f"final-host-{stamp}.json"
    if output.exists():
        raise SystemExit(f"FINAL_HOST_EVIDENCE_ERROR=refusing to overwrite existing evidence: {output}")

    EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    output.write_text(payload, encoding="utf-8")
    os.chmod(output, 0o600)

    print(
        "FINAL_HOST_MACHINE_EVIDENCE="
        + ("PASS" if evidence["machine_evidence_ready_for_review"] else "BLOCKED")
    )
    print(f"FINAL_HOST_EVIDENCE={output}")
    print(f"FINAL_HOST_EVIDENCE_SHA256={hashlib.sha256(payload.encode('utf-8')).hexdigest()}")
    print("FINAL_HOST_MANUAL_CONTROLS=REQUIRED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
