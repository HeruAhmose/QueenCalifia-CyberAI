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

PKI_ROOT = Path("/srv/queen-califia/pki/valkey")
EVIDENCE_ROOT = Path("/srv/queen-califia/evidence")
AUTH_MARKER = Path("/srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED")
CERT_NAMES = ("ca", "server", "health", "api", "worker")
CLIENT_NAMES = ("health", "api", "worker")
CERT_SHA_RE = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){31}$")


def fail(message: str) -> None:
    raise SystemExit(f"VALKEY_PKI_EVIDENCE_ERROR={message}")


def run(command: list[str]) -> str:
    proc = subprocess.run(command, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"exit {proc.returncode}"
        fail(f"command failed: {command[0]}: {detail}")
    return proc.stdout.strip()


def file_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def public_key_digest_from_key(path: Path) -> str:
    proc = subprocess.run(
        ["openssl", "pkey", "-in", str(path), "-pubout", "-outform", "DER"],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        fail(f"unable to derive public key from {path.name}")
    return hashlib.sha256(proc.stdout).hexdigest()


def public_key_digest_from_cert(path: Path) -> str:
    pem = run(["openssl", "x509", "-in", str(path), "-pubkey", "-noout"])
    proc = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        input=pem.encode("utf-8"),
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        fail(f"unable to derive certificate public key from {path.name}")
    return hashlib.sha256(proc.stdout).hexdigest()


def cert_fingerprint(path: Path) -> str:
    output = run(["openssl", "x509", "-in", str(path), "-noout", "-fingerprint", "-sha256"])
    if "=" not in output:
        fail(f"invalid certificate fingerprint output for {path.name}")
    value = output.split("=", 1)[1].strip()
    if not CERT_SHA_RE.fullmatch(value):
        fail(f"invalid SHA-256 certificate fingerprint for {path.name}")
    return value.lower().replace(":", "")


def cert_text(path: Path) -> str:
    return run(["openssl", "x509", "-in", str(path), "-noout", "-text"])


def require_text(text: str, needle: str, label: str) -> None:
    if needle not in text:
        fail(f"{label} missing required certificate constraint: {needle}")


def verify_material() -> dict[str, Any]:
    virt = run(["systemd-detect-virt"]).strip().lower()
    if virt != "none":
        fail(f"final-host Valkey PKI evidence requires bare metal; detected {virt or 'unknown'}")

    required = [PKI_ROOT / "ca.key", PKI_ROOT / "ca.crt"]
    for name in ("server", "health", "api", "worker"):
        required.extend([PKI_ROOT / f"{name}.key", PKI_ROOT / f"{name}.crt"])
    for path in required:
        if not path.is_file() or path.is_symlink():
            fail(f"missing canonical non-symlink PKI file: {path}")

    if file_mode(PKI_ROOT / "ca.key") != 0o400:
        fail("ca.key must be mode 0400")
    if file_mode(PKI_ROOT / "ca.crt") != 0o444:
        fail("ca.crt must be mode 0444")
    ca_stat = (PKI_ROOT / "ca.key").stat()
    if ca_stat.st_uid != 0 or ca_stat.st_gid != 0:
        fail("ca.key must remain root:root")

    for name in ("server", "health", "api", "worker"):
        key = PKI_ROOT / f"{name}.key"
        cert = PKI_ROOT / f"{name}.crt"
        if file_mode(key) != 0o440:
            fail(f"{name}.key must be mode 0440")
        if file_mode(cert) != 0o444:
            fail(f"{name}.crt must be mode 0444")
        key_stat = key.stat()
        if key_stat.st_uid != 10001 or key_stat.st_gid != 10001:
            fail(f"{name}.key must be owned by 10001:10001")
        if public_key_digest_from_key(key) != public_key_digest_from_cert(cert):
            fail(f"{name} certificate does not match its private key")

    ca = PKI_ROOT / "ca.crt"
    run(["openssl", "verify", "-CAfile", str(ca), str(ca)])
    fingerprints: dict[str, str] = {"ca": cert_fingerprint(ca)}

    for name in ("server", "health", "api", "worker"):
        cert = PKI_ROOT / f"{name}.crt"
        run(["openssl", "verify", "-CAfile", str(ca), str(cert)])
        run(["openssl", "x509", "-in", str(cert), "-noout", "-checkend", "2592000"])
        fingerprints[name] = cert_fingerprint(cert)

    if len(set(fingerprints.values())) != len(fingerprints):
        fail("certificate identities must have distinct fingerprints")

    server_text = cert_text(PKI_ROOT / "server.crt")
    require_text(server_text, "TLS Web Server Authentication", "server")
    require_text(server_text, "DNS:valkey", "server")
    require_text(server_text, "IP Address:127.0.0.1", "server")
    require_text(server_text, "CA:FALSE", "server")

    client_sans = {
        "health": "DNS:queen-califia-valkey-health",
        "api": "DNS:queen-califia-api",
        "worker": "DNS:queen-califia-worker",
    }
    for name, san in client_sans.items():
        text = cert_text(PKI_ROOT / f"{name}.crt")
        require_text(text, "TLS Web Client Authentication", name)
        require_text(text, san, name)
        require_text(text, "CA:FALSE", name)

    ca_text = cert_text(ca)
    require_text(ca_text, "CA:TRUE", "ca")
    require_text(ca_text, "QueenCalifia Sovereign Edge Valkey CA", "ca")

    return {
        "bare_metal": True,
        "pki_root": str(PKI_ROOT),
        "pki_material_verified": True,
        "certificate_fingerprints_sha256": fingerprints,
        "certificate_chain_verified": True,
        "certificate_private_key_pairs_verified": True,
        "server_identity_constraints_verified": True,
        "client_identity_constraints_verified": True,
        "minimum_30_day_validity_verified": True,
        "private_key_permissions_verified": True,
        "distinct_certificate_identities_verified": True,
        "live_valkey_authority_verified": False,
        "eligible_for_pki_generated_review": True,
        "eligible_for_authority_verified_review": False,
    }


def main() -> int:
    if os.geteuid() != 0:
        fail("run as root so private-key ownership and permissions can be verified")
    if AUTH_MARKER.exists():
        fail("authorization marker exists; preauthorization PKI evidence refused")
    if not PKI_ROOT.is_dir() or PKI_ROOT.is_symlink():
        fail(f"missing canonical non-symlink PKI directory: {PKI_ROOT}")

    evidence = verify_material()
    evidence.update(
        {
            "schema": "queen-califia-final-valkey-pki-evidence-v1",
            "verified_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "authorization_modified": False,
            "deployment_ledger_modified": False,
        }
    )

    EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = EVIDENCE_ROOT / f"final-valkey-pki-{stamp}.json"
    if output.exists():
        fail(f"refusing to overwrite existing evidence: {output}")
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(output, 0o600)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()

    print("FINAL_VALKEY_PKI_MATERIAL=PASS")
    print("FINAL_VALKEY_PKI_GENERATED=ELIGIBLE_FOR_HUMAN_REVIEW")
    print("FINAL_VALKEY_AUTHORITY_VERIFIED=NO")
    print(f"FINAL_VALKEY_PKI_EVIDENCE={output}")
    print(f"FINAL_VALKEY_PKI_EVIDENCE_SHA256={digest}")
    print("FINAL_VALKEY_LEDGER_UPDATED=NO")
    print("FINAL_VALKEY_AUTHORIZATION_UPDATED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
