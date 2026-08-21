#!/usr/bin/env python3
from __future__ import annotations

import py_compile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "scripts/edge/verify-final-valkey-pki.py"
GENERATOR = ROOT / "scripts/edge/generate-valkey-mtls.sh"


def require(text: str, *needles: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"final Valkey PKI evidence contract missing: {missing}")


def main() -> int:
    if not VERIFIER.is_file():
        raise SystemExit("missing final Valkey PKI verifier")
    if not GENERATOR.is_file():
        raise SystemExit("missing canonical Valkey PKI generator")

    py_compile.compile(str(VERIFIER), doraise=True)
    text = VERIFIER.read_text(encoding="utf-8")
    require(
        text,
        'PKI_ROOT = Path("/srv/queen-califia/pki/valkey")',
        'EVIDENCE_ROOT = Path("/srv/queen-califia/evidence")',
        "final-host Valkey PKI evidence requires bare metal",
        '"pki_material_verified": True',
        '"certificate_chain_verified": True',
        '"certificate_private_key_pairs_verified": True',
        '"server_identity_constraints_verified": True',
        '"client_identity_constraints_verified": True',
        '"minimum_30_day_validity_verified": True',
        '"private_key_permissions_verified": True',
        '"distinct_certificate_identities_verified": True',
        '"live_valkey_authority_verified": False',
        '"eligible_for_pki_generated_review": True',
        '"eligible_for_authority_verified_review": False',
        "TLS Web Server Authentication",
        "TLS Web Client Authentication",
        "DNS:valkey",
        "IP Address:127.0.0.1",
        "DNS:queen-califia-api",
        "DNS:queen-califia-worker",
        "DNS:queen-califia-valkey-health",
        "ca.key must be mode 0400",
        "must be owned by 10001:10001",
        "FINAL_VALKEY_AUTHORITY_VERIFIED=NO",
        "FINAL_VALKEY_LEDGER_UPDATED=NO",
        "FINAL_VALKEY_AUTHORIZATION_UPDATED=NO",
    )

    for forbidden in (
        "argparse",
        "sys.argv",
        "sovereign-edge-deployment-state.json",
        '"live_valkey_authority_verified": True',
        '"eligible_for_authority_verified_review": True',
        "AUTH_MARKER.write_text",
        "AUTH_MARKER.unlink",
        "pki_generated\": true",
        "authority_verified\": true",
    ):
        if forbidden in text:
            raise SystemExit(f"final Valkey PKI verifier contains forbidden promotion/path surface: {forbidden}")

    generator = GENERATOR.read_text(encoding="utf-8")
    require(
        generator,
        'PKI="${ROOT}/pki/valkey"',
        'issue_cert server serverAuth "subjectAltName=DNS:valkey,IP:127.0.0.1"',
        'issue_cert health clientAuth "subjectAltName=DNS:queen-califia-valkey-health"',
        'issue_cert api clientAuth "subjectAltName=DNS:queen-califia-api"',
        'issue_cert worker clientAuth "subjectAltName=DNS:queen-califia-worker"',
        'chmod 0400 "$PKI/ca.key"',
        'chmod 0440 "$PKI/${name}.key"',
    )

    print(
        "Final Valkey PKI evidence guard verified: fixed final-host PKI path, offline chain/key/identity/permission checks, "
        "bare-metal boundary, and explicit refusal to equate PKI material with live authority verification"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
