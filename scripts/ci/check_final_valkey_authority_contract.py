#!/usr/bin/env python3
from __future__ import annotations

import py_compile
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "scripts/edge/verify-runtime.sh"
BINDER = ROOT / "scripts/edge/bind-final-valkey-authority-evidence.py"
TESTS = ROOT / "tests/test_final_valkey_authority_evidence.py"


def require(text: str, *needles: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"final Valkey authority contract missing: {missing}")


def main() -> int:
    for path in (RUNTIME, BINDER, TESTS):
        if not path.is_file():
            raise SystemExit(f"missing final Valkey authority contract file: {path.relative_to(ROOT)}")

    subprocess.run(["bash", "-n", str(RUNTIME)], check=True)
    py_compile.compile(str(BINDER), doraise=True)

    runtime = RUNTIME.read_text(encoding="utf-8")
    require(
        runtime,
        "preauthorization proof refused: runtime authorization marker already exists",
        "preauthorization proof invalidated: runtime authorization marker appeared during proof",
        "preauthorization evidence refused: runtime authorization marker appeared before evidence write",
        "Valkey TLS unexpectedly accepted a client without a client certificate",
        "for client in health api worker",
        "unauthorized application container is running",
        '"queen-califia-api"',
        '"queen-califia-worker"',
        '"queen-califia-cloudflared"',
        '"schema": "queen-califia-sovereign-edge-runtime-evidence-v2"',
        '"host_identity_fingerprint_sha256": host_identity_fingerprint()',
        '"repository_clean": repo_status.stdout.strip() == ""',
        '"valkey_certificate_fingerprints_sha256": cert_fingerprints',
        '"valkey_client_certificate_required": True',
        '"valkey_health_client_verified": True',
        '"valkey_api_client_verified": True',
        '"valkey_worker_client_verified": True',
        '"unauthorized_application_runtime_absent": mode == "--preauth" and not running_application_containers',
    )

    binder = BINDER.read_text(encoding="utf-8")
    require(
        binder,
        'EVIDENCE_ROOT = Path("/srv/queen-califia/evidence")',
        'AUTH_MARKER = Path("/srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED")',
        'CANONICAL_REPO_ROOT = Path("/opt/queen-califia")',
        '"queen-califia-final-host-evidence-v1"',
        '"queen-califia-final-valkey-pki-evidence-v1"',
        '"queen-califia-sovereign-edge-runtime-evidence-v2"',
        "host identity fingerprints do not match",
        "Git heads do not match",
        "certificate fingerprints do not match",
        '"eligible_for_authority_verified_review": True',
        '"automatic_ledger_promotion": False',
        '"authorization_modified": False',
        '"deployment_ledger_modified": False',
        '"schema": "queen-califia-final-valkey-authority-evidence-v1"',
        "FINAL_VALKEY_AUTHORITY_LEDGER_UPDATED=NO",
        "FINAL_VALKEY_AUTHORIZATION_UPDATED=NO",
    )
    for forbidden in (
        "argparse",
        "sys.argv",
        "sovereign-edge-deployment-state.json",
        "AUTH_MARKER.write_text",
        "AUTH_MARKER.unlink",
        '"automatic_ledger_promotion": True',
        '"authorization_modified": True',
        '"deployment_ledger_modified": True',
    ):
        if forbidden in binder:
            raise SystemExit(f"final Valkey authority binder contains forbidden promotion/path surface: {forbidden}")

    tests = TESTS.read_text(encoding="utf-8")
    require(
        tests,
        "test_valid_evidence_chain_is_review_eligible_only",
        "test_wrong_host_is_rejected",
        "test_wrong_git_head_is_rejected",
        "test_mismatched_pki_is_rejected",
        "test_missing_client_certificate_requirement_is_rejected",
        "test_authorized_or_application_runtime_record_is_rejected",
    )

    print(
        "Final Valkey authority guard verified: preauthorization stays closed, all intended mTLS clients are proven, "
        "no-client-cert and plaintext access are rejected, evidence is bound to one host/Git head/PKI set, and no authority state is mutated"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
