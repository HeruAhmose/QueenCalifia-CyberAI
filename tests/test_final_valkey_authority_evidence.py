from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/edge/bind-final-valkey-authority-evidence.py"
spec = importlib.util.spec_from_file_location("qc_final_valkey_authority", SCRIPT)
assert spec is not None and spec.loader is not None
binder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binder)


def records():
    fingerprints = {
        "ca": "1" * 64,
        "server": "2" * 64,
        "health": "3" * 64,
        "api": "4" * 64,
        "worker": "5" * 64,
    }
    host = {
        "schema": "queen-califia-final-host-evidence-v1",
        "machine_evidence_ready_for_review": True,
        "authorization_marker": {"present": False},
        "virtualization": {"bare_metal": True},
        "identity": {"fingerprint_sha256": "a" * 64},
        "repository": {"head": "b" * 40},
    }
    pki = {
        "schema": "queen-califia-final-valkey-pki-evidence-v1",
        "pki_material_verified": True,
        "live_valkey_authority_verified": False,
        "eligible_for_pki_generated_review": True,
        "eligible_for_authority_verified_review": False,
        "certificate_fingerprints_sha256": fingerprints,
    }
    runtime = {
        "schema": "queen-califia-sovereign-edge-runtime-evidence-v2",
        "mode": "--preauth",
        "authorization_marker_present": False,
        "repository_clean": True,
        "host_identity_fingerprint_sha256": "a" * 64,
        "git_head": "b" * 40,
        "boot_id": "12345678-1234-1234-1234-123456789abc",
        "valkey_certificate_fingerprints_sha256": fingerprints,
        "running_application_containers": [],
        "claims": {
            "no_host_ports_published": True,
            "valkey_tls_verified": True,
            "valkey_plaintext_refused": True,
            "valkey_client_certificate_required": True,
            "valkey_health_client_verified": True,
            "valkey_api_client_verified": True,
            "valkey_worker_client_verified": True,
            "unauthorized_application_runtime_absent": True,
            "authorized_runtime_probed": False,
        },
    }
    return host, pki, runtime


def assert_rejected(host, pki, runtime, match: str) -> None:
    with pytest.raises(SystemExit, match=match):
        binder.validate(host, pki, runtime)


def test_valid_evidence_chain_is_review_eligible_only() -> None:
    host, pki, runtime = records()
    result = binder.validate(host, pki, runtime)
    assert result["same_final_host"] is True
    assert result["same_valkey_pki"] is True
    assert result["live_mtls_authority_verified"] is True
    assert result["eligible_for_authority_verified_review"] is True
    assert result["automatic_ledger_promotion"] is False
    assert result["authorization_modified"] is False
    assert result["deployment_ledger_modified"] is False


def test_wrong_host_is_rejected() -> None:
    host, pki, runtime = records()
    runtime = copy.deepcopy(runtime)
    runtime["host_identity_fingerprint_sha256"] = "c" * 64
    assert_rejected(host, pki, runtime, "host identity fingerprints do not match")


def test_wrong_git_head_is_rejected() -> None:
    host, pki, runtime = records()
    runtime = copy.deepcopy(runtime)
    runtime["git_head"] = "c" * 40
    assert_rejected(host, pki, runtime, "Git heads do not match")


def test_mismatched_pki_is_rejected() -> None:
    host, pki, runtime = records()
    runtime = copy.deepcopy(runtime)
    runtime["valkey_certificate_fingerprints_sha256"]["server"] = "f" * 64
    assert_rejected(host, pki, runtime, "certificate fingerprints do not match")


def test_missing_client_certificate_requirement_is_rejected() -> None:
    host, pki, runtime = records()
    runtime = copy.deepcopy(runtime)
    runtime["claims"]["valkey_client_certificate_required"] = False
    assert_rejected(host, pki, runtime, "valkey_client_certificate_required must be True")


def test_authorized_or_application_runtime_record_is_rejected() -> None:
    host, pki, runtime = records()
    runtime = copy.deepcopy(runtime)
    runtime["claims"]["authorized_runtime_probed"] = True
    assert_rejected(host, pki, runtime, "authorized_runtime_probed must be False")

    host, pki, runtime = records()
    runtime = copy.deepcopy(runtime)
    runtime["running_application_containers"] = ["queen-califia-api"]
    assert_rejected(host, pki, runtime, "running application containers")
