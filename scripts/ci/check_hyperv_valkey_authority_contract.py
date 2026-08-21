#!/usr/bin/env python3
from __future__ import annotations

import ast
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PKI = ROOT / "scripts/edge/verify-hyperv-valkey-pki.py"
RUNTIME_BINDER = ROOT / "scripts/edge/bind-hyperv-runtime-evidence.py"
WINDOWS_BINDER = ROOT / "scripts/edge/windows/Bind-QueenCalifia-HyperVValkeyAuthorityEvidence.ps1"


def require(text: str, *needles: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"Hyper-V Valkey authority contract missing: {missing}")


def parse_python(path: Path) -> str:
    if not path.is_file():
        raise SystemExit(f"missing Hyper-V Valkey authority component: {path.relative_to(ROOT)}")
    text = path.read_text(encoding="utf-8")
    ast.parse(text, str(path))
    return text


def main() -> int:
    pki = parse_python(PKI)
    runtime = parse_python(RUNTIME_BINDER)
    if not WINDOWS_BINDER.is_file():
        raise SystemExit("missing Windows Hyper-V Valkey authority binder")

    pwsh = shutil.which("pwsh")
    if not pwsh:
        raise SystemExit("PowerShell 7 is required in CI")
    parser = (
        "$t=$null;$e=$null;"
        "[System.Management.Automation.Language.Parser]::ParseFile("
        f"'{WINDOWS_BINDER.as_posix()}',[ref]$t,[ref]$e)|Out-Null;"
        "if($e.Count -gt 0){$e|Format-List Message,Extent;exit 1}"
    )
    subprocess.run([pwsh, "-NoLogo", "-NoProfile", "-Command", parser], check=True)
    windows = WINDOWS_BINDER.read_text(encoding="utf-8")

    require(
        pki,
        'systemd-detect-virt',
        'microsoft',
        '/sys/class/dmi/id/product_uuid',
        'queen-califia-hyperv-final-valkey-pki-evidence-v1',
        'hyperv_guest_vm_id_raw',
        'guest_host_identity_fingerprint_sha256',
        'certificate_fingerprints_sha256',
        'eligible_for_pki_generated_review',
        'live_valkey_authority_verified',
        'authorization_modified": False',
        'deployment_ledger_modified": False',
    )
    require(
        runtime,
        'systemd-detect-virt',
        'microsoft',
        '/sys/class/dmi/id/product_uuid',
        'queen-califia-sovereign-edge-runtime-evidence-v2',
        'queen-califia-hyperv-runtime-binding-evidence-v1',
        'runtime_preauthorization_claims_verified',
        'authorization_marker_absent_verified',
        'valkey_client_certificate_required',
        'valkey_plaintext_refused',
        'unauthorized_application_runtime_absent',
        'authorization_modified": False',
        'deployment_ledger_modified": False',
    )
    require(
        windows,
        'queen-califia-hyperv-final-host-evidence-v2',
        'queen-califia-hyperv-final-valkey-pki-evidence-v1',
        'queen-califia-sovereign-edge-runtime-evidence-v2',
        'queen-califia-hyperv-runtime-binding-evidence-v1',
        'queen-califia-hyperv-final-valkey-authority-evidence-v1',
        'windows-physical-host-with-hyperv-ubuntu-guest',
        'hyperv.vm_id',
        'hyperv_guest_vm_id_raw',
        'guest_host_identity_fingerprint_sha256',
        'runtime_source.sha256',
        'QUEEN_CALIFIA=BLOCKED',
        'runtime authorization gate is closed',
        'same_hyperv_vm_identity = $true',
        'same_guest_identity = $true',
        'same_repository_head = $true',
        'same_valkey_pki = $true',
        'live_mtls_authority_verified = $true',
        'plaintext_refusal_verified = $true',
        'client_certificate_requirement_verified = $true',
        'all_intended_client_identities_verified = $true',
        'automatic_ledger_promotion = $false',
        'authorization_modified = $false',
        'deployment_ledger_modified = $false',
        'HYPERV_FINAL_VALKEY_LEDGER_UPDATED=NO',
        'HYPERV_FINAL_VALKEY_AUTHORIZATION_UPDATED=NO',
    )

    combined = "\n".join((pki, runtime, windows))
    for forbidden in (
        'automatic_ledger_promotion = $true',
        'authorization_modified = $true',
        'deployment_ledger_modified = $true',
        'SOVEREIGN_EDGE_RUNTIME_AUTHORIZED',
        'sovereign-edge-deployment-state.json',
    ):
        if forbidden in combined:
            raise SystemExit(f"forbidden mutation surface in Hyper-V Valkey authority evidence path: {forbidden}")

    print(
        "Hyper-V Valkey authority evidence guard verified: Microsoft guest identity, VM-ID binding, "
        "offline PKI, preauthorization runtime proof, Windows physical-host binding, and fail-closed "
        "authorization/ledger boundaries are clean"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
