#!/usr/bin/env python3
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/edge/windows/Verify-QueenCalifia-FinalHostManualControlsV2.ps1"


def require(text: str, *needles: str) -> None:
    missing = [x for x in needles if x not in text]
    if missing:
        raise SystemExit(f"Hyper-V manual-controls contract missing: {missing}")


def main() -> int:
    if not SCRIPT.is_file():
        raise SystemExit("missing Hyper-V manual-controls verifier")

    pwsh = shutil.which("pwsh")
    if not pwsh:
        raise SystemExit("PowerShell 7 is required in CI")

    parser = (
        "$t=$null;$e=$null;"
        "[System.Management.Automation.Language.Parser]::ParseFile("
        f"'{SCRIPT.as_posix()}',[ref]$t,[ref]$e)|Out-Null;"
        "if($e.Count -gt 0){$e|Format-List Message,Extent;exit 1}"
    )
    subprocess.run([pwsh, "-NoLogo", "-NoProfile", "-Command", parser], check=True)

    text = SCRIPT.read_text(encoding="utf-8")
    require(
        text,
        "queen-califia-hyperv-final-host-manual-controls-request-v2",
        "queen-califia-hyperv-final-host-manual-controls-verification-v2",
        "queen-califia-hyperv-final-host-evidence-v2",
        "windows-physical-host-with-hyperv-ubuntu-guest",
        "hyperv-final-host-v2-*.json",
        "host_identity.fingerprint_sha256",
        "controlled_ac_loss_test_performed",
        "automatic_power_restore_observed",
        "controlled_utility_interruption_test_performed",
        "post_test_normal_operation_observed",
        "QUEEN_CALIFIA=BLOCKED",
        "runtime authorization gate is closed",
        "physical_truth_automatically_verified = $false",
        "human_review_required = $true",
        "automatic_ledger_promotion = $false",
        "authorization_modified = $false",
        "deployment_ledger_modified = $false",
        "HYPERV_FINAL_HOST_MANUAL_CONTROLS_LEDGER_UPDATED=NO",
        "HYPERV_FINAL_HOST_MANUAL_CONTROLS_AUTHORIZATION_UPDATED=NO",
    )

    for forbidden in (
        "sovereign-edge-deployment-state.json",
        "SOVEREIGN_EDGE_RUNTIME_AUTHORIZED",
        "automatic_ledger_promotion = $true",
        "authorization_modified = $true",
        "deployment_ledger_modified = $true",
    ):
        if forbidden in text:
            raise SystemExit(f"forbidden mutation surface in Hyper-V manual-controls verifier: {forbidden}")

    print("Hyper-V manual-controls verifier contract: parser clean; host-bound BIOS/UPS evidence remains human-review-only and authorization stays closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
