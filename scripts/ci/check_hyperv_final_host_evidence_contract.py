#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COLLECTOR = ROOT / "scripts/edge/windows/Collect-QueenCalifia-FinalHostEvidence.ps1"


def require(text: str, *needles: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"Hyper-V final-host evidence contract missing: {missing}")


def main() -> int:
    if not COLLECTOR.is_file():
        raise SystemExit("missing Hyper-V final-host evidence collector")

    text = COLLECTOR.read_text(encoding="utf-8")

    require(
        text,
        "$VmName = 'QueenCalifia-Sovereign-Edge-HyperV'",
        "queen-califia-hyperv-final-host-evidence-v1",
        "windows-physical-host-with-hyperv-ubuntu-guest",
        "Get-BitLockerVolume",
        "Confirm-SecureBootUEFI",
        "Get-Tpm",
        "Win32_DeviceGuard",
        "RunAsPPL",
        "RunAsPPLBoot",
        "Get-NetFirewallProfile",
        "Get-NetTCPConnection -State Listen",
        "$ProhibitedPorts = @(80, 443, 5432, 6379)",
        "Get-VM -Name $VmName",
        "Get-VMFirmware -VMName $VmName",
        "Get-VMSecurity -VMName $VmName",
        "Get-VMHardDiskDrive -VMName $VmName",
        "expected_vm_identity",
        "restart_after_host_boot_configured",
        "authorization_gate_closed",
        "runtime authorization gate is closed",
        "manual-physical-evidence-required",
        "physical_truth_automatically_verified = $false",
        "human_review_required = $true",
        "automatic_ledger_promotion = $false",
        "deployment_ledger_modified = $false",
        "authorization_modified = $false",
        "HYPERV_FINAL_HOST_LEDGER_UPDATED=NO",
        "HYPERV_FINAL_HOST_AUTHORIZATION_UPDATED=NO",
    )

    for forbidden in (
        "sovereign-edge-deployment-state.json",
        "SOVEREIGN_EDGE_RUNTIME_AUTHORIZED').Write",
        "SOVEREIGN_EDGE_RUNTIME_AUTHORIZED\").Write",
        "New-Item -ItemType File",
        "Set-Content",
        "Out-File",
        "Remove-Item",
        "Clear-Content",
        "automatic_ledger_promotion = $true",
        "deployment_ledger_modified = $true",
        "authorization_modified = $true",
    ):
        if forbidden in text:
            raise SystemExit(f"Hyper-V final-host collector contains forbidden state-mutation surface: {forbidden}")

    print(
        "Hyper-V final-host evidence guard verified: Windows physical-host trust, BitLocker/TPM/Secure Boot/VBS/LSA/firewall, "
        "exact VM identity/storage, and closed guest authorization are review-only; BIOS/UPS remain manual and no ledger/authorization state is mutated"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
