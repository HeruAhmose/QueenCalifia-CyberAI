#!/usr/bin/env python3
from __future__ import annotations

import ast
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GUEST = ROOT / 'scripts/edge/bind-hyperv-guest-identity.py'
WINDOWS = ROOT / 'scripts/edge/windows/Bind-QueenCalifia-HyperVValkeyAuthorityEvidenceV2.ps1'


def require(text: str, *needles: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f'Hyper-V Gen1 Valkey NIC-binding contract missing: {missing}')


def main() -> int:
    if not GUEST.is_file() or not WINDOWS.is_file():
        raise SystemExit('missing Hyper-V Gen1 Valkey NIC-binding component')

    guest = GUEST.read_text(encoding='utf-8')
    ast.parse(guest, str(GUEST))

    pwsh = shutil.which('pwsh')
    if not pwsh:
        raise SystemExit('PowerShell 7 is required in CI')
    parser = (
        '$t=$null;$e=$null;'
        '[System.Management.Automation.Language.Parser]::ParseFile('
        f"'{WINDOWS.as_posix()}',[ref]$t,[ref]$e)|Out-Null;"
        'if($e.Count -gt 0){$e|Format-List Message,Extent;exit 1}'
    )
    subprocess.run([pwsh, '-NoLogo', '-NoProfile', '-Command', parser], check=True)
    windows = WINDOWS.read_text(encoding='utf-8')

    # PowerShell variable names are case-insensitive. $Host is a built-in read-only
    # automatic variable, so assigning to $host would parse but fail at runtime.
    if re.search(r'(?im)^\s*\$host\s*=', windows):
        raise SystemExit('Hyper-V Gen1 Valkey NIC-binding contract assigns to read-only PowerShell $Host automatic variable')

    require(
        guest,
        'queen-califia-hyperv-guest-identity-binding-evidence-v1',
        'hyperv-nic-mac-sha256-with-trailing-nul',
        "digest.update(b'\\0')",
        "mac.replace(':', '').upper()",
        'raw_mac_included',
        'authorization_marker_absent_verified',
        "automatic_ledger_promotion': False",
        "authorization_modified': False",
        "deployment_ledger_modified': False",
    )
    require(
        windows,
        'queen-califia-hyperv-final-valkey-authority-evidence-v2',
        'queen-califia-hyperv-guest-identity-binding-evidence-v1',
        'shared_hyperv_nic_identity_sha256',
        'same_hyperv_vm_network_identity = $true',
        'guest_dmi_product_uuid_informational',
        'cross_host_binding_method =',
        'QUEEN_CALIFIA=BLOCKED',
        'runtime authorization gate is closed',
        'eligible_for_authority_verified_review = $true',
        'automatic_ledger_promotion = $false',
        'authorization_modified = $false',
        'deployment_ledger_modified = $false',
        'HYPERV_FINAL_VALKEY_LEDGER_UPDATED=NO',
        'HYPERV_FINAL_VALKEY_AUTHORIZATION_UPDATED=NO',
    )

    # Reading/checking the authorization marker is required. Mutation primitives are not.
    for forbidden in (
        'automatic_ledger_promotion = $true',
        'authorization_modified = $true',
        'deployment_ledger_modified = $true',
        'Set-Content SOVEREIGN_EDGE_RUNTIME_AUTHORIZED',
        'New-Item SOVEREIGN_EDGE_RUNTIME_AUTHORIZED',
        'Remove-Item SOVEREIGN_EDGE_RUNTIME_AUTHORIZED',
        'sovereign-edge-deployment-state.json',
    ):
        if forbidden in guest or forbidden in windows:
            raise SystemExit(f'forbidden mutation surface in Hyper-V Gen1 NIC-binding path: {forbidden}')

    print('Hyper-V Gen1 Valkey NIC-binding guard verified: guest MAC hashes use the Windows collector algorithm; DMI UUID is informational; PowerShell automatic-variable collisions are rejected; live authority stays fail-closed and review-only')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
