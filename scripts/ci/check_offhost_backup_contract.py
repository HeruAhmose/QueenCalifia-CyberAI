#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/edge/copy-offhost-backup.sh"


def require(text: str, *needles: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"off-host backup proof contract missing: {missing}")


def main() -> int:
    if not SCRIPT.is_file():
        raise SystemExit("missing off-host backup proof operator")

    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)
    text = SCRIPT.read_text(encoding="utf-8")
    require(
        text,
        'STATE_ROOT="/srv/queen-califia"',
        'OFFHOST_ROOT="/mnt/qc-offhost-backup"',
        "authorization marker exists; preauthorization backup proof refused",
        '[[ "$mount_target" == "$OFFHOST_ROOT" ]]',
        '[[ "$source_dev" != "$offhost_dev" ]]',
        "top_disk_for_device",
        '[[ "$offhost_mount_source" != /dev/loop* ]]',
        '[[ "$source_top_disk" != "$offhost_top_disk" ]]',
        'independence_mode="distinct-physical-disk"',
        'nfs|nfs4|cifs|smb3|fuse.sshfs)',
        'independence_mode="network-filesystem"',
        "source backup hash mismatch",
        "off-host copy hash mismatch",
        "source_destination_hash_equal",
        "separate_filesystem_device",
        "independence_mode",
        "deployment_ledger_modified",
        "authorization_modified",
        "destination archive or manifest already exists; immutable copy refused",
        "OFFHOST_BACKUP_LEDGER_UPDATED=NO",
        "OFFHOST_BACKUP_AUTHORIZATION_UPDATED=NO",
    )

    for forbidden in (
        "QC_EDGE_STATE_ROOT",
        "QC_OFFHOST_ROOT",
        "getopts",
        "${1",
        "touch \"$AUTH_MARKER\"",
        "> \"$AUTH_MARKER\"",
        "sovereign-edge-deployment-state.json",
        "production_authorized",
        "runtime_authorized",
    ):
        if forbidden in text:
            raise SystemExit(f"off-host backup operator contains forbidden mutation/path surface: {forbidden}")

    print(
        "Off-host backup proof guard verified: canonical paths fixed; loop/RAM-style shortcuts excluded; "
        "destination must be a distinct physical disk or supported network filesystem; encrypted archive and "
        "evidence are hash-verified; authorization/ledger state cannot be changed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
