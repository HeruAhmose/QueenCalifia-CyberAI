#!/usr/bin/env bash
set -euo pipefail

STATE_ROOT="/srv/queen-califia"
BACKUP_ROOT="${STATE_ROOT}/backups"
EVIDENCE_ROOT="${STATE_ROOT}/evidence"
AUTH_MARKER="${STATE_ROOT}/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED"
OFFHOST_ROOT="/mnt/qc-offhost-backup"
DEST_ROOT="${OFFHOST_ROOT}/queen-califia/host-state"

fail() {
  echo "OFFHOST_BACKUP_ERROR=$1" >&2
  exit "${2:-2}"
}

top_disk_for_device() {
  local device="$1"
  [[ "$device" == /dev/* ]] || return 1
  [[ "$device" != /dev/loop* ]] || return 1
  local disk
  disk="$(lsblk -s -n -o NAME,TYPE "$device" 2>/dev/null | awk '$2 == "disk" { value=$1 } END { print value }')"
  [[ -n "$disk" ]] || return 1
  printf '/dev/%s\n' "$disk"
}

[[ "${EUID}" -eq 0 ]] || fail "run as root" 1
[[ ! -e "$AUTH_MARKER" ]] || fail "authorization marker exists; preauthorization backup proof refused" 78
[[ -d "$BACKUP_ROOT" ]] || fail "missing canonical backup root"
[[ -d "$OFFHOST_ROOT" ]] || fail "mount independent storage at $OFFHOST_ROOT"

mount_target="$(findmnt -n -o TARGET --target "$OFFHOST_ROOT" 2>/dev/null || true)"
[[ "$mount_target" == "$OFFHOST_ROOT" ]] || fail "$OFFHOST_ROOT must be a dedicated mount point" 3

source_dev="$(stat -c '%d' "$BACKUP_ROOT")"
offhost_dev="$(stat -c '%d' "$OFFHOST_ROOT")"
[[ "$source_dev" != "$offhost_dev" ]] || fail "off-host destination is on the same filesystem/device as source backups" 3

source_mount_source="$(findmnt -n -o SOURCE --target "$BACKUP_ROOT")"
source_mount_fstype="$(findmnt -n -o FSTYPE --target "$BACKUP_ROOT")"
offhost_mount_source="$(findmnt -n -o SOURCE --target "$OFFHOST_ROOT")"
offhost_mount_fstype="$(findmnt -n -o FSTYPE --target "$OFFHOST_ROOT")"

independence_mode=""
source_top_disk=""
offhost_top_disk=""
if [[ "$offhost_mount_source" == /dev/* ]]; then
  [[ "$offhost_mount_source" != /dev/loop* ]] || fail "loop devices do not qualify as off-host backup storage" 3
  source_top_disk="$(top_disk_for_device "$source_mount_source" || true)"
  offhost_top_disk="$(top_disk_for_device "$offhost_mount_source" || true)"
  [[ -n "$source_top_disk" ]] || fail "unable to establish source physical disk" 3
  [[ -n "$offhost_top_disk" ]] || fail "unable to establish off-host physical disk" 3
  [[ "$source_top_disk" != "$offhost_top_disk" ]] || fail "off-host backup resolves to the same physical disk as Sovereign Edge state" 3
  independence_mode="distinct-physical-disk"
else
  case "$offhost_mount_fstype" in
    nfs|nfs4|cifs|smb3|fuse.sshfs)
      independence_mode="network-filesystem"
      ;;
    *)
      fail "off-host mount must be a distinct physical block device or supported network filesystem" 3
      ;;
  esac
fi

source_record="$(
  find "$BACKUP_ROOT" -maxdepth 1 -type f -regextype posix-extended \
    -regex '.*/edge-state-[0-9]{8}T[0-9]{6}Z\.tar\.age' \
    -printf '%T@ %p\n' \
    | sort -nr \
    | head -n 1 || true
)"
[[ -n "$source_record" ]] || fail "no encrypted host-state backup found" 4
source="${source_record#* }"
source="$(readlink -f -- "$source")"
[[ "$(dirname -- "$source")" == "$BACKUP_ROOT" ]] || fail "source escaped canonical backup root" 4
source_name="$(basename -- "$source")"
[[ "$source_name" =~ ^edge-state-[0-9]{8}T[0-9]{6}Z\.tar\.age$ ]] || fail "invalid backup filename" 4

manifest="${source}.sha256"
[[ -f "$manifest" ]] || fail "missing source SHA-256 manifest" 4
expected_hash="$(awk 'NR==1 {print $1}' "$manifest")"
[[ "$expected_hash" =~ ^[0-9a-f]{64}$ ]] || fail "invalid source SHA-256 manifest" 4
actual_hash="$(sha256sum "$source" | awk '{print $1}')"
[[ "$actual_hash" == "$expected_hash" ]] || fail "source backup hash mismatch" 5

mkdir -p "$DEST_ROOT" "$EVIDENCE_ROOT"
chmod 0700 "$DEST_ROOT"
destination="${DEST_ROOT}/${source_name}"
destination_manifest="${destination}.sha256"
[[ ! -e "$destination" && ! -e "$destination_manifest" ]] || fail "destination archive or manifest already exists; immutable copy refused" 6

tmp="${destination}.tmp.$$"
trap 'rm -f -- "${tmp:-}"' EXIT
install -m 0600 -- "$source" "$tmp"
copied_hash="$(sha256sum "$tmp" | awk '{print $1}')"
[[ "$copied_hash" == "$expected_hash" ]] || fail "off-host copy hash mismatch" 7
mv -- "$tmp" "$destination"
printf '%s  %s\n' "$expected_hash" "$source_name" > "$destination_manifest"
chmod 0600 "$destination_manifest"
sync -f "$destination"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence="${EVIDENCE_ROOT}/offhost-backup-${stamp}.json"
[[ ! -e "$evidence" ]] || fail "evidence path collision" 8

export QC_OFFHOST_EVIDENCE="$evidence"
export QC_OFFHOST_SOURCE_NAME="$source_name"
export QC_OFFHOST_SHA256="$expected_hash"
export QC_OFFHOST_SOURCE_SIZE="$(stat -c '%s' "$source")"
export QC_OFFHOST_DEST_SIZE="$(stat -c '%s' "$destination")"
export QC_OFFHOST_MOUNT_SOURCE="$offhost_mount_source"
export QC_OFFHOST_MOUNT_FSTYPE="$offhost_mount_fstype"
export QC_OFFHOST_SOURCE_MOUNT_SOURCE="$source_mount_source"
export QC_OFFHOST_SOURCE_MOUNT_FSTYPE="$source_mount_fstype"
export QC_OFFHOST_SOURCE_DEV="$source_dev"
export QC_OFFHOST_DEST_DEV="$offhost_dev"
export QC_OFFHOST_INDEPENDENCE_MODE="$independence_mode"
export QC_OFFHOST_SOURCE_TOP_DISK="$source_top_disk"
export QC_OFFHOST_DEST_TOP_DISK="$offhost_top_disk"

python3 - <<'PY'
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

path = Path(os.environ["QC_OFFHOST_EVIDENCE"])
def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

payload = {
    "schema": "queen-califia-offhost-backup-evidence-v1",
    "collected_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "encrypted_archive_name": os.environ["QC_OFFHOST_SOURCE_NAME"],
    "archive_sha256": os.environ["QC_OFFHOST_SHA256"],
    "source_size": int(os.environ["QC_OFFHOST_SOURCE_SIZE"]),
    "destination_size": int(os.environ["QC_OFFHOST_DEST_SIZE"]),
    "source_destination_hash_equal": True,
    "separate_filesystem_device": os.environ["QC_OFFHOST_SOURCE_DEV"] != os.environ["QC_OFFHOST_DEST_DEV"],
    "independence_mode": os.environ["QC_OFFHOST_INDEPENDENCE_MODE"],
    "offhost_mount": "/mnt/qc-offhost-backup",
    "offhost_mount_source_sha256": digest(os.environ["QC_OFFHOST_MOUNT_SOURCE"]),
    "offhost_mount_fstype": os.environ["QC_OFFHOST_MOUNT_FSTYPE"],
    "source_mount_source_sha256": digest(os.environ["QC_OFFHOST_SOURCE_MOUNT_SOURCE"]),
    "source_mount_fstype": os.environ["QC_OFFHOST_SOURCE_MOUNT_FSTYPE"],
    "source_top_disk_sha256": digest(os.environ["QC_OFFHOST_SOURCE_TOP_DISK"]) if os.environ["QC_OFFHOST_SOURCE_TOP_DISK"] else None,
    "offhost_top_disk_sha256": digest(os.environ["QC_OFFHOST_DEST_TOP_DISK"]) if os.environ["QC_OFFHOST_DEST_TOP_DISK"] else None,
    "authorization_modified": False,
    "deployment_ledger_modified": False,
}
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
os.chmod(path, 0o600)
PY

evidence_hash="$(sha256sum "$evidence" | awk '{print $1}')"
evidence_copy="${DEST_ROOT}/$(basename -- "$evidence")"
[[ ! -e "$evidence_copy" ]] || fail "off-host evidence copy already exists" 8
install -m 0600 -- "$evidence" "$evidence_copy"
[[ "$(sha256sum "$evidence_copy" | awk '{print $1}')" == "$evidence_hash" ]] || fail "evidence-copy hash mismatch" 9
sync -f "$evidence_copy"
trap - EXIT

printf 'OFFHOST_BACKUP_PROOF=PASS\n'
printf 'OFFHOST_BACKUP_INDEPENDENCE=%s\n' "$independence_mode"
printf 'OFFHOST_BACKUP_ARCHIVE_SHA256=%s\n' "$expected_hash"
printf 'OFFHOST_BACKUP_EVIDENCE=%s\n' "$evidence"
printf 'OFFHOST_BACKUP_EVIDENCE_SHA256=%s\n' "$evidence_hash"
printf 'OFFHOST_BACKUP_LEDGER_UPDATED=NO\n'
printf 'OFFHOST_BACKUP_AUTHORIZATION_UPDATED=NO\n'
