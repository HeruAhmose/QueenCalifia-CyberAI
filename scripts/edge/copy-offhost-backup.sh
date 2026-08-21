#!/usr/bin/env bash
set -euo pipefail

STATE_ROOT="/srv/queen-califia"
BACKUP_ROOT="${STATE_ROOT}/backups"
EVIDENCE_ROOT="${STATE_ROOT}/evidence"
AUTH_MARKER="${STATE_ROOT}/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED"
OFFHOST_ROOT="/mnt/qc-offhost-backup"
DEST_ROOT="${OFFHOST_ROOT}/queen-califia/host-state"

[[ "${EUID}" -eq 0 ]] || { echo "OFFHOST_BACKUP_ERROR=run as root" >&2; exit 1; }
[[ ! -e "$AUTH_MARKER" ]] || { echo "OFFHOST_BACKUP_ERROR=authorization marker exists; preauthorization backup proof refused" >&2; exit 78; }
[[ -d "$BACKUP_ROOT" ]] || { echo "OFFHOST_BACKUP_ERROR=missing canonical backup root" >&2; exit 2; }
[[ -d "$OFFHOST_ROOT" ]] || { echo "OFFHOST_BACKUP_ERROR=mount independent storage at $OFFHOST_ROOT" >&2; exit 2; }

mount_target="$(findmnt -n -o TARGET --target "$OFFHOST_ROOT" 2>/dev/null || true)"
[[ "$mount_target" == "$OFFHOST_ROOT" ]] || {
  echo "OFFHOST_BACKUP_ERROR=$OFFHOST_ROOT must be a dedicated mount point" >&2
  exit 3
}

source_dev="$(stat -c '%d' "$BACKUP_ROOT")"
offhost_dev="$(stat -c '%d' "$OFFHOST_ROOT")"
[[ "$source_dev" != "$offhost_dev" ]] || {
  echo "OFFHOST_BACKUP_ERROR=off-host destination is on the same filesystem/device as source backups" >&2
  exit 3
}

source_record="$(
  find "$BACKUP_ROOT" -maxdepth 1 -type f -regextype posix-extended \
    -regex '.*/edge-state-[0-9]{8}T[0-9]{6}Z\.tar\.age' \
    -printf '%T@ %p\n' \
    | sort -nr \
    | head -n 1 || true
)"
[[ -n "$source_record" ]] || { echo "OFFHOST_BACKUP_ERROR=no encrypted host-state backup found" >&2; exit 4; }
source="${source_record#* }"
source="$(readlink -f -- "$source")"
[[ "$(dirname -- "$source")" == "$BACKUP_ROOT" ]] || { echo "OFFHOST_BACKUP_ERROR=source escaped canonical backup root" >&2; exit 4; }
source_name="$(basename -- "$source")"
[[ "$source_name" =~ ^edge-state-[0-9]{8}T[0-9]{6}Z\.tar\.age$ ]] || { echo "OFFHOST_BACKUP_ERROR=invalid backup filename" >&2; exit 4; }

manifest="${source}.sha256"
[[ -f "$manifest" ]] || { echo "OFFHOST_BACKUP_ERROR=missing source SHA-256 manifest" >&2; exit 4; }
expected_hash="$(awk 'NR==1 {print $1}' "$manifest")"
[[ "$expected_hash" =~ ^[0-9a-f]{64}$ ]] || { echo "OFFHOST_BACKUP_ERROR=invalid source SHA-256 manifest" >&2; exit 4; }
actual_hash="$(sha256sum "$source" | awk '{print $1}')"
[[ "$actual_hash" == "$expected_hash" ]] || { echo "OFFHOST_BACKUP_ERROR=source backup hash mismatch" >&2; exit 5; }

mkdir -p "$DEST_ROOT" "$EVIDENCE_ROOT"
chmod 0700 "$DEST_ROOT"
destination="${DEST_ROOT}/${source_name}"
destination_manifest="${destination}.sha256"
[[ ! -e "$destination" && ! -e "$destination_manifest" ]] || {
  echo "OFFHOST_BACKUP_ERROR=destination archive or manifest already exists; immutable copy refused" >&2
  exit 6
}

tmp="${destination}.tmp.$$"
trap 'rm -f -- "${tmp:-}"' EXIT
install -m 0600 -- "$source" "$tmp"
copied_hash="$(sha256sum "$tmp" | awk '{print $1}')"
[[ "$copied_hash" == "$expected_hash" ]] || { echo "OFFHOST_BACKUP_ERROR=off-host copy hash mismatch" >&2; exit 7; }
mv -- "$tmp" "$destination"
printf '%s  %s\n' "$expected_hash" "$source_name" > "$destination_manifest"
chmod 0600 "$destination_manifest"
sync -f "$destination"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence="${EVIDENCE_ROOT}/offhost-backup-${stamp}.json"
[[ ! -e "$evidence" ]] || { echo "OFFHOST_BACKUP_ERROR=evidence path collision" >&2; exit 8; }

export QC_OFFHOST_EVIDENCE="$evidence"
export QC_OFFHOST_SOURCE_NAME="$source_name"
export QC_OFFHOST_SHA256="$expected_hash"
export QC_OFFHOST_SOURCE_SIZE="$(stat -c '%s' "$source")"
export QC_OFFHOST_DEST_SIZE="$(stat -c '%s' "$destination")"
export QC_OFFHOST_MOUNT_SOURCE="$(findmnt -n -o SOURCE --target "$OFFHOST_ROOT")"
export QC_OFFHOST_MOUNT_FSTYPE="$(findmnt -n -o FSTYPE --target "$OFFHOST_ROOT")"
export QC_OFFHOST_SOURCE_DEV="$source_dev"
export QC_OFFHOST_DEST_DEV="$offhost_dev"

python3 - <<'PY'
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

path = Path(os.environ["QC_OFFHOST_EVIDENCE"])
mount_source = os.environ["QC_OFFHOST_MOUNT_SOURCE"]
payload = {
    "schema": "queen-califia-offhost-backup-evidence-v1",
    "collected_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "encrypted_archive_name": os.environ["QC_OFFHOST_SOURCE_NAME"],
    "archive_sha256": os.environ["QC_OFFHOST_SHA256"],
    "source_size": int(os.environ["QC_OFFHOST_SOURCE_SIZE"]),
    "destination_size": int(os.environ["QC_OFFHOST_DEST_SIZE"]),
    "source_destination_hash_equal": True,
    "separate_filesystem_device": os.environ["QC_OFFHOST_SOURCE_DEV"] != os.environ["QC_OFFHOST_DEST_DEV"],
    "offhost_mount": "/mnt/qc-offhost-backup",
    "offhost_mount_source_sha256": hashlib.sha256(mount_source.encode("utf-8")).hexdigest(),
    "offhost_mount_fstype": os.environ["QC_OFFHOST_MOUNT_FSTYPE"],
    "authorization_modified": False,
    "deployment_ledger_modified": False,
}
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
os.chmod(path, 0o600)
PY

evidence_hash="$(sha256sum "$evidence" | awk '{print $1}')"
evidence_copy="${DEST_ROOT}/$(basename -- "$evidence")"
[[ ! -e "$evidence_copy" ]] || { echo "OFFHOST_BACKUP_ERROR=off-host evidence copy already exists" >&2; exit 8; }
install -m 0600 -- "$evidence" "$evidence_copy"
[[ "$(sha256sum "$evidence_copy" | awk '{print $1}')" == "$evidence_hash" ]] || {
  echo "OFFHOST_BACKUP_ERROR=evidence-copy hash mismatch" >&2
  exit 9
}
sync -f "$evidence_copy"
trap - EXIT

printf 'OFFHOST_BACKUP_PROOF=PASS\n'
printf 'OFFHOST_BACKUP_ARCHIVE_SHA256=%s\n' "$expected_hash"
printf 'OFFHOST_BACKUP_EVIDENCE=%s\n' "$evidence"
printf 'OFFHOST_BACKUP_EVIDENCE_SHA256=%s\n' "$evidence_hash"
printf 'OFFHOST_BACKUP_LEDGER_UPDATED=NO\n'
printf 'OFFHOST_BACKUP_AUTHORIZATION_UPDATED=NO\n'
