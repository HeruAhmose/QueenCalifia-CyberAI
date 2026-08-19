#!/usr/bin/env bash
set -euo pipefail

ROOT="${QC_EDGE_STATE_ROOT:-/srv/queen-califia}"
RECIPIENTS="${QC_BACKUP_AGE_RECIPIENTS_FILE:-}"
[[ -n "$RECIPIENTS" && -f "$RECIPIENTS" ]] || { echo "QC_BACKUP_AGE_RECIPIENTS_FILE must point to an age recipients file" >&2; exit 2; }
for dir in app evidence valkey pki; do
  [[ -d "$ROOT/$dir" ]] || { echo "missing edge state directory: $ROOT/$dir" >&2; exit 2; }
done

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="${ROOT}/backups/edge-state-${stamp}.tar.age"
tmp="${out}.tmp"
manifest="${out}.sha256"
mkdir -p "$ROOT/backups"
umask 077

# Stream the archive directly into age; no plaintext tarball is written.
tar --numeric-owner --acls --xattrs -C "$ROOT" -cf - app evidence valkey pki \
  | age -R "$RECIPIENTS" -o "$tmp"

mv "$tmp" "$out"
sha256sum "$out" > "$manifest"
chmod 0600 "$out" "$manifest"
printf 'HOST_BACKUP=%s\nSHA256=%s\n' "$out" "$(cut -d' ' -f1 "$manifest")"
