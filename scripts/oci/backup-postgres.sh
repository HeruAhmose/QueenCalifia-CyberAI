#!/usr/bin/env bash
set -euo pipefail

ROOT="${QC_OCI_STATE_ROOT:-/srv/queen-califia}"
COMPOSE="${QC_OCI_COMPOSE_FILE:-deploy/oci/docker-compose.oci.yml}"
RECIPIENTS="${QC_BACKUP_AGE_RECIPIENTS_FILE:-}"
[[ -n "$RECIPIENTS" && -f "$RECIPIENTS" ]] || { echo "QC_BACKUP_AGE_RECIPIENTS_FILE must point to an age recipients file" >&2; exit 2; }

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="${ROOT}/backups/queen-${stamp}.dump.age"
manifest="${out}.sha256"
tmp="${out}.tmp"
mkdir -p "${ROOT}/backups"
umask 077

# pg_dump custom format is produced inside the PostgreSQL 16 container and
# encrypted immediately on the host. No plaintext dump is written to disk.
docker compose -f "$COMPOSE" --profile state exec -T postgres \
  pg_dump --format=custom --no-owner --no-acl \
    --username "${QC_POSTGRES_USER:-queen}" "${QC_POSTGRES_DB:-queen}" \
  | age -R "$RECIPIENTS" -o "$tmp"

mv "$tmp" "$out"
sha256sum "$out" > "$manifest"
chmod 0600 "$out" "$manifest"
printf 'BACKUP=%s\nSHA256=%s\n' "$out" "$(cut -d' ' -f1 "$manifest")"
