#!/usr/bin/env bash
set -euo pipefail

ROOT="${QC_EDGE_STATE_ROOT:-/srv/queen-califia}"
RECIPIENTS="${QC_BACKUP_AGE_RECIPIENTS_FILE:-}"
DIRECT_URL="${QC_DATABASE_DIRECT_URL:-}"
[[ -n "$RECIPIENTS" && -f "$RECIPIENTS" ]] || { echo "QC_BACKUP_AGE_RECIPIENTS_FILE must point to an age recipients file" >&2; exit 2; }
[[ "$DIRECT_URL" == postgresql://* || "$DIRECT_URL" == postgres://* ]] || { echo "QC_DATABASE_DIRECT_URL must be the direct PostgreSQL authority URL" >&2; exit 2; }
[[ "$DIRECT_URL" == *"sslmode=require"* ]] || { echo "QC_DATABASE_DIRECT_URL must require sslmode=require" >&2; exit 2; }
[[ "$DIRECT_URL" != *"-pooler."* ]] || { echo "pg_dump must use the direct Neon endpoint, not the pooled hostname" >&2; exit 2; }

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="${ROOT}/backups/queen-${stamp}.dump.age"
manifest="${out}.sha256"
tmp="${out}.tmp"
mkdir -p "${ROOT}/backups"
umask 077

docker run --rm -i postgres:18-alpine \
  pg_dump --format=custom --no-owner --no-acl --dbname "$DIRECT_URL" \
  | age -R "$RECIPIENTS" -o "$tmp"

mv "$tmp" "$out"
sha256sum "$out" > "$manifest"
chmod 0600 "$out" "$manifest"
printf 'BACKUP=%s\nSHA256=%s\n' "$out" "$(cut -d' ' -f1 "$manifest")"
