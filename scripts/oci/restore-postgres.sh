#!/usr/bin/env bash
set -euo pipefail

backup="${1:-}"
identity="${QC_BACKUP_AGE_IDENTITY_FILE:-}"
live_url="${QC_DATABASE_DIRECT_URL:-}"
restore_url="${QC_RESTORE_DATABASE_URL:-}"
[[ -n "$backup" && -f "$backup" ]] || { echo "usage: restore-postgres.sh <backup.dump.age>" >&2; exit 2; }
[[ -n "$identity" && -f "$identity" ]] || { echo "QC_BACKUP_AGE_IDENTITY_FILE must point to an age identity file" >&2; exit 2; }
[[ -f "${backup}.sha256" ]] || { echo "missing checksum manifest: ${backup}.sha256" >&2; exit 2; }
sha256sum --check "${backup}.sha256"
[[ "$restore_url" == postgresql://* || "$restore_url" == postgres://* ]] || { echo "QC_RESTORE_DATABASE_URL must identify a separate verification database/branch" >&2; exit 2; }
[[ "$restore_url" == *"sslmode=require"* ]] || { echo "QC_RESTORE_DATABASE_URL must require sslmode=require" >&2; exit 2; }
[[ "$restore_url" != *"-pooler."* ]] || { echo "restore verification must use a direct PostgreSQL endpoint" >&2; exit 2; }
if [[ -n "$live_url" && "$restore_url" == "$live_url" && "${QC_ALLOW_LIVE_DATABASE_RESTORE:-0}" != "1" ]]; then
  echo "refusing restore into live authority; use a separate verification database/branch" >&2
  exit 3
fi

# Target must already exist and be dedicated to restore verification.
# pg_restore --clean is intentionally not used; target-empty enforcement remains explicit.
if docker run --rm postgres:18-alpine psql "$restore_url" -Atqc \
  "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'" | grep -vq '^0$'; then
  echo "restore verification target must have zero public base tables" >&2
  exit 3
fi

age -d -i "$identity" "$backup" \
  | docker run --rm -i postgres:18-alpine \
      pg_restore --exit-on-error --no-owner --no-acl --dbname "$restore_url"

echo "RESTORE_VERIFIED_TARGET=separate-direct-postgresql-authority"
