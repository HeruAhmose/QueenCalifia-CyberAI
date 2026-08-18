#!/usr/bin/env bash
set -euo pipefail

backup="${1:-}"
identity="${QC_BACKUP_AGE_IDENTITY_FILE:-}"
compose="${QC_OCI_COMPOSE_FILE:-deploy/oci/docker-compose.oci.yml}"
[[ -n "$backup" && -f "$backup" ]] || { echo "usage: restore-postgres.sh <backup.dump.age>" >&2; exit 2; }
[[ -n "$identity" && -f "$identity" ]] || { echo "QC_BACKUP_AGE_IDENTITY_FILE must point to an age identity file" >&2; exit 2; }
[[ -f "${backup}.sha256" ]] || { echo "missing checksum manifest: ${backup}.sha256" >&2; exit 2; }
sha256sum --check "${backup}.sha256"

# Restore is deliberately destructive only to the named target database.
# Default target is a separate verification database, never the live authority.
target="${QC_RESTORE_DATABASE:-queen_restore_verify}"
case "$target" in
  "${QC_POSTGRES_DB:-queen}")
    [[ "${QC_ALLOW_LIVE_DATABASE_RESTORE:-0}" == "1" ]] || { echo "refusing restore into live database without QC_ALLOW_LIVE_DATABASE_RESTORE=1" >&2; exit 3; }
    ;;
esac

docker compose -f "$compose" --profile state exec -T postgres \
  sh -ceu 'dropdb --if-exists -U "$POSTGRES_USER" "$1"; createdb -U "$POSTGRES_USER" "$1"' sh "$target"

age -d -i "$identity" "$backup" \
  | docker compose -f "$compose" --profile state exec -T postgres \
      pg_restore --exit-on-error --no-owner --no-acl \
        --username "${QC_POSTGRES_USER:-queen}" --dbname "$target"

echo "RESTORE_VERIFIED_DATABASE=$target"
