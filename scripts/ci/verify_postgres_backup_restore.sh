#!/usr/bin/env bash
set -euo pipefail

# Real PostgreSQL 16 backup/restore contract:
#   representative migrated SQLite state -> PostgreSQL source DB
#   runtime migration manifest + whole-public-schema/database fingerprint
#   pg_dump --format=custom
#   pg_restore into a separate DB
#   both targeted runtime and whole-database verification against the restore

BASE_URL="${QC_TEST_POSTGRES_URL:?QC_TEST_POSTGRES_URL is required}"
if [[ "$BASE_URL" != "postgresql://queen:queen-ci@127.0.0.1:5432/queen_ci" ]]; then
  echo "backup/restore contract only permits the isolated CI PostgreSQL service" >&2
  exit 2
fi

SOURCE_URL="postgresql://queen:queen-ci@127.0.0.1:5432/queen_backup_ci"
RESTORE_URL="postgresql://queen:queen-ci@127.0.0.1:5432/queen_restore_ci"
CONTRACT_DIR="/tmp/qc-postgres-backup-contract"
RUNTIME_MANIFEST="$CONTRACT_DIR/runtime-manifest.json"
DATABASE_MANIFEST="$CONTRACT_DIR/database-manifest.json"
DUMP="$CONTRACT_DIR/runtime-state.dump"
mkdir -p "$CONTRACT_DIR"
rm -f "$RUNTIME_MANIFEST" "$DATABASE_MANIFEST" "$DUMP"

cleanup() {
  QC_TEST_POSTGRES_URL="$BASE_URL" python - <<'PY'
import os
import psycopg
from psycopg import sql
url = os.environ["QC_TEST_POSTGRES_URL"]
with psycopg.connect(url, autocommit=True) as conn:
    for name in ("queen_backup_ci", "queen_restore_ci"):
        conn.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=%s AND pid <> pg_backend_pid()",
            (name,),
        )
        conn.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(name)))
PY
}
trap cleanup EXIT

QC_TEST_POSTGRES_URL="$BASE_URL" python - <<'PY'
import os
import psycopg
from psycopg import sql
url = os.environ["QC_TEST_POSTGRES_URL"]
with psycopg.connect(url, autocommit=True) as conn:
    for name in ("queen_backup_ci", "queen_restore_ci"):
        conn.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(name)))
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
PY

QC_BACKUP_SOURCE_URL="$SOURCE_URL" \
  python scripts/ci/seed_backup_restore_contract.py > "$RUNTIME_MANIFEST"
test -s "$RUNTIME_MANIFEST"

QC_DATABASE_URL="$SOURCE_URL" \
  python scripts/postgres_database_manifest.py > "$DATABASE_MANIFEST"
test -s "$DATABASE_MANIFEST"

# Use the exact PostgreSQL major version used by the CI service. Network and
# filesystem locations are fixed by this script rather than caller supplied.
docker run --rm --network host \
  -e PGPASSWORD=queen-ci \
  -v "$CONTRACT_DIR:/backup" \
  postgres:16-alpine \
  pg_dump --host=127.0.0.1 --port=5432 --username=queen \
    --dbname=queen_backup_ci --format=custom --no-owner --no-privileges \
    --file=/backup/runtime-state.dump

test -s "$DUMP"

docker run --rm --network host \
  -e PGPASSWORD=queen-ci \
  -v "$CONTRACT_DIR:/backup:ro" \
  postgres:16-alpine \
  pg_restore --host=127.0.0.1 --port=5432 --username=queen \
    --dbname=queen_restore_ci --no-owner --no-privileges \
    /backup/runtime-state.dump

python scripts/migrate_runtime_state_to_postgres.py \
  --database-url "$RESTORE_URL" \
  --verify-manifest-stdin < "$RUNTIME_MANIFEST"

QC_DATABASE_URL="$RESTORE_URL" \
  python scripts/postgres_database_manifest.py --verify-stdin \
  < "$DATABASE_MANIFEST"

echo "PostgreSQL 16 pg_dump -> separate pg_restore -> targeted and whole-database verification passed."
