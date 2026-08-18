#!/usr/bin/env bash
set -euo pipefail

# Real PostgreSQL 16 backup/restore contract:
#   representative migrated SQLite state -> PostgreSQL source DB
#   pg_dump --format=custom
#   pg_restore into a separate DB
#   deterministic migration-manifest verification against the restored DB

BASE_URL="${QC_TEST_POSTGRES_URL:?QC_TEST_POSTGRES_URL is required}"
if [[ "$BASE_URL" != "postgresql://queen:queen-ci@127.0.0.1:5432/queen_ci" ]]; then
  echo "backup/restore contract only permits the isolated CI PostgreSQL service" >&2
  exit 2
fi

SOURCE_URL="postgresql://queen:queen-ci@127.0.0.1:5432/queen_backup_ci"
RESTORE_URL="postgresql://queen:queen-ci@127.0.0.1:5432/queen_restore_ci"
CONTRACT_DIR="/tmp/qc-postgres-backup-contract"
MANIFEST="$CONTRACT_DIR/manifest.json"
DUMP="$CONTRACT_DIR/runtime-state.dump"
mkdir -p "$CONTRACT_DIR"
rm -f "$MANIFEST" "$DUMP"

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
  python scripts/ci/seed_backup_restore_contract.py > "$MANIFEST"
test -s "$MANIFEST"

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
  --verify-manifest-stdin < "$MANIFEST"

echo "PostgreSQL 16 pg_dump -> pg_restore -> runtime-state manifest verification passed."
