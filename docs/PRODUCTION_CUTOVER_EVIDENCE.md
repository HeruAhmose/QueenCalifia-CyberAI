# Production cutover evidence runbook

This is the evidence gate between the current single-writer SQLite/file-backed deployment and a future PostgreSQL/Celery production cutover. It does **not** authorize multi-replica API operation, read-only root filesystems, PVC deletion, or deletion of legacy state.

## Non-negotiable safety boundary

The legacy live-scanner database is container-local at:

`/opt/render/project/src/backend/data/qc_scans.db`

It is **not** on the `/var/data` PVC. Capture or explicitly verify its absence from the existing API pod before any action that can replace, restart, evict, reschedule, scale down, or delete that pod. A rollout before this check can permanently destroy historical live-scanner state.

The `/var/data` PVC remains attached throughout this evidence gate.

## Prerequisites

- Declared maintenance window; mutating traffic is quiesced without deleting the existing API pod.
- `kubectl` authenticated to the intended production cluster/namespace.
- Empty PostgreSQL production target and a second, separate empty PostgreSQL restore database.
- PostgreSQL 16 `pg_dump` / `pg_restore` clients.
- `QC_AUDIT_HMAC_KEY` available only through the operator's secret mechanism for audit-chain verification.
- Secure operator workstation. `.cutover-staging/` is git-ignored but contains sensitive operational state and must be mode `0700` and access-controlled.

Never put database URLs, passwords, API keys, bearer tokens, private keys, or HMAC keys into the secret-free evidence JSON.

## Phase 0 — identify and freeze without replacing the pod

```bash
export QC_NAMESPACE='queen-califia-production'
export QC_API_POD='<current-qc-api-pod>'
kubectl -n "$QC_NAMESPACE" get deploy qc-api -o wide
kubectl -n "$QC_NAMESPACE" get pods -l app=qc-api -o wide
kubectl -n "$QC_NAMESPACE" get pod "$QC_API_POD" \
  -o jsonpath='{.metadata.uid}{"\n"}{.status.containerStatuses[?(@.name=="api")].imageID}{"\n"}'
```

Confirm exactly one API writer. Quiesce external mutating traffic and asynchronous producers/workers using the production maintenance procedure. **Do not scale `qc-api` to zero and do not trigger a rollout.** The old API container must stay alive until the container-local live-scanner source is captured or explicitly verified absent.

Record the freeze procedure in change control, not in the evidence JSON.

## Phase 1 — consistent source capture

```bash
install -d -m 0700 .cutover-staging
```

### 1A. SQLite snapshots

Use Python already present in the running API image and SQLite's online backup API. `kubectl exec -i` is required so the heredoc is actually delivered to Python in the pod.

```bash
kubectl -n "$QC_NAMESPACE" exec -i "$QC_API_POD" -c api -- python - <<'PY'
import os
import sqlite3
from pathlib import Path

pairs = [
    (os.environ.get("QC_DB_PATH", "/var/data/queen.db"), "/var/data/cutover-primary.db"),
    (os.environ.get("QC_EVOLUTION_DB", "/var/data/qc_evolution.db"), "/var/data/cutover-evolution.db"),
    (os.environ.get("QC_THREAT_INTEL_DB", "/var/data/qc_threat_intel.db"), "/var/data/cutover-threat-intel.db"),
    ("/opt/render/project/src/backend/data/qc_scans.db", "/var/data/cutover-live-scanner.db"),
]
for source, destination in pairs:
    src = Path(source)
    if not src.is_file():
        print(f"ABSENT\t{source}")
        continue
    dst = Path(destination)
    if dst.exists():
        raise SystemExit(f"refusing to overwrite existing capture: {destination}")
    with sqlite3.connect(f"file:{src}?mode=ro", uri=True) as source_db:
        source_db.execute("PRAGMA query_only=ON")
        with sqlite3.connect(dst) as target_db:
            source_db.backup(target_db)
    os.chmod(dst, 0o600)
    print(f"CAPTURED\t{source}\t{destination}")
PY
```

**First copy the live-scanner snapshot off the pod if it was reported `CAPTURED`:**

```bash
kubectl -n "$QC_NAMESPACE" cp \
  "$QC_API_POD:/var/data/cutover-live-scanner.db" \
  .cutover-staging/qc-live-scanner-legacy.db -c api
sha256sum .cutover-staging/qc-live-scanner-legacy.db
```

If it was reported `ABSENT`, record `live-scanner-db` as `verified-absent` with the pod UID and a non-secret reason; do not create an empty substitute database.

Copy each other snapshot that was reported `CAPTURED` and hash it:

```bash
kubectl -n "$QC_NAMESPACE" cp "$QC_API_POD:/var/data/cutover-primary.db" .cutover-staging/primary.db -c api
kubectl -n "$QC_NAMESPACE" cp "$QC_API_POD:/var/data/cutover-evolution.db" .cutover-staging/evolution.db -c api
kubectl -n "$QC_NAMESPACE" cp "$QC_API_POD:/var/data/cutover-threat-intel.db" .cutover-staging/threat-intel.db -c api
sha256sum .cutover-staging/primary.db .cutover-staging/evolution.db .cutover-staging/threat-intel.db
```

The vulnerability archival mode requires the fixed staging name and refuses a source without `qc_vuln_scan_jobs`:

```bash
cp --preserve=mode,timestamps \
  .cutover-staging/primary.db \
  .cutover-staging/qc-vulnerability-legacy.db
```

Do not interpret a missing `qc_vuln_scan_jobs` table as a successful empty migration; investigate and record the actual production source state.

### 1B. File-backed evidence

Check `QC_API_KEYS_FILE`, `QC_AUDIT_LOG_FILE`, and `QC_SPKI_LOG_FILE` in the frozen source pod:

```bash
kubectl -n "$QC_NAMESPACE" exec "$QC_API_POD" -c api -- sh -c '
for p in "${QC_API_KEYS_FILE:-/var/data/keys.json}" "${QC_AUDIT_LOG_FILE:-/var/data/audit.log.jsonl}" "${QC_SPKI_LOG_FILE:-/var/data/spki.jsonl}"; do
  if [ -f "$p" ]; then printf "PRESENT\t%s\n" "$p"; else printf "ABSENT\t%s\n" "$p"; fi
done'
```

For every `PRESENT` source, copy/stream it to secured local staging and record its SHA-256. For every `ABSENT` source, record `verified-absent` plus `checked: true` and a non-secret reason. Never create an empty replacement merely to satisfy a migration command.

## Phase 2 — migrate into an empty PostgreSQL authority

Point `QC_DATABASE_URL` at the production target through the operator's secret mechanism. The migration/disposition tools fail closed when their target authority is already occupied.

For captured runtime SQLite authorities:

```bash
python scripts/migrate_runtime_state_to_postgres.py \
  --primary-sqlite .cutover-staging/primary.db \
  --evolution-sqlite .cutover-staging/evolution.db \
  --threat-intel-sqlite .cutover-staging/threat-intel.db \
  --emit-manifest-json > .cutover-staging/runtime-state-manifest.json
sha256sum .cutover-staging/runtime-state-manifest.json
```

Run scanner dispositions only when the corresponding historical source exists and is valid:

```bash
python scripts/disposition_legacy_runtime_state.py vulnerability \
  > .cutover-staging/disposition-vulnerability.json
python scripts/disposition_legacy_runtime_state.py live-scanner \
  > .cutover-staging/disposition-live-scanner.json
```

For file sources reported `PRESENT`, use the stdin-only disposition modes:

```bash
python scripts/disposition_legacy_runtime_state.py api-keys \
  < .cutover-staging/keys.json > .cutover-staging/disposition-api-keys.json
python scripts/disposition_legacy_runtime_state.py audit-log \
  < .cutover-staging/audit.log.jsonl > .cutover-staging/disposition-audit-log.json
python scripts/disposition_legacy_runtime_state.py spki \
  < .cutover-staging/spki.jsonl > .cutover-staging/disposition-spki.json
```

For a file source reported `verified-absent`, the evidence bundle must carry the matching disposition as:

```json
{"kind":"spki","status":"not-applicable-source-absent"}
```

Do not attach `verified: true` or an `evidence_sha256` to an absent-source disposition.

## Phase 3 — whole-database source manifest

After migrations/dispositions and before the target accepts live traffic:

```bash
python scripts/postgres_database_manifest.py \
  > .cutover-staging/postgres-source-manifest.json
```

The manifest covers every public base table's columns, constraints, indexes, row count, deterministic content digest, plus public sequence definition/current state. It contains no row values or connection URL. Record its `database_sha256`.

## Phase 4 — real production-data backup and separate restore

Create a PostgreSQL 16 custom-format dump using the operator's credential mechanism:

```bash
pg_dump --format=custom --no-owner --no-privileges \
  --file=.cutover-staging/production-runtime-state.dump "$QC_DATABASE_URL"
sha256sum .cutover-staging/production-runtime-state.dump
```

Restore to the **separate empty restore database**:

```bash
pg_restore --no-owner --no-privileges \
  --dbname="$QC_RESTORE_DATABASE_URL" \
  .cutover-staging/production-runtime-state.dump

QC_DATABASE_URL="$QC_RESTORE_DATABASE_URL" \
  python scripts/postgres_database_manifest.py --verify-stdin \
  < .cutover-staging/postgres-source-manifest.json
```

A count-only check is insufficient. Any missing/unexpected/changed table, schema contract, row digest, or sequence state fails verification.

## Phase 5 — single-replica authority cutover and probes

Only after Phases 1–4 succeed may a **separate deployment change** point the single API replica at PostgreSQL/Celery/Redis. Keep the old PVC and captured sources retained.

Prove in production that:

1. PostgreSQL is the active API/runtime authority.
2. Celery/Redis is the vulnerability job/result authority.
3. Production composition cannot write a legacy SQLite/file authority.
4. The API is still exactly one replica.
5. The root filesystem is still writable pending the later writable-path inventory/rootfs gate.

Do not remove `/var/data`, its PVC, or legacy environment bindings in this evidence-tooling PR.

## Phase 6 — secret-free immutable evidence bundle

Build a JSON object accepted by `scripts/verify_production_cutover_evidence.py` containing:

- source API pod UID and immutable image digest;
- every required source as `captured` + SHA-256 or explicit `verified-absent`;
- runtime migration manifest digest;
- scanner/file disposition evidence, with source absence propagated rather than fabricated;
- whole-database target manifest digest;
- production dump SHA-256;
- source and restored whole-database manifest digests, which must match;
- PostgreSQL, Celery/Redis, and legacy-write-disable probes;
- confirmation that legacy sources remain preserved and legacy bindings are still present.

Validate only through stdin:

```bash
python scripts/verify_production_cutover_evidence.py \
  < .cutover-staging/production-cutover-evidence.json
```

The verifier emits a canonical `evidence_sha256`. Record that digest in issue #72/change control and store the full **secret-free** evidence JSON in the approved immutable evidence location.

Success means only `eligible_for_legacy_binding_removal_review: true`. It always returns `ha_authorized: false`.

## Stop conditions

Abort and preserve all source state if:

- the original API pod is replaced before live-scanner capture/absence proof;
- a source cannot be accounted for;
- SQLite read-only backup fails;
- the PostgreSQL target is not empty before import;
- migration/disposition/audit-chain verification fails;
- source and restore whole-database manifests differ;
- restore is not into a separate database;
- production can still write a legacy authority;
- evidence contains credentials or secret material.

## After this gate

Only after real production evidence is independently reviewed should a new PR remove obsolete PVC/file bindings and enumerate all remaining writable paths. That later stage must prove rolling update behavior and a read-only root filesystem. Multi-replica API/HA remains a separate final gate after those checks succeed.
