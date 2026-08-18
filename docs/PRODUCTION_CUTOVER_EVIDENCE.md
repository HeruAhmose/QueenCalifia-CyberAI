# Production cutover evidence runbook

This runbook is the evidence gate between the current single-writer SQLite/file-backed deployment and a future PostgreSQL/Celery production cutover.

It does **not** authorize multi-replica API operation, read-only root filesystems, or deletion of legacy state. It deliberately preserves the old sources until a separate storage-removal review is approved.

## Non-negotiable safety boundary

The legacy live-scanner database is container-local at:

`/opt/render/project/src/backend/data/qc_scans.db`

It is **not** on the `/var/data` PVC. Capture it from the existing API pod before any action that can replace, restart, evict, reschedule, scale down, or delete that pod. A deployment rollout before this capture can permanently destroy historical live-scanner state.

The `/var/data` PVC remains attached throughout this evidence gate.

## Required operator prerequisites

- A declared maintenance window in which mutating traffic is quiesced without deleting the existing API pod.
- `kubectl` authenticated to the intended production cluster and namespace.
- An empty PostgreSQL production target intended to become the new authority.
- A second, separate empty PostgreSQL database for restore verification.
- PostgreSQL 16 `pg_dump` and `pg_restore` clients.
- `QC_AUDIT_HMAC_KEY` available to the operator only for audit-chain verification. Never place it in an evidence file or shell transcript.
- A secure operator workstation. `.cutover-staging/` is git-ignored but still contains sensitive operational state and must be access-controlled and securely removed only after the retention decision.

Do not put database URLs, passwords, API keys, bearer tokens, private keys, or HMAC keys into the evidence bundle.

## Phase 0 — identify and freeze without replacing the source pod

Record the namespace, current API pod name, pod UID, and immutable image digest. Confirm there is exactly one API writer.

Example inspection commands (replace namespace only):

```bash
export QC_NAMESPACE='queen-califia-production'
kubectl -n "$QC_NAMESPACE" get deploy qc-api -o wide
kubectl -n "$QC_NAMESPACE" get pods -l app=qc-api -o wide
kubectl -n "$QC_NAMESPACE" get pod "$QC_API_POD" -o jsonpath='{.metadata.uid}{"\n"}{.status.containerStatuses[?(@.name=="api")].imageID}{"\n"}'
```

Quiesce external mutating traffic and asynchronous producers/workers using the production platform's maintenance procedure. **Do not scale `qc-api` to zero and do not trigger a rollout.** The old API container must remain alive until the live-scanner snapshot is outside the pod.

Record how mutation traffic was frozen in the change ticket, not in the secret-free evidence JSON.

## Phase 1 — consistent source capture

Create local staging only on the secured operator workstation:

```bash
install -d -m 0700 .cutover-staging
```

### 1A. Capture SQLite authorities with SQLite's online backup API

Use Python already present in the running API image to make transactionally consistent SQLite snapshots while keeping the pod alive. The snapshot destinations below are temporary files on the existing `/var/data` PVC so they can be copied out safely.

```bash
kubectl -n "$QC_NAMESPACE" exec "$QC_API_POD" -c api -- python - <<'PY'
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
    if not src.exists():
        print(f"ABSENT\t{source}")
        continue
    dst = Path(destination)
    if dst.exists():
        raise SystemExit(f"refusing to overwrite existing capture: {destination}")
    with sqlite3.connect(f"file:{src}?mode=ro", uri=True) as source_db:
        with sqlite3.connect(dst) as target_db:
            source_db.backup(target_db)
    os.chmod(dst, 0o600)
    print(f"CAPTURED\t{source}\t{destination}")
PY
```

Immediately copy the live-scanner snapshot off the pod **before any replacement/restart**:

```bash
kubectl -n "$QC_NAMESPACE" cp \
  "$QC_API_POD:/var/data/cutover-live-scanner.db" \
  .cutover-staging/qc-live-scanner-legacy.db -c api
```

Then copy the other snapshots:

```bash
kubectl -n "$QC_NAMESPACE" cp "$QC_API_POD:/var/data/cutover-primary.db" .cutover-staging/primary.db -c api
kubectl -n "$QC_NAMESPACE" cp "$QC_API_POD:/var/data/cutover-evolution.db" .cutover-staging/evolution.db -c api
kubectl -n "$QC_NAMESPACE" cp "$QC_API_POD:/var/data/cutover-threat-intel.db" .cutover-staging/threat-intel.db -c api
```

The vulnerability disposition command expects its fixed staging filename. Preserve a dedicated copy of the primary snapshot for that archival pass:

```bash
cp --preserve=mode,timestamps .cutover-staging/primary.db .cutover-staging/qc-vulnerability-legacy.db
```

### 1B. Capture file-backed evidence

For each of `QC_API_KEYS_FILE`, `QC_AUDIT_LOG_FILE`, and `QC_SPKI_LOG_FILE`, determine whether the file exists in the frozen source pod. If present, stream/copy it into a secured local capture and record its SHA-256. If absent, record `verified-absent` with a non-secret reason in the final evidence bundle.

Do not create an empty substitute file and claim that as historical evidence.

Example existence check:

```bash
kubectl -n "$QC_NAMESPACE" exec "$QC_API_POD" -c api -- sh -c '
for p in "${QC_API_KEYS_FILE:-/var/data/keys.json}" "${QC_AUDIT_LOG_FILE:-/var/data/audit.log.jsonl}" "${QC_SPKI_LOG_FILE:-/var/data/spki.jsonl}"; do
  if [ -f "$p" ]; then printf "PRESENT\t%s\n" "$p"; else printf "ABSENT\t%s\n" "$p"; fi
done'
```

Hash every local capture with `sha256sum` and retain the hashes in the change record/evidence bundle. Do not commit the captures.

## Phase 2 — migrate into an empty PostgreSQL authority

Verify the target database is empty before migration. The migration/disposition tools also enforce empty target authorities and abort rather than merge unrelated state.

Point `QC_DATABASE_URL` at the production target through the operator's secret mechanism, not a committed file.

Migrate the authoritative runtime SQLite snapshots and capture the emitted manifest:

```bash
python scripts/migrate_runtime_state_to_postgres.py \
  --primary-sqlite .cutover-staging/primary.db \
  --evolution-sqlite .cutover-staging/evolution.db \
  --threat-intel-sqlite .cutover-staging/threat-intel.db \
  --emit-manifest-json > .cutover-staging/runtime-state-manifest.json
```

Run the historical scanner dispositions against the same target:

```bash
python scripts/disposition_legacy_runtime_state.py vulnerability \
  > .cutover-staging/disposition-vulnerability.json
python scripts/disposition_legacy_runtime_state.py live-scanner \
  > .cutover-staging/disposition-live-scanner.json
```

Stream the three captured file artifacts through the stdin-only disposition modes when each source was present:

```bash
python scripts/disposition_legacy_runtime_state.py api-keys \
  < .cutover-staging/keys.json > .cutover-staging/disposition-api-keys.json
python scripts/disposition_legacy_runtime_state.py audit-log \
  < .cutover-staging/audit.log.jsonl > .cutover-staging/disposition-audit-log.json
python scripts/disposition_legacy_runtime_state.py spki \
  < .cutover-staging/spki.jsonl > .cutover-staging/disposition-spki.json
```

If a source was verified absent, do not fabricate a successful disposition result. The production evidence record must preserve that distinction and the operator must confirm the new PostgreSQL authority initializes the corresponding table safely.

## Phase 3 — whole-database source manifest

After all migrations/dispositions complete and before the production target accepts live traffic, generate a secret-free manifest covering **every public PostgreSQL base table**, not only the runtime-migration subset:

```bash
python scripts/postgres_database_manifest.py \
  > .cutover-staging/postgres-source-manifest.json
```

The manifest contains table schema metadata, row counts, and SHA-256 digests only. It does not contain row values or the database URL.

Record its own `database_sha256` in the evidence bundle.

## Phase 4 — real production-data backup and separate restore

Create a custom-format PostgreSQL 16 dump of the production target using a credential mechanism that does not expose the password in evidence files:

```bash
pg_dump --format=custom --no-owner --no-privileges \
  --file=.cutover-staging/production-runtime-state.dump "$QC_DATABASE_URL"
sha256sum .cutover-staging/production-runtime-state.dump
```

Restore it into the **separate empty restore database**, then verify that database against the source whole-database manifest:

```bash
QC_DATABASE_URL="$QC_RESTORE_DATABASE_URL" pg_restore \
  --no-owner --no-privileges --dbname="$QC_RESTORE_DATABASE_URL" \
  .cutover-staging/production-runtime-state.dump

QC_DATABASE_URL="$QC_RESTORE_DATABASE_URL" \
  python scripts/postgres_database_manifest.py --verify-stdin \
  < .cutover-staging/postgres-source-manifest.json
```

A count-only restore check is insufficient. The verifier requires the same complete public-table set, schema metadata, row counts, and deterministic content digests.

## Phase 5 — cut over authority and probe it

Only after Phases 1–4 succeed may a separate deployment change point the **single API replica** at PostgreSQL/Celery/Redis. Keep the old PVC and captured sources retained for rollback/evidence.

Verify, with production probes and logs, all of the following:

1. PostgreSQL is the active API/runtime authority.
2. Celery/Redis is the vulnerability job/result authority.
3. Production composition refuses legacy SQLite/file write authority.
4. The API remains at one replica.
5. The root filesystem remains writable until the later writable-path inventory/rootfs gate.

Do not remove `/var/data`, the PVC, or old environment bindings during this evidence collection PR.

## Phase 6 — build and verify the secret-free evidence bundle

Create a JSON object matching `scripts/verify_production_cutover_evidence.py` with:

- production pod UID and immutable image digest;
- all seven source-artifact capture/verified-absence records;
- verified runtime migration manifest digest;
- all five disposition results where applicable;
- whole-database target manifest digest;
- production dump SHA-256;
- source and restored database-manifest SHA-256 values (they must match);
- post-cutover PostgreSQL/Celery/legacy-write probes;
- explicit confirmation that legacy sources are retained and bindings are **not** yet removed.

Validate it through stdin:

```bash
python scripts/verify_production_cutover_evidence.py \
  < .cutover-staging/production-cutover-evidence.json
```

The verifier returns a canonical `evidence_sha256`. Record that digest in issue #72/change control and store the full secret-free evidence JSON in the approved immutable evidence location.

A successful result means only that legacy binding removal may enter **review**. The verifier always returns `ha_authorized: false`.

## Stop conditions

Abort the cutover and preserve all source state if any of these occur:

- the original API pod was replaced before the live-scanner capture completed;
- a required source cannot be accounted for as captured or explicitly verified absent;
- a SQLite snapshot cannot be opened read-only;
- the target authority is not empty before import;
- migration/disposition verification fails;
- audit predecessor/hash/HMAC validation fails;
- source and restore whole-database manifests differ;
- the restore occurs into the same database as the source;
- production composition can still write a legacy SQLite/file authority;
- any evidence file contains credentials or secret material.

## What comes after this gate

Only after production evidence is independently reviewed should a new PR remove obsolete PVC/file bindings and enumerate every remaining writable path. That later PR must then prove a rolling update with a read-only root filesystem. Multi-replica API/HA remains a separate final gate after those checks succeed.
