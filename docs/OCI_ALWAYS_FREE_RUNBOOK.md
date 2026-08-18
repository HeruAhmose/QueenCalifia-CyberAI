# OCI Always Free Production Runbook

This profile is the replacement production target for a suspended Render workspace. It does **not** declare the old Render data migrated, absent, or disposable.

## Safety state

- `render.yaml` remains in the repository for historical deployment context.
- OCI runtime is **not authorized by default**.
- PostgreSQL 16 and Redis may be staged before application cutover.
- API remains exactly one container; no HA or autoscaling is authorized.
- `readOnlyRootFilesystem` remains a future gate.
- Historical Render `backend/data/qc_scans.db` is recorded as `unrecoverable-unverified`, never `verified-absent`.
- No historical source, Render disk, or legacy binding may be deleted based on this deployment profile.

## Supported compute architectures

`deploy/oci/Dockerfile` and the selected upstream images are intended for both `linux/arm64` and `linux/amd64`. OCI Ampere A1 uses `linux/arm64`; set `QC_PLATFORM=linux/amd64` only when provisioning an x86_64 host.

## Persistent host layout

All writable deployment state is rooted at `${QC_OCI_STATE_ROOT:-/srv/queen-califia}`:

- `postgres/` — PostgreSQL data
- `redis/` — Redis AOF state
- `app/` — application cutover marker and retained legacy evidence
- `backups/` — encrypted PostgreSQL backups
- `caddy/data/`, `caddy/config/` — ACME/TLS state

No OCI production authority depends on `/opt/render/...`.

## 1. Provision the OCI host

Use a fresh supported Ubuntu image. Keep the VM within the account's current Always Free allowance. Configure the OCI VCN/security-list or NSG ingress so only required public ports are exposed; the bootstrap script also configures UFW, but host firewalling is not a substitute for cloud firewall rules.

```bash
sudo bash scripts/oci/bootstrap-ubuntu.sh
```

Do not create `OCI_RUNTIME_AUTHORIZED` during bootstrap.

## 2. Configure secrets

```bash
cp deploy/oci/.env.oci.example .env.oci
chmod 600 .env.oci
```

Populate strong production values. Generate a URL-safe PostgreSQL password, for example:

```bash
openssl rand -hex 32
```

Never commit `.env.oci`, age identities, private keys, database dumps, or historical evidence files.

## 3. Stage state services only

```bash
set -a
. ./.env.oci
set +a
docker compose -f deploy/oci/docker-compose.oci.yml --profile state up -d postgres redis
```

At this point API, worker, frontend, and Caddy remain stopped.

## 4. Historical source disposition

Use the existing migration/disposition tools for every historical artifact actually available. The suspended Render container-local source previously expected at:

`/opt/render/project/src/backend/data/qc_scans.db`

was not captured before suspension. Its evidence status is therefore **unrecoverable-unverified**. Do not synthesize an empty SQLite file, do not mark it absent, and do not use its loss to assert a complete historical migration.

Any Render persistent-disk artifacts recovered later must be hashed, retained, and processed through the existing cutover/disposition contracts before changing their status.

## 5. Verify PostgreSQL migration and backup/restore

Run the repository migration/disposition verifiers appropriate to the recovered sources, then create an encrypted backup. Backups require an age recipients file:

```bash
export QC_BACKUP_AGE_RECIPIENTS_FILE=/root/qc-backup-recipients.txt
scripts/oci/backup-postgres.sh
```

Verify restore into a **separate database**:

```bash
export QC_BACKUP_AGE_IDENTITY_FILE=/root/qc-backup-age-key.txt
export QC_RESTORE_DATABASE=queen_restore_verify
scripts/oci/restore-postgres.sh /srv/queen-califia/backups/queen-<timestamp>.dump.age
```

Do not set `QC_ALLOW_LIVE_DATABASE_RESTORE=1` during routine verification.

## 6. Authorize runtime only after evidence review

The repository intentionally cannot decide this from CI. After migration/disposition, whole-database manifest, encrypted backup, separate restore, and authority probes are reviewed, create the host-local authorization marker:

```bash
sudo install -d -m 0750 -o 10001 -g 10001 /srv/queen-califia/app/cutover
printf 'AUTHORIZED\n' | sudo tee /srv/queen-califia/app/cutover/OCI_RUNTIME_AUTHORIZED >/dev/null
sudo chown 10001:10001 /srv/queen-califia/app/cutover/OCI_RUNTIME_AUTHORIZED
sudo chmod 0440 /srv/queen-califia/app/cutover/OCI_RUNTIME_AUTHORIZED
```

Creating this marker authorizes only the **single-replica OCI runtime**. It does not authorize HA, rootfs read-only conversion, or legacy source deletion.

## 7. Start runtime

```bash
set -a
. ./.env.oci
set +a
docker compose -f deploy/oci/docker-compose.oci.yml --profile runtime up -d --build
```

Expected topology: one API container, one Celery worker, one frontend, Caddy edge, PostgreSQL 16, and Redis. PostgreSQL and Redis are not published on host ports.

## 8. Validate

Verify HTTPS, `/healthz`, `/readyz`, authenticated API behavior, PostgreSQL authority, Celery/Redis task completion, live-scanner PostgreSQL writes, and restart persistence. Record real OCI host/instance/image/git identity in the production evidence record.

Do not change these gates to true until their existing evidence contracts are satisfied:

- `production_cutover_complete`
- `production_backup_restore_tested`
- `legacy_binding_removal_eligible`
- `read_only_root_filesystem_enabled`
- `multi_replica_api_enabled`

## Rollback

If runtime validation fails, stop application services while preserving state:

```bash
docker compose -f deploy/oci/docker-compose.oci.yml --profile runtime stop caddy frontend worker api
```

Do not delete `/srv/queen-califia`, PostgreSQL data, Redis data, backups, recovered Render artifacts, or cutover evidence during rollback.
