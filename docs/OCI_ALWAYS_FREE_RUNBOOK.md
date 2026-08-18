# OCI Always Free Production-Candidate Runbook

This profile is the preferred **production candidate** for replacing the suspended Render workspace. It is not authorized production by default, and it does not declare any historical Render source migrated, absent, or disposable.

## Architecture boundary

OCI is **compute/edge only**:

- exactly one API container;
- exactly one Celery worker;
- frontend container;
- Caddy TLS edge.

Authoritative state is external:

- PostgreSQL: isolated Neon project `QueenCalifia-CyberAI`, PostgreSQL 18;
- application traffic: Neon pooled endpoint with `sslmode=require`;
- migrations, `pg_dump`, and evidence: Neon direct endpoint with `sslmode=require`;
- Celery broker/result backend: one external Redis-compatible TLS authority using `rediss://` with `ssl_cert_reqs=required`.

The OCI production compose file must not start local PostgreSQL or Redis services. A successful VM deployment without verified external authorities is not a valid production runtime.

## Safety state

- OCI host provisioning is currently unverified until provider-backed instance identity exists.
- external queue provisioning/authority is currently unverified until provider-backed evidence exists.
- `OCI_RUNTIME_AUTHORIZED` is absent by default.
- API and worker remain exactly one instance each; no HA/autoscaling is authorized.
- read-only-rootfs and legacy-storage retirement remain future gates.
- historical Render `backend/data/qc_scans.db` remains `unrecoverable-unverified`, never `verified-absent`.
- `render.yaml` and retained evidence remain preserved.

## 1. Provision a real OCI host

Use a fresh supported Ubuntu image on a production-eligible OCI compute resource. Record provider-backed evidence before changing `application_host.provisioned` or `instance_identity_verified` in `config/oci-deployment-state.json`:

- OCI instance OCID;
- tenancy/compartment and region;
- image OCID / immutable image identity;
- shape and architecture;
- public/private IP identity;
- VCN/NSG ingress policy;
- creation timestamp.

Run:

```bash
sudo bash scripts/oci/bootstrap-ubuntu.sh
```

The bootstrap configures Docker, host firewalling, fail2ban, unattended upgrades, sysctl hardening, application state directories, backups, and Caddy state. It deliberately does not create local PostgreSQL or Redis authorities and does not create the runtime authorization marker.

Cloud VCN/NSG rules must independently restrict ingress. UFW is defense in depth, not a substitute for OCI network controls.

## 2. Configure secrets

```bash
cp deploy/oci/.env.oci.example .env.oci
chmod 600 .env.oci
```

Populate secrets locally; never commit `.env.oci`.

Required PostgreSQL values:

- `QC_DATABASE_URL` and `DATABASE_URL`: same Neon pooled URL, `sslmode=require`;
- `QC_DATABASE_DIRECT_URL`: direct Neon URL, `sslmode=require`, no `-pooler` hostname;
- `QC_OCI_POSTGRES_PROVIDER=neon`;
- `QC_DATABASE_CONNECTION_MODE=pooled`.

Required queue values:

- `QC_REDIS_URL`;
- `QC_CELERY_BROKER_URL`;
- `QC_CELERY_RESULT_BACKEND`.

All three queue values must be exactly identical and use `rediss://...?ssl_cert_reqs=required`.

## 3. Provision and verify TLS queue authority

Provision the external Redis-compatible service using the provider control plane. The repository currently records Aiven Valkey as the preferred free service, but free-tier availability or a successful connection must not be represented as an SLA.

Before `queue.service_provisioned` or `queue.authority_verified` can become true, retain provider-backed evidence for:

- service identity/project;
- region;
- TLS endpoint identity without committing credentials;
- TLS certificate verification success;
- authenticated `PING`/write/read/delete probe;
- Celery task completion using the exact configured broker/result URL.

Do not expose the queue publicly beyond provider-required network behavior and credentials.

## 4. Historical source disposition

Process only authentic recovered artifacts with the existing migration/disposition tooling. The suspended Render source formerly expected at:

`/opt/render/project/src/backend/data/qc_scans.db`

was not captured before suspension. Its status remains **unrecoverable-unverified**. Do not synthesize an empty source, mark it absent, or use its loss to assert complete migration.

## 5. Migrate to the verified Neon authority

The isolated Neon project is the production database candidate. It was empirically verified empty before migration. Use the direct endpoint for migration and evidence operations where session semantics are required.

Only run the existing migration/disposition tools against authentic source evidence. After migration:

1. generate the whole-database manifest;
2. verify deterministic row counts/digests and sequence state;
3. retain the migration/disposition evidence;
4. keep `production_migration_verified=false` until the real production run succeeds.

CI migration tests are contract evidence, not production migration evidence.

## 6. Encrypted backup and independent restore

Back up the real Neon authority through its direct TLS endpoint:

```bash
export QC_DATABASE_DIRECT_URL='postgresql://...direct...?sslmode=require'
export QC_BACKUP_AGE_RECIPIENTS_FILE=/root/qc-backup-recipients.txt
scripts/oci/backup-postgres.sh
```

The script uses a pinned PostgreSQL 18 client container and streams the custom-format dump directly into `age`; it does not write a plaintext dump.

Create a separate Neon verification branch/database and provide its **direct** URL:

```bash
export QC_BACKUP_AGE_IDENTITY_FILE=/root/qc-backup-age-key.txt
export QC_RESTORE_DATABASE_URL='postgresql://...separate-direct-target...?sslmode=require'
scripts/oci/restore-postgres.sh /srv/queen-califia/backups/queen-<timestamp>.dump.age
```

The restore target must have zero public base tables and must not equal the live authority unless an explicit emergency override is supplied. After restore, run the repository whole-database manifest verifier and require equality with the source manifest before marking production backup/restore verified.

## 7. Runtime authorization

Do **not** create the authorization marker until all of these are evidenced:

- provider-backed OCI host identity and network policy;
- external TLS queue provisioned and authority probe successful;
- authentic production migration/disposition complete for all recoverable sources;
- whole-database manifest generated;
- encrypted `pg_dump` completed from the direct production endpoint;
- independent restore completed and manifest equality proven;
- PostgreSQL and Celery authority probes pass;
- legacy production writers are disabled.

Only then:

```bash
sudo install -d -m 0750 -o 10001 -g 10001 /srv/queen-califia/app/cutover
printf 'AUTHORIZED\n' | sudo tee /srv/queen-califia/app/cutover/OCI_RUNTIME_AUTHORIZED >/dev/null
sudo chown 10001:10001 /srv/queen-califia/app/cutover/OCI_RUNTIME_AUTHORIZED
sudo chmod 0440 /srv/queen-califia/app/cutover/OCI_RUNTIME_AUTHORIZED
```

At container startup, `scripts/oci/validate-runtime-env.py` then independently refuses non-TLS PostgreSQL, non-pooled Neon application URLs, plaintext Redis, weak Redis certificate verification, or divergent Celery broker/result URLs.

## 8. Start and validate runtime

```bash
set -a
. ./.env.oci
set +a
docker compose -f deploy/oci/docker-compose.oci.yml --profile runtime up -d --build
```

Expected OCI containers: API, worker, frontend, Caddy. PostgreSQL and queue services remain external.

Validate and retain evidence for:

- HTTPS and certificate chain;
- `/healthz` and `/readyz`;
- authenticated API behavior;
- PostgreSQL writes/reads against Neon;
- Celery task dispatch/completion through the TLS queue;
- scanner writes;
- API and worker restart persistence;
- full compose stop/start persistence;
- host reboot persistence;
- immutable Git SHA and OCI instance/image identities.

Do not route production frontend traffic until those probes pass.

## Completion gates that remain false

Until their existing evidence contracts are satisfied, keep these false:

- `production_cutover_complete`;
- `runtime_authorized`;
- `ha_authorized`;
- `read_only_root_filesystem_authorized`;
- `legacy_storage_retirement_authorized`;
- #72 `backup_restore_tested` / `rolling_update_tested` / multi-replica gates.

## Rollback

If validation fails:

```bash
docker compose -f deploy/oci/docker-compose.oci.yml --profile runtime stop caddy frontend worker api
```

Remove or invalidate the authorization marker if necessary. Preserve Neon state, queue evidence, encrypted backups, restored verification state, historical artifacts, and all cutover evidence while investigating.
