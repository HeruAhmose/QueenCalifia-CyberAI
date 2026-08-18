# Managed Free Staging Runbook

This profile is retained for **staging and evaluation only**. Northflank's current Developer Sandbox documentation explicitly says the free tier should not be used for production applications. Therefore this profile must not be treated as the preferred production target or used to close any production cutover gate.

Official provider policy reference (verified 2026-08-18):
- Northflank pricing documentation: https://northflank.com/docs/v1/application/billing/pricing-on-northflank

## Target topology

- Northflank Developer Sandbox: one API service and one Celery worker service, staging/evaluation only.
- Neon: isolated `QueenCalifia-CyberAI` PostgreSQL project, application traffic through the pooled TLS endpoint.
- Aiven Valkey Free: Redis-compatible TLS queue/result backend for Celery. No production SLA is assumed by this profile.
- Existing static frontend hosting remains independent and is not migrated by this profile.

The OCI and Render deployment files remain retained. The OCI profile is the safer current free-tier production candidate because Oracle documents Always Free compute for deploying applications, but it still remains fail-closed until real production evidence is complete.

## Current evidence state

The historical Render live-scanner database formerly expected at `/opt/render/project/src/backend/data/qc_scans.db` remains `unrecoverable-unverified`. It was not captured and was not proven absent before the Render workspace was suspended. Never synthesize an empty replacement or represent this source as migrated/absent.

## 1. Database

Use only the isolated Neon project named `QueenCalifia-CyberAI`. Do not reuse unrelated databases.

Application services must use Neon's pooled endpoint with `sslmode=require` in both `QC_DATABASE_URL` and `DATABASE_URL`. Migration, `pg_dump`, restore verification, and whole-database evidence should use a direct Neon endpoint when session-level behavior is required.

Do not commit the connection URI. Store it only in provider secret storage.

## 2. Queue

For staging, create an Aiven Valkey Free service and obtain its TLS Redis-compatible URI. Configure Celery with `rediss://...` and `ssl_cert_reqs=required`.

Use the exact same TLS URI for:

- `QC_REDIS_URL`
- `QC_CELERY_BROKER_URL`
- `QC_CELERY_RESULT_BACKEND`

The managed runtime gate refuses plaintext `redis://`, certificate verification weaker than `required`, or broker/backend URLs that diverge from `QC_REDIS_URL`.

Do not infer production availability, durability, or SLA guarantees from a successful free-tier staging test.

## 3. Northflank staging services

Create exactly two services from this GitHub repository using `deploy/managed/Dockerfile` only for staging/evaluation.

### API

- service name: `queen-califia-api`
- instances: exactly 1
- internal port: 5000
- public HTTP/S: staging only
- `QC_SERVICE_ROLE=api`
- liveness: `/healthz`
- readiness: `/readyz`

### Worker

- service name: `queen-califia-worker`
- instances: exactly 1
- no public port
- `QC_SERVICE_ROLE=worker`
- command: `celery -A celery_app.celery_app worker -l INFO --concurrency 1 -Q scans`

Do not enable autoscaling or additional replicas while issue #72 remains open.

## 4. Shared non-secret environment

Set:

```text
QC_PRODUCTION=1
QC_USE_CELERY=1
QC_REQUIRE_REDIS=1
QC_MANAGED_RUNTIME_GATE=1
QC_MANAGED_POSTGRES_PROVIDER=neon
QC_DATABASE_CONNECTION_MODE=pooled
QC_ALLOW_INSECURE_BOOTSTRAP=0
QC_DENY_PUBLIC_TARGETS=1
```

Keep `QC_MANAGED_RUNTIME_AUTHORIZED=NOT_AUTHORIZED` unless running an explicitly bounded staging authorization test. A staging authorization is not production authorization and must not change repository production-completion flags.

## 5. Secret environment

Provision provider secrets, never repository variables containing credentials:

- `QC_DATABASE_URL`
- `DATABASE_URL`
- `QC_REDIS_URL`
- `QC_CELERY_BROKER_URL`
- `QC_CELERY_RESULT_BACKEND`
- `QC_API_KEY_PEPPER`
- `QC_AUDIT_HMAC_KEY`
- `QC_METRICS_TOKEN`

Retain any additional application provider keys as secrets.

## 6. Evidence boundary

This profile can validate application compatibility with Neon PostgreSQL 18 and a TLS Redis-compatible Celery queue. It cannot by itself prove production cutover readiness.

Before any real production authorization on a production-eligible host:

1. Inventory every actually recoverable historical source.
2. Run existing SQLite/file migration and disposition tools only against authentic recovered evidence.
3. Verify the real production PostgreSQL target was empty before import where required.
4. Generate the whole PostgreSQL database manifest.
5. Produce a PostgreSQL dump from the real production target.
6. Restore into a separate verification database/branch and require manifest equality.
7. Verify PostgreSQL authority and Celery/queue task completion.
8. Verify legacy production writers are disabled.
9. Preserve the `unrecoverable-unverified` Render scanner status unless provider-backed recovery evidence appears.
10. Run restart/redeploy persistence and health/readiness probes on the actual production host.

CI and staging compatibility evidence are not production-data migration evidence.

## 7. Production routing

Do **not** point the production frontend at the Northflank Developer Sandbox. Use a production-eligible deployment target and keep issue #72 open until all existing completion gates are actually satisfied.

## Rollback

If staging validation fails, set `QC_MANAGED_RUNTIME_AUTHORIZED=NOT_AUTHORIZED` or stop the staging services. Do not delete the Neon project, queue evidence, recovered historical artifacts, manifests, dumps, or evidence while investigating.
