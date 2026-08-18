# Managed Free Deployment Runbook

This is the preferred staged replacement target for the suspended Render deployment. It uses external managed state and deliberately keeps production authorization closed until real cutover evidence is reviewed.

## Target topology

- Northflank Developer Sandbox: one API service and one Celery worker service.
- Neon: isolated `QueenCalifia-CyberAI` PostgreSQL project, application traffic through the pooled TLS endpoint.
- Aiven Valkey Free: Redis-compatible TLS queue/result backend for Celery.
- Existing static frontend hosting remains independent and is not migrated by this profile.

The OCI and Render deployment files are retained as historical/alternative deployment context. This profile does not authorize deleting them.

## Current evidence state

The historical Render live-scanner database formerly expected at `/opt/render/project/src/backend/data/qc_scans.db` remains `unrecoverable-unverified`. It was not captured and was not proven absent before the Render workspace was suspended. Never synthesize an empty replacement or represent this source as migrated/absent.

## 1. Database

Use only the isolated Neon project named `QueenCalifia-CyberAI`. Do not reuse TechBridge or Peoples Portfolio databases.

Application services must use Neon's pooled endpoint with `sslmode=require` in both `QC_DATABASE_URL` and `DATABASE_URL`. Migration, `pg_dump`, restore verification, and whole-database evidence should use a direct Neon endpoint rather than the pooler when the PostgreSQL operation requires session-level behavior.

Do not commit the connection URI. Store it in the application host's secret environment.

## 2. Queue

Create a free Aiven Valkey service and obtain its TLS Redis-compatible URI. Convert/configure the Celery URI as `rediss://...` and append `ssl_cert_reqs=required` if the provider URI does not already carry Celery's TLS verification parameter.

Use the exact same TLS URI for:

- `QC_REDIS_URL`
- `QC_CELERY_BROKER_URL`
- `QC_CELERY_RESULT_BACKEND`

The managed runtime gate refuses plaintext `redis://`, certificate verification weaker than `required`, or broker/backend URLs that diverge from `QC_REDIS_URL`.

Upstash remains protocol-compatible, but its command-metered free tier is not the preferred always-on Celery broker for this profile.

## 3. Northflank services

Create exactly two services from this GitHub repository using `deploy/managed/Dockerfile`.

### API

- service name: `queen-califia-api`
- instances: exactly 1
- internal port: 5000
- public HTTP/S: enabled only after staged validation
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

Keep `QC_MANAGED_RUNTIME_AUTHORIZED=NOT_AUTHORIZED` during staging. The containers are expected to fail closed while this value is not `AUTHORIZED`.

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

Retain any additional LLM/market/provider keys required by application features as secrets.

## 6. Migration and evidence

Before runtime authorization:

1. Inventory every actually recoverable historical source.
2. Run the existing SQLite/file migration and disposition tools only against authentic recovered evidence.
3. Verify the Neon target was empty before import where required by the migration contract.
4. Generate the whole PostgreSQL database manifest.
5. Produce a PostgreSQL dump from the real managed target.
6. Restore into a separate verification database/branch and require manifest equality.
7. Verify PostgreSQL authority and Celery/Valkey task completion.
8. Verify legacy production writers are disabled.
9. Preserve the `unrecoverable-unverified` Render scanner status unless provider-backed recovery evidence appears.

CI compatibility evidence is not production-data migration evidence.

## 7. Authorization

Only after the evidence above is reviewed should both services receive:

```text
QC_MANAGED_RUNTIME_AUTHORIZED=AUTHORIZED
```

That value authorizes only this single-API/single-worker managed runtime. It does not authorize HA, autoscaling, read-only-rootfs conversion, or legacy evidence deletion.

## 8. Cutover

After authorized services pass `/healthz`, `/readyz`, authenticated API behavior, PostgreSQL writes, Celery task completion, scanner writes, and restart/redeploy persistence checks:

- point the existing frontend API configuration to the managed API URL;
- update the explicit CORS allowlist if a new browser origin is introduced;
- record immutable deploy/git/provider identities in the production evidence record;
- keep issue #72 open until all existing completion gates are actually satisfied.

## Rollback

If validation fails, set `QC_MANAGED_RUNTIME_AUTHORIZED=NOT_AUTHORIZED` or stop the application services. Do not delete the Neon project, Valkey service, recovered historical artifacts, manifests, dumps, or evidence while investigating.
