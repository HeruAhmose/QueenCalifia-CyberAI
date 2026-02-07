# QueenCalifia CyberAI — Defense Hardening & Scale Notes

## What changed (high impact)
- **RBAC + hashed API keys** (`keys.json` or `QC_API_KEYS_JSON`).
- **Tamper-evident audit log**: append-only JSONL with hash chaining + HMAC (`QC_AUDIT_LOG_FILE`, `QC_AUDIT_HMAC_KEY`).
- **Rate limiting**: Redis-backed sliding-window (horizontal-safe) with optional per-endpoint ceilings + RBAC tier defaults.
- **Global request budgeting**: Redis token-bucket budgeting with per-endpoint cost weights (protects expensive endpoints).
- **Scan safety policy**: deny public targets by default; allowlist CIDRs via `QC_SCAN_ALLOWLIST`.
- **Thread-safety**: core mesh and IOC/baseline/correlation paths guarded with `RLock`.
- **Async vulnerability scans**: queued jobs with global per-minute cap (`QC_MAX_SCANS`).

## Production guidance
- Run behind a reverse proxy (TLS termination, WAF, request size limits).
- Prefer **1 Gunicorn worker** unless you externalize state (Redis/DB).
- Store audit logs on **WORM** storage or forward to SIEM.
- Rotate keys; do not expose admin endpoints to untrusted networks.

## Env vars
- `QC_PRODUCTION=1`
- `QC_ENFORCE_HTTPS=1` (when proxy sets `X-Forwarded-Proto`)
- `QC_API_KEYS_FILE=keys.json` (or `QC_API_KEYS_JSON='{"keys":[...]}'`)
- `QC_API_KEY_PEPPER=...` (secret)
- `QC_AUDIT_HMAC_KEY=...` (secret)
- `QC_AUDIT_LOG_FILE=/var/log/qc/audit.jsonl`
- `QC_SCAN_ALLOWLIST=10.0.0.0/8,192.168.0.0/16`
- `QC_DENY_PUBLIC_TARGETS=1`
- `QC_REDIS_URL=redis://host:6379/0`
- `QC_FORCE_REDIS_RATE_LIMIT=1` (optional hard fail)
- `QC_ROLE_RATE_LIMITS_JSON='{...}'` (RBAC tier defaults)
- `QC_RATE_LIMIT_ENDPOINTS_JSON='{...}'` (per-endpoint ceilings)

## Key provisioning
Create keys via admin endpoint (requires an existing admin key) or generate offline by writing `keys.json` with SHA-256 hashes (see `api/gateway.py` for format).


## Global request budgeting (token bucket)

Env:
- `QC_BUDGET_ENABLED=1`
- `QC_BUDGET_ROLE_BUCKETS_JSON` (role → `{capacity, refill_per_minute}`)
- `QC_BUDGET_ENDPOINT_COSTS_JSON` (endpoint → cost)
- `QC_BUDGET_DEFAULT_CAPACITY`, `QC_BUDGET_DEFAULT_REFILL_PER_MINUTE`
- `QC_FORCE_REDIS_BUDGET=1` (fail closed if Redis unavailable)

Response headers:
- `X-Budget-Capacity`, `X-Budget-Remaining`, `X-Budget-Cost`, `X-Budget-Refill-Per-Second`
