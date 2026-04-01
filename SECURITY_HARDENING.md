# Queen Califia CyberAI — Security Hardening Guide

## For Bug Bounty, TryHackMe, HackTheBox & Contracted Assessments

---

## Pre-Deployment Checklist

### 0. Choose Your Auth Mode Explicitly

There are two supported deployment postures:

1. **Dashboard convenience mode**
   - `QC_NO_AUTH=1`
   - Best for the current public dashboard UX (GCS static site or legacy Firebase)
   - Keep `QC_MEMORY_EXPORT_TOKEN` set so memory backup/export remains protected

2. **Strict API mode**
   - `QC_NO_AUTH=0`
   - Set API/admin keys and update the frontend to send them
   - Recommended when the API is not intentionally public-facing

Current checked-in `render.yaml` uses **dashboard convenience mode**. Do not assume API-key enforcement is active unless you explicitly switch it on.

### 0.5 Production Secret Baseline

```bash
export QC_PRODUCTION=1
export QC_API_KEY_PEPPER=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export QC_AUDIT_HMAC_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export QC_MEMORY_EXPORT_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
```

If `QC_PRODUCTION=1`, the gateway expects strong pepper/HMAC secrets to be configured.

### 1. Authorization Guardrail (`QC_REQUIRE_AUTHZ_ACK`)
Every scan endpoint requires explicit `acknowledge_authorized: true`. This is **enabled by default**.

```bash
# KEEP THIS ON in production (default)
export QC_REQUIRE_AUTHZ_ACK=1

# Only disable for automated pipelines with explicit scoping
export QC_REQUIRE_AUTHZ_ACK=0
```

**Protected endpoints:**
- `POST /api/vulns/scan`
- `POST /api/vulns/webapp`
- `POST /api/v1/scanner/scan`
- `POST /api/v1/one-click/scan-and-fix`

### 2. API Key Authentication
```bash
# Generate a strong key
export QC_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")

# Store in keys.json with pepper
export QC_API_KEY_PEPPER=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

If you intentionally run `QC_NO_AUTH=1`, API keys are bypassed for normal dashboard routes. Keep memory backup/export protected with `QC_MEMORY_EXPORT_TOKEN`.

### 3. Target Allowlisting
```bash
# ONLY allow scanning specific ranges
export QC_SCAN_ALLOWLIST="10.10.10.0/24,192.168.1.0/24"

# Public targets are DENIED by default
export QC_DENY_PUBLIC_TARGETS=1
```

### 4. Rate Limiting
```bash
export QC_RATE_LIMIT=60          # Requests per minute
export QC_MAX_SCANS=5            # Max concurrent scans
export QC_SCAN_THREADS=20        # Threads per scan
```

### 5. Audit Logging
```bash
export QC_AUDIT_LOG_FILE=/var/log/qc/audit.jsonl
export QC_AUDIT_HMAC_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

### 6. Persistent Memory Storage
```bash
export QC_DB_PATH=/var/data/queen.db
export QC_EVOLUTION_DB=/var/data/qc_evolution.db
export QC_MEMORY_BACKUP_DIR=/var/data/memory-backups
```

For Render, attach a persistent disk at `/var/data` before using production memory or backup workflows.

---

## Bug Bounty Configuration

```bash
# .env for bug bounty engagement
QC_REQUIRE_AUTHZ_ACK=1
QC_SCAN_ALLOWLIST=10.10.10.0/24     # Only the target scope
QC_DENY_PUBLIC_TARGETS=1
QC_RATE_LIMIT=30
QC_MAX_SCANS=3
QC_SCAN_THREADS=10                    # Gentle threading
```

### One-Command Engagement
```bash
# Scan the target scope
python cli.py go 10.10.10.0/24

# With auto-remediation planning (does NOT execute)
python cli.py go 10.10.10.5 --mode full

# Export findings
python cli.py findings --severity CRITICAL > findings.txt
```

---

## TryHackMe / HackTheBox Configuration

```bash
# .env for CTF platforms
QC_SCAN_ALLOWLIST=10.10.10.0/8       # THM/HTB ranges
QC_DENY_PUBLIC_TARGETS=1
QC_REQUIRE_AUTHZ_ACK=1
```

### Quick Workflow
```bash
# Step 1: Quick scan the box
python cli.py scan 10.10.10.42 --mode full

# Step 2: Check findings
python cli.py findings

# Step 3: Get remediation hints (shows attack surface)
python cli.py remediate

# Step 4: Quantum assessment
python cli.py quantum

# Step 5: Check what QC learned
python cli.py evolution intel
```

---

## Defense-In-Depth Architecture

### Input Validation
- `InputSanitizer` blocks XSS, SQL injection, SSRF, and command injection patterns
- All string inputs are length-limited (10,000 chars max)
- JSON bodies are recursively sanitized
- Target addresses validated against CIDR allowlist

### Authentication
- API keys are pepper-hashed (SHA-256 + per-deployment pepper)
- HMAC-signed audit logs (tamper-evident)
- Memory export/backup endpoints can be separately protected with `QC_MEMORY_EXPORT_TOKEN`
- Ed25519 crypto approvals for high-risk operations apply only if the optional sovereignty module is present
- Dual-approval for destructive actions in production

### Network Safety
- Public IPs denied by default
- RFC 1918 only unless explicitly allowlisted
- Rate limiting per-endpoint and per-role
- Scan semaphore prevents thread exhaustion

### Audit Trail
- Append-only JSONL with hash chaining
- HMAC integrity verification
- Every scan, login, and API call logged
- Immutable evidence chain for incidents

---

## Testing the Hardening

```bash
# Run security-specific tests
python -m pytest tests/test_authz_ack.py -v

# Run the full suite
python -m pytest tests/ -v

# Check for common vulnerabilities
# 1. Authorization bypass
curl -X POST http://localhost:5000/api/vulns/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1"}'
# Expected: 400 authorization_ack_required

# 2. Public IP rejection
curl -X POST http://localhost:5000/api/vulns/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "8.8.8.8", "acknowledge_authorized": true}'
# Expected: 400 Target denied

# 3. XSS rejection
curl -X POST http://localhost:5000/api/vulns/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "<script>alert(1)</script>", "acknowledge_authorized": true}'
# Expected: 500 (sanitizer blocks prohibited pattern)

# 4. Rate limiting
for i in $(seq 1 200); do
  curl -s -o /dev/null -w "%{http_code}\n" http://localhost:5000/api/health
done
# Expected: 429 after limit exceeded

# 5. Memory backup protection
curl http://localhost:5000/api/v1/evolution/storage
# Expected: 403 unless X-QC-Memory-Token or admin auth is provided
```

---

## Responsible Use

Queen Califia is designed for **authorized security assessments only**.

- Always have written authorization before scanning
- Respect scope boundaries
- Follow responsible disclosure for any findings
- Log and document all activities
- The `acknowledge_authorized` guardrail is a legal protection — use it
