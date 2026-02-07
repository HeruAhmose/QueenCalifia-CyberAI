# Queen Califia Quantum CyberAI

![SOC Dashboard Preview](docs/images/dashboard.svg)

## Quick start (local)
```bash
cp .env.example .env
docker compose up --build
```

### Observability (local)
- Jaeger UI: `http://localhost:16686`
- Tempo: `http://localhost:3200`
- Collector writes traces to: `./data/otel/traces.jsonl`

### Metrics (Prometheus + Grafana)
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000` (defaults: `admin` / `admin` — override via `GRAFANA_ADMIN_PASSWORD`)
- API metrics endpoint: `GET /metrics` (Bearer token required when `QC_PRODUCTION=1`):
  - set `QC_METRICS_TOKEN` in `.env` (also used by Prometheus scrape config)

Included dashboards:
- **QueenCalifia API KPIs** (RPS, p95, status mix)
- **Rate Limit & Budget** (429/s by scope, budget cost by route)

### Incident evidence
Evidence artifacts are first-class:
- List: `GET /api/incidents/<id>/evidence`
- Add: `POST /api/incidents/<id>/evidence`
- Get: `GET /api/incidents/<id>/evidence/<evidence_id>`
- Tombstone: `DELETE /api/incidents/<id>/evidence/<evidence_id>` (admin)

The dashboard incident drill-down includes an **Evidence artifacts** panel (with Export JSON).


Tail-sampling (collector):
- keep **ERROR** traces
- keep traces slower than `QC_OTEL_LATENCY_THRESHOLD_MS`
- otherwise sample `QC_OTEL_SAMPLING_PERCENTAGE%`

### Load test
```bash
export QC_SCAN_DRY_RUN=1
export QC_K6_VUS=25
export QC_K6_DURATION=60s
export QC_K6_ENABLE_SCAN=1
export QC_LOADTEST_API_KEY="<your_api_key>"   # optional

docker compose --profile loadtest run --rm k6
```

Reports are written to:
- `./data/loadtest/summary.json`
- `./data/loadtest/summary.txt`

### Frontend (premium SOC UI)
- `frontend/QueenCalifia_v2_Perfected.jsx`
  - persists only `QC_API_BASE`, `QC_POLL_MS`, `QC_UI_DENSITY`
  - keeps API key **in-memory only**

---

## Defense-Grade Cybersecurity Intelligence Platform

> *Biomimetic self-healing security architecture that analyzes, corrects, and deters vulnerabilities in real-time.*

Queen Califia is a cybersecurity AI platform built on biomimetic architecture — spider web threat correlation, mycelium distributed intelligence, and Tamerian hardened processing circuits. It provides real-time threat detection, vulnerability analysis, and automated incident response at defense-grade security standards.

---

## Architecture

```
Queen Califia Quantum CyberAI
├── 🕷️  Tamerian Security Mesh (core/tamerian_mesh.py)
│   ├── Hub Nodes (4) — Network, Endpoint, Identity, Data security
│   ├── Radial Nodes (12) — Detection pipelines per domain
│   ├── Spiral Nodes (8) — Cross-domain attack chain correlation
│   ├── Tamerian Circuits (6) — Hardened processing with integrity checks
│   ├── 15+ Signature Rules — MITRE ATT&CK mapped
│   ├── Behavioral Analysis — Baseline deviation detection
│   ├── Anomaly Detection — Statistical Z-score analysis
│   ├── IOC Database — Indicator of Compromise management
│   └── Self-Healing Loop — Automatic node repair & failover
│
├── 🔍 Vulnerability Engine (engines/vulnerability_engine.py)
│   ├── Port Scanning & Service Fingerprinting
│   ├── CVE Knowledge Base — CISA KEV prioritized
│   ├── CVSS Scoring & Risk Calculation
│   ├── Compliance Auditing — CIS, NIST 800-53, PCI DSS, HIPAA
│   ├── Web Application Scanning — OWASP Top 10 checks
│   ├── Attack Surface Mapping
│   └── Automated Remediation Plan Generation
│
├── 🛡️  Incident Response Orchestrator (engines/incident_response.py)
│   ├── NIST SP 800-61 Aligned Lifecycle
│   ├── Automated Playbooks — Ransomware, APT, Breach, Phishing
│   ├── Containment Actions — Block, Isolate, Quarantine, Disable
│   ├── Forensic Evidence Collection — Chain of custody tracking
│   ├── Remediation Workflows — Approval-gated execution
│   └── Post-Incident Review & Metrics (MTTD/MTTC/MTTR)
│
├── 🔒 Hardened API Gateway (api/gateway.py)
│   ├── API Key Authentication with RBAC (admin/analyst/reader)
│   ├── Sliding Window Rate Limiting
│   ├── Input Sanitization — XSS, SQLi, path traversal protection
│   ├── Tamper-Evident Audit Logging (hash-chained)
│   ├── Security Headers (CSP, HSTS, X-Frame-Options, etc.)
│   ├── CORS with restricted origins (not wildcard)
│   └── No error detail leakage
│
└── 📊 SOC Dashboard (React frontend, served separately)
```

## Biomimetic Design Principles

| Biology | Cybersecurity Application |
|---------|--------------------------|
| **Spider Web** | Threat correlation mesh — hub nodes detect, radial threads propagate, spiral threads correlate attack chains across domains |
| **Mycelium** | Distributed IOC propagation — when one node detects a threat indicator, it spreads to all nodes in O(log n) |
| **Self-Healing** | Degraded nodes automatically repair, circuits verify integrity via cryptographic hashes, failover is seamless |
| **Tamerian Circuits** | Hardened processing pipelines with redundant paths, integrity verification, and fault tolerance |

## Quick Start

### Prerequisites
- Python 3.11+
- pip

### Installation

```bash
git clone https://github.com/TamerianMaterials/QueenCalifia-CyberAI.git
cd QueenCalifia-CyberAI
pip install -r requirements.txt
```

### Run (Docker Compose) — recommended (Redis + Celery)

```bash
cp .env.example .env
# edit .env and set real secrets
docker compose up --build
```

- API: http://localhost:5000
- Redis: localhost:6379

### Logging (structured)

Set `QC_LOG_FORMAT=json` (default when `QC_PRODUCTION=1`). HTTP and task logs include:
- `request_id` (propagates from HTTP -> Celery via `X-Request-ID`)
- `principal` (API key hash or ip identity)

### Tests

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest
```

### Run (Development)

```bash
# With authentication disabled (development only)
python app.py --no-auth --debug

# With authentication (production-like)
python app.py --port 5000
```

### Run (Production)

Production requires **non-default secrets** and **API keys**.

Create a `.env` file (see `.env.example`) with at least:

- `QC_API_KEY_PEPPER` (used for hashing API keys)
- `QC_AUDIT_HMAC_KEY` (used for audit log integrity)

Provide an API key store via:

- `QC_API_KEYS_FILE` (path to keys JSON), or
- `QC_API_KEYS_JSON` (JSON string)

#### Docker Compose (recommended)

```bash
# 1) copy env template and fill secrets
cp .env.example .env

# 2) start Redis + API + worker
docker compose up --build
```

> First run will bootstrap `./data/keys.json` if `QC_ALLOW_INSECURE_BOOTSTRAP=1` is set.
> Disable bootstrap and rotate keys immediately after provisioning.

#### Gunicorn

```bash
export QC_PRODUCTION=1
export QC_API_KEY_PEPPER="CHANGE_ME"
export QC_AUDIT_HMAC_KEY="CHANGE_ME_TOO"
export QC_API_KEYS_FILE="keys.json"

gunicorn --bind 0.0.0.0:5000 --workers 2 --threads 4 --timeout 120 "app:app"
```
 4 --timeout 120 "app:app"
```

### Distributed mode (Horizontal Scaling)

To scale across multiple Gunicorn workers/nodes, enable **Redis + Celery**:

```bash
# 1) Start Redis (or use managed Redis)
export QC_REDIS_URL="redis://localhost:6379/0"
export QC_USE_CELERY=1

# 2) API (can run multiple instances)
gunicorn --bind 0.0.0.0:5000 --workers 2 --threads 4 --timeout 120 "app:app"

# 3) Celery worker(s) for vulnerability scans
celery -A celery_app.celery_app worker -l INFO --concurrency 4 -Q scans
```

Docker Compose is included for convenience:

```bash
docker compose up --build
```

## API Reference

All endpoints require `X-QC-API-Key` header (except `/api/health`).

### Health Check
```
GET /api/health
→ {"status": "operational", "system": "Queen Califia CyberAI", "version": "1.0.0"}
```

### Dashboard (Aggregated SOC View)
```
GET /api/dashboard
→ Mesh status, vulnerability summary, incident metrics — all in one call
```

### Threat Detection

```
POST /api/events/ingest          # Ingest security event for real-time analysis
GET  /api/threats/active          # Active attack chains and threat posture
GET  /api/mesh/status             # Full mesh topology and health
```

### IOC Management

```
GET  /api/iocs                    # List active indicators of compromise
POST /api/iocs                    # Add single IOC
POST /api/iocs/bulk               # Bulk import from threat intel feed
```

### Vulnerability Scanning

```
POST /api/vulns/scan              # Start vulnerability scan (target required)
POST /api/vulns/webapp            # Web application security scan
GET  /api/vulns/status            # Vulnerability engine status
GET  /api/vulns/remediation       # Prioritized remediation plan
```

### Incident Response

```
GET  /api/incidents               # List all incidents
POST /api/incidents               # Create new incident (triggers playbook)
GET  /api/incidents/<id>          # Full incident report with timeline
POST /api/incidents/<id>/approve/<action_id>  # Approve pending response action
GET  /api/ir/status               # IR orchestrator status and metrics
```

### Audit (Admin Only)

```
GET /api/audit/log                # Tamper-evident audit log
GET /api/audit/integrity          # Verify audit chain integrity
```

## Security Controls

### What was WRONG with the original codebase:
- ❌ `CORS(app, origins="*")` — Wildcard CORS allowing any origin
- ❌ No authentication on any endpoint
- ❌ No input validation or sanitization
- ❌ Error messages leaking internal stack traces
- ❌ No rate limiting
- ❌ No audit logging
- ❌ No security headers
- ❌ `sys.path.append` with hardcoded sandbox paths
- ❌ No encryption considerations
- ❌ Zero actual cybersecurity capability

### What Queen Califia CyberAI implements:
- ✅ CORS restricted to explicit allowed origins
- ✅ API key authentication with role-based access control
- ✅ Defense-grade input sanitization (XSS, SQLi, path traversal, null bytes)
- ✅ Generic error responses — no internal detail leakage
- ✅ Sliding window rate limiting per client
- ✅ Tamper-evident audit logging with hash chain integrity
- ✅ Full security header suite (CSP, HSTS, X-Frame-Options, etc.)
- ✅ No hardcoded paths or credentials
- ✅ Non-root Docker execution
- ✅ Production WSGI server (gunicorn, not Flask dev server)

## MITRE ATT&CK Coverage

The detection engine maps all alerts to MITRE ATT&CK techniques:

| Tactic | Techniques Covered |
|--------|--------------------|
| Reconnaissance | T1046 (Port Scanning) |
| Initial Access | T1190 (Exploit Public-Facing), T1078 (Valid Accounts), T1566 (Phishing) |
| Execution | T1059 (Command Scripting) |
| Persistence | T1547 (Boot/Logon Autostart), T1053 (Scheduled Tasks) |
| Privilege Escalation | T1068 (Exploitation), T1548 (Abuse Elevation) |
| Defense Evasion | T1070 (Indicator Removal) |
| Credential Access | T1003 (OS Credential Dumping), T1110 (Brute Force) |
| Discovery | T1046 (Network Scanning) |
| Lateral Movement | T1021 (Remote Services) |
| Collection | T1005 (Data from Local System), T1039 (Network Shared Drive) |
| C2 | T1071 (Application Layer Protocol), T1573 (Encrypted Channel) |
| Exfiltration | T1041 (Over C2), T1048 (Alternative Protocol/DNS) |
| Impact | T1486 (Data Encrypted for Impact/Ransomware) |

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `QC_PORT` | 5000 | API port |
| `QC_HOST` | 0.0.0.0 | Bind address |
| `QC_PRODUCTION` | 0 | Enable production hardening |
| `QC_DETECTION_THREADS` | 8 | Parallel detection workers |
| `QC_SCAN_THREADS` | 16 | Parallel scan workers |
| `QC_RATE_LIMIT` | 60 | Requests per minute |
| `QC_CONN_BURST` | 100 | Connection burst threshold |
| `QC_AUTH_FAIL` | 5 | Auth failure threshold |
| `QC_ANOMALY_Z` | 3.0 | Anomaly Z-score threshold |
| `QC_CORS_ORIGINS` | (restricted) | Comma-separated CORS origins |

## License

MIT License — See LICENSE

## Author

**Jon** — Tamerian Materials  
Naval Academy Graduate | Navy Veteran | Cybersecurity Professional

---

*Built with 🕷️ Biomimetic Architecture • 🔬 Tamerian Circuits • 🛡️ Defense-Grade Security*


## Observability (OpenTelemetry → Collector → Jaeger + Tempo + File)

Docker Compose includes:
- **OpenTelemetry Collector** (OTLP ingest)
- **Jaeger** (UI)
- **Tempo** (trace backend)
- Collector writes a local file: `./data/otel/traces.jsonl`

### Enable tracing
- `QC_OTEL_ENABLED=1`
- Set `OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318`
- Optional sampling: `QC_OTEL_SAMPLING_PERCENTAGE=25` (collector-side probabilistic sampler)

Jaeger UI:
- `http://localhost:16686`

Tempo query:
- `http://localhost:3200`

API responses include:
- `X-Request-Id` (correlation)
- `X-Trace-Id` (trace id when tracing enabled)

Celery tasks receive trace context via message headers (W3C `traceparent`).

## Load testing (k6)

A small k6 script is included at `loadtest/k6_qc.js`.

Run it via Docker Compose:

```bash
# optional
export QC_LOADTEST_API_KEY="<api_key>"
export QC_SCAN_DRY_RUN=1
export QC_K6_VUS=25
export QC_K6_DURATION=60s

docker compose --profile loadtest run --rm k6
```


## Prometheus remote_write (optional)

Set `QC_PROM_REMOTE_WRITE_URL` to ship metrics to a remote store. Optionally set `QC_PROM_REMOTE_WRITE_BEARER_TOKEN` (recommended) or basic auth (`QC_PROM_REMOTE_WRITE_BASIC_USER`/`QC_PROM_REMOTE_WRITE_BASIC_PASSWORD`).

## Grafana alert rules (provisioned)

This repo provisions three Grafana-managed alert rules into folder **QueenCalifia**:
- Rate-limit denials spike
- Budget depletion / throttling
- 5xx error-rate SLO burn

Add your contact points / notification policies in Grafana UI (Alerting) as desired.


## Grafana alert notifications (optional)

Set `QC_ALERT_WEBHOOK_URL` in `.env` to provision a default webhook contact point (`qc-webhook`) and a default notification policy routing alerts to it. Optionally set `QC_ALERT_WEBHOOK_BEARER_TOKEN` to send an `Authorization: Bearer …` header. If unset, no contact point/policy is provisioned and Grafana keeps its defaults.


## Grafana webhook smoke test

```bash
export QC_ALERT_WEBHOOK_BEARER_TOKEN="smoke-token"
docker compose --profile smoketest up --build --abort-on-container-exit --exit-code-from grafana-smoketest
```


## Developer workflow

### Common commands

```bash
make test         # backend pytest + frontend vitest
make smoketest    # Grafana webhook provisioned-contact-point smoke test (Docker)
make hooks        # install git hooks (.githooks)
```

### Pre-push hook

After `make hooks`, `git push` runs `make test` automatically.

To also run the Docker-based smoke test before pushing:

```bash
export QC_PREPUSH_SMOKETEST=1
git push
```


### SPKI pin helper

```bash
make spki-pin URL=rediss://redis.internal.example:6380/0 JSON=1
# Optional PEM
make spki-pin URL=rediss://redis.internal.example:6380/0 PEM=1 REDACT=1
```


### SPKI pin runbook wrapper

```bash
chmod +x scripts/spki_pin_runbook.sh
scripts/spki_pin_runbook.sh --url rediss://redis.internal.example:6380/0 --json --out ./data/loadtest/spki_pins.jsonl
```


### SPKI pin runbook (Make target)

```bash
make spki-pin-runbook URL=rediss://redis.internal.example:6380/0 JSON=1 OUT=./data/loadtest/spki_pins.jsonl
# Retry lock timeouts too:
QC_SPKI_RETRY_LOCK_TIMEOUT=1 make spki-pin-runbook URL=rediss://redis.internal.example:6380/0 JSON=1 OUT=./data/loadtest/spki_pins.jsonl
```


Host/port mode:

```bash
make spki-pin-runbook HOST=redis.internal.example PORT=6380 JSON=1 OUT=./data/loadtest/spki_pins.jsonl
```
