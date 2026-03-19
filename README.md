# Queen Califia CyberAI — QC OS

**Sovereign agent platform for cybersecurity, market intelligence, forecasting, and adaptive operator workflows**

Version 4.3 | Tamerian Materials | Proprietary

---

## Production Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                    FIREBASE HOSTING (Frontend)                   │
│  Vite/React dashboard · cinematic intro · QC avatar states       │
│  Cyber Guardian │ Research Companion │ Quant Lab (expert mode)   │
└───────────────────────────┬─────────────────────────────────────┘
                            │ HTTPS
┌───────────────────────────▼─────────────────────────────────────┐
│                    RENDER (Backend — Flask)                      │
│                                                                  │
│  /api/chat/          Conversation + memory routing               │
│  /api/market/        Market intelligence                         │
│  /api/forecast/      Forecast and portfolio lab                  │
│  /api/identity/      Identity Core                               │
│  /api/vulns/*        Real scan/remediation workflows             │
│  /api/v1/evolution/* Adaptive learning / memory / backups        │
│  /healthz            Health check                                │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    QC CORE                                │    │
│  │  Conversation Engine · Memory · Tool Routing · Evals      │    │
│  │  Source Provenance · Persona Switching · Audit Log         │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │   MARKET      │  │  FORECAST    │  │  QUANTUM WORKER      │  │
│  │  Intelligence │  │  & Portfolio │  │  (optional)           │  │
│  │               │  │  Lab         │  │                       │  │
│  │  SEC EDGAR    │  │  Regime Det  │  │  Qiskit / Braket     │  │
│  │  FRED API     │  │  Scenarios   │  │  Portfolio Opt        │  │
│  │  ECB Data     │  │  Signal Ens  │  │  Feature Selection    │  │
│  │  Coinbase     │  │  Risk Budget │  │  Regime Clustering    │  │
│  │  Kraken       │  │  Paper Trade │  │                       │  │
│  │  Nasdaq       │  │  Alerting    │  │  Never sole decision  │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                 PERSISTENT STORAGE (/var/data)              │    │
│  │  queen.db              Main QC OS application data          │    │
│  │  qc_evolution.db       Evolution / learned memory state     │    │
│  │  memory-backups/       Point-in-time memory snapshots       │    │
│  │  keys.json             API key store                        │    │
│  │  audit.log.jsonl       Tamper-evident gateway audit log     │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Runtime Model

- Frontend is served from Firebase Hosting.
- The production API runs on Render using `backend/app.py`, which loads the root security gateway app and mounts the dashboard blueprints.
- Persistent memory/state is stored on a Render disk mounted at `/var/data`.
- The evolution engine uses `QC_EVOLUTION_DB=/var/data/qc_evolution.db`.
- Memory snapshots use `QC_MEMORY_BACKUP_DIR=/var/data/memory-backups`.
- Identity Core persistence is centralized through `backend/modules/identity/store.py`, which maps the v4.3 build-plan storage contract onto the stabilized runtime schema.

## License And Provenance

- This repository is now governed by the proprietary `LICENSE` in the repo root, not Apache 2.0.
- Queen Califia CyberAI source in this repository is intended to be original repo-owned implementation unless a file explicitly states otherwise.
- Third-party software is used as dependencies and hosted services, not as copied external repository source, unless separately documented.
- Dependency attribution guidance lives in `THIRD_PARTY_NOTICES.md`.

## Authentication Model

- The current dashboard-oriented Render profile uses `QC_NO_AUTH=1` so the public UI can call the API without manually entering an API key.
- Sensitive memory export/backup operations are separately protected by `QC_MEMORY_EXPORT_TOKEN`.
- If you want stricter API auth, set `QC_NO_AUTH=0`, configure API/admin keys, and update the frontend to send the appropriate headers.
- For production, also set:
  - `QC_PRODUCTION=1`
  - `QC_API_KEY_PEPPER`
  - `QC_AUDIT_HMAC_KEY`
  - `QC_MEMORY_EXPORT_TOKEN`

## Three Personas

| Persona | Visibility | Purpose |
|---------|-----------|---------|
| Cyber Guardian | Public | Threat analysis, vulnerability assessment, security architecture |
| Research Companion | Public | Market data, economic indicators, company filings analysis |
| Quant Lab | Internal (admin) | Experiments, signal ensembles, paper trading, quantum research |

## Trusted Source Policy

QC does NOT browse random web pages. All market data comes from a whitelist:

| Source | Type | Confidence | API |
|--------|------|-----------|-----|
| SEC EDGAR | Filings & disclosures | 99% | data.sec.gov (public JSON) |
| FRED API | Macro & economic series | 98% | api.stlouisfed.org (key required) |
| ECB Data Portal | FX reference rates | 97% | data-api.ecb.europa.eu |
| Coinbase Exchange | Crypto market data | 93% | api.exchange.coinbase.com |
| Kraken | Crypto market data | 92% | api.kraken.com |
| Nasdaq Data Link | Market datasets | 96% | data.nasdaq.com (key required) |

Every fetched datum is stamped with source + timestamp + SHA-256 hash.

## LLM Evolution Path

| Stage | Description | Status |
|-------|-------------|--------|
| Stage 1 | Local symbolic core with memory, persona switching, and intent detection | **Current** |
| Stage 2 | Plug self-hosted open-weight model (Llama/Mistral) via QC_LLM_URL | Ready to wire |
| Stage 3 | Fine-tune on domain conversations, telemetry, eval failures, research notes | Planned |
| Stage 4 | Specialized heads/modules for cyber, finance, portfolio research | Planned |

## Auto-Update Policy

"Auto-update" does NOT mean uncontrolled self-editing. It means:

1. Fetch newest data from approved sources only
2. Stamp each datum with source + time + hash
3. Recompute signals
4. Compare against prior model/eval baseline
5. Only promote if it beats baseline AND passes risk checks
6. Admin approval required for signal promotion

## Quantum-Capable (Honest Definition)

"Quantum-capable" means pluggable hybrid quantum/classical research workers:

- Qiskit (IBM Quantum) for quantum workflow development
- Amazon Braket for managed hybrid jobs and simulators
- Used for: portfolio optimization experiments, combinatorial search, feature selection, regime clustering
- **Never the sole decision engine**

## What This Is NOT

- NOT a live trading engine
- NOT a guaranteed prediction system
- NOT an uncontrolled self-modifying AI
- NOT investment advice (research and analysis only)

## Local Development

```bash
# Backend
cd backend
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your API keys / local paths
gunicorn app:app --bind 0.0.0.0:5000

# Frontend (new terminal)
cd frontend
npm install
npm run dev
```

## Validation

```bash
# Frontend production build
cd frontend && npm run build && cd ..

# Backend test suite
python -m pytest -q
```

Notes:

- The repository includes the `sovereignty/` package restored from internal repository history.
- Playwright smoke tests are optional and require a running app plus Playwright installed.

## Deploy

```bash
# Backend → Render (uses render.yaml and persistent disk)
# Frontend → Firebase Hosting
cd frontend && npm run build && cd ..
firebase deploy --only hosting
```

Render requirements before redeploy:

- Attach a disk at `/var/data`
- Provision the Render Key Value instance from `render.yaml` and let both the web service and worker attach to it via `QC_REDIS_URL`
- Run the Render background worker from `render.yaml` so async vulnerability scans execute through Celery instead of in-process memory
- Set `QC_PRODUCTION=1`
- Set `QC_API_KEY_PEPPER`
- Set `QC_AUDIT_HMAC_KEY`
- Set `QC_MEMORY_EXPORT_TOKEN`
- Set `FRED_API_KEY` if you want live FRED macro coverage to show as configured
- Set `NASDAQ_API_KEY` if you want Nasdaq Data Link coverage to show as configured
- `render.yaml` now enables the shared Redis/Celery async scan path and marks Redis as required in `/readyz`
- If a Blueprint update does not auto-create the worker or Key Value instance in your workspace, create them once in Render with the same names and env wiring shown in `render.yaml`

## Post-Deploy Smoke Check

Use the repeatable smoke script to validate that the live dashboard shell, route mounting, identity core, market providers, and vuln guardrails are all aligned with production:

```bash
python scripts/live_smoke.py
python scripts/live_smoke.py --require-fred --require-nasdaq
python scripts/live_smoke.py --browser
```

Notes:

- `--require-fred` and `--require-nasdaq` turn missing production provider keys into hard failures.
- `--browser` performs a Playwright click-through of the live intro flow: `CLICK TO AWAKEN` -> `ENTER COMMAND` -> dashboard render.
- If Playwright is not installed locally, use:

```bash
python -m pip install playwright
python -m playwright install chromium
```

## Key API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /healthz | None | Health check |
| GET | /api/config | None | Public config |
| POST | /api/chat/ | Public in current Render profile; API key in strict mode | Conversation |
| GET | /api/market/sources | Public in current Render profile; API key in strict mode | Source status |
| GET | /api/identity/state | Public in current Render profile; API key in strict mode | Identity overview |
| POST | /api/forecast/run | Public in current Render profile; API key in strict mode | Forecast run |
| POST | /api/vulns/scan | Public in current Render profile; authz acknowledgement required | Queue vulnerability scan |
| POST | /api/v1/one-click/scan-and-fix | Public in current Render profile; authz acknowledgement required | Scan + remediate workflow |
| GET | /api/v1/evolution/status | Public in current Render profile | Evolution engine status |
| GET | /api/v1/evolution/storage | `X-QC-Memory-Token` or admin principal | Memory storage status |
| GET | /api/v1/evolution/backups | `X-QC-Memory-Token` or admin principal | List memory backups |
| POST | /api/v1/evolution/backup | `X-QC-Memory-Token` or admin principal | Create memory backup |

---

*Queen Califia CyberAI — Designed and built by Jonathan Peoples at Tamerian Materials*
*Proprietary · github.com/HeruAhmose/QueenCalifia-CyberAI*
