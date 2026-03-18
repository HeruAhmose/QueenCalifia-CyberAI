# Queen Califia CyberAI — QC OS

**Sovereign Agent Platform: Cybersecurity + Market Intelligence + Forecast Lab**

Version 4.2.1 | Tamerian Materials | Proprietary

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    FIREBASE HOSTING (Frontend)                   │
│  React Dashboard · Three-Mode Interface · Feature Flags          │
│  Cyber Guardian │ Research Companion │ Quant Lab (internal)      │
└───────────────────────────┬─────────────────────────────────────┘
                            │ HTTPS
┌───────────────────────────▼─────────────────────────────────────┐
│                    RENDER (Backend — Flask)                       │
│                                                                  │
│  /api/chat/          Conversation Core (LLM + Memory + Tools)    │
│  /api/market/        Trusted Market Intelligence                 │
│  /api/forecast/      Forecast & Portfolio Lab                    │
│  /api/identity/      Identity Core (admin-gated)                 │
│  /healthz            Health Check                                │
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
│  │                    STORAGE (SQLite)                        │    │
│  │  sessions · turns · memories · trusted_sources             │    │
│  │  source_cache · features · forecast_runs                   │    │
│  │  portfolio_scenarios · audit_log · telemetry_events        │    │
│  │  identity_proposals · identity_reflections                 │    │
│  │  identity_persona_rules · identity_self_notes              │    │
│  │  identity_provider · identity_missions                     │    │
│  │  identity_findings · identity_remediation                  │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

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
# Edit .env with your API keys
python app.py

# Frontend (new terminal)
cd frontend
npm install
npm run dev
```

## Deploy

```bash
# Backend → Render (uses render.yaml)
# Frontend → Firebase Hosting
cd frontend && npm run build && cd ..
firebase deploy --only hosting
```

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /healthz | None | Health check |
| GET | /api/config | None | Public config |
| POST | /api/chat/ | API key | Conversation (mode: cyber/research/lab) |
| GET | /api/chat/memories | API key | List user memories |
| GET | /api/market/snapshot | API key | Multi-source snapshot (?asset_type=&symbol=) |
| GET | /api/market/fred/{id} | API key | FRED economic series |
| GET | /api/market/nasdaq/{dataset} | API key | Nasdaq datasets |
| GET | /api/market/sources | API key | List trusted sources + status |
| POST | /api/forecast/run | API key | Run forecast experiment |
| POST | /api/forecast/portfolio/create | API key | Create paper portfolio |
| GET | /api/forecast/portfolio/list | API key | List paper portfolios |
| POST | /api/forecast/portfolio/risk | API key | Risk budget analysis |
| POST | /api/forecast/portfolio/analyze | API key | Detailed portfolio analysis |
| POST | /api/forecast/quant/run | Admin key | Quant optimizer (admin-only) |
| POST | /api/forecast/admin/promote-signal | Admin key | Promote forecast signal |
| GET | /api/identity/state | API key | Persona state overview |
| GET | /api/identity/memory/pending | API key | Pending memory proposals |
| POST | /api/identity/memory/{id}/approve | Admin key | Approve proposal |
| POST | /api/identity/memory/{id}/reject | Admin key | Reject proposal |
| GET | /api/identity/reflections/pending | API key | Pending reflections |
| POST | /api/identity/reflections/{id}/approve | Admin key | Approve reflection |
| POST | /api/identity/reflections/{id}/reject | Admin key | Reject reflection |
| GET | /api/identity/rules/pending | API key | Pending persona rules |
| GET | /api/identity/rules/approved | API key | Approved persona rules |
| POST | /api/identity/rules/{id}/approve | Admin key | Approve rule |
| POST | /api/identity/rules/{id}/reject | Admin key | Reject rule |
| GET | /api/identity/self-notes/pending | API key | Pending self-notes |
| POST | /api/identity/self-notes/{id}/approve | Admin key | Approve self-note |
| POST | /api/identity/self-notes/{id}/reject | Admin key | Reject self-note |
| POST | /api/identity/learning/cycle/run | Admin key | Trigger learning cycle |
| GET | /api/identity/provider-status | API key | Provider status |
| POST | /api/identity/provider-status | Admin key | Switch provider |
| GET | /api/identity/ollama/health | API key | Ollama health check |
| GET | /api/identity/ollama/models | API key | List Ollama models |
| POST | /api/identity/ollama/pull | Admin key | Pull Ollama model |
| POST | /api/identity/missions | Admin key | Create cyber mission |
| GET | /api/identity/missions | API key | List missions |
| GET | /api/identity/missions/{id} | API key | Mission detail |
| POST | /api/identity/missions/{id}/findings | Admin key | Add finding |
| POST | /api/identity/missions/{id}/remediation/generate | Admin key | Generate remediation |
| POST | /api/identity/missions/{id}/remediation/apply | Admin key | Apply remediation |

---

*Queen Califia CyberAI — Designed and built by Jonathan Peoples at Tamerian Materials*
*Proprietary · github.com/HeruAhmose/QueenCalifia-CyberAI*
