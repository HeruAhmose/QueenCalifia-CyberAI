# QC OS v4.3 — Triple-Core Build Plan
## Foundation: v4.2.1 (clean, all 7 bugs fixed)

---

## The Three Cores

```
┌──────────────────────────────────────────────────────────────────────┐
│                         QUEEN CALIFIA CyberAI                        │
│                          Triple-Core Architecture                    │
├──────────────────┬──────────────────────┬───────────────────────────┤
│   CYBER CORE     │   IDENTITY CORE      │   MARKETS CORE            │
│   (existing)     │   (v4.3 — new)       │   (v4.2.1 — working)      │
│                  │                      │                           │
│   13 Engines     │   Memory Proposals   │   SEC EDGAR (live)        │
│   SOC Dashboard  │   Reflections        │   FRED API (live)         │
│   Scan Mode      │   Persona Rules      │   ECB FX (live)           │
│   Remediation    │   Self-Notes         │   Coinbase (live)         │
│   Incidents      │   Provider Manager   │   Kraken (live)           │
│   Vuln Engine    │   Learning Cycle     │   Nasdaq (live)           │
│   Zero-Day Pred  │   Biomimetic Loop    │   Portfolio Lab           │
│   Security Mesh  │   Cyber Memory Lane  │   Forecast Lab            │
│   Telemetry      │   Market Memory Lane │   Regime Detection        │
│   Rate Limiting  │   Persona Memory     │   Paper Trading           │
│   Audit Log      │   Ollama/vLLM Mgmt   │   Quant Lab (admin)       │
│                  │                      │   Signal Ensemble         │
│                  │                      │   Risk Budgeting          │
└──────────────────┴──────────────────────┴───────────────────────────┘
```

---

## What Already Works (v4.2.1)

### Markets Core — REAL, not stubs:
- SEC EDGAR: CIK lookup → submissions → filings (live API)
- FRED: Series observations with API key (live API)
- ECB: CSV parsing with field detection (live API)
- Coinbase: Ticker with fallback to Kraken (live API)
- Kraken: Error array handling (live API)
- Nasdaq: Dataset fetch with API key (live API)
- Market snapshot persistence + SHA-256 provenance
- Portfolio analysis with PnL, cost basis, weights, concentration
- Forecast: regime detection + momentum/vol from stored history
- Paper trading CRUD
- Signal ensemble
- Risk budget with HHI
- Admin signal promotion

### Conversation Core — Self-reliant:
- Local symbolic engine (default, no external API)
- Three personas: cyber/research/lab
- Intent detection with mode-specific keywords
- Memory extraction + persistence
- Optional pluggable LLM via QC_LLM_URL (any OpenAI-compatible)
- No message duplication (fixed)

### Infrastructure:
- 11-table SQLite schema with WAL
- Unified auth (QC_API_KEY + QC_ADMIN_KEY)
- Frozen Settings dataclass
- Audit log + telemetry events
- GCS static dashboard (or legacy Firebase) + Render backend

---

## What Needs Building (v4.3 — Identity Core)

### New Module: `backend/modules/identity/`

#### `backend/modules/identity/store.py`
New tables (ADD to existing database.py init_db):
```
qc_memory_proposals    — pending/approved/rejected memories
qc_reflections         — pending/approved/rejected reflections
qc_persona_rules       — pending/approved/rejected persona rules
qc_self_notes          — pending/approved/rejected weekly self-notes
qc_runtime_provider    — current LLM provider config (single row)
qc_cyber_missions      — mission name, objective, status
qc_cyber_findings      — mission_id, severity, summary, details_json
qc_remediation_packages — mission_id, package_json, applied flag
qc_memory_lanes        — lane (personal/cyber/market/persona), key, value, source
```

Implementation note:
- The live runtime now centralizes Identity Core persistence in `backend/modules/identity/store.py`.
- The store maps this original `qc_*` logical contract onto the stabilized production schema (`identity_*` tables plus shared durable `memories`) so the current web app and APIs stay backward-compatible while the v4.3 plan is fully represented in code.

#### `backend/modules/identity/engine.py`
Functions:
- `create_proposal(lane, kind, content, score, source)` → pending proposal
- `list_pending(lane)` → all pending items
- `approve_proposal(lane, id)` → moves to approved, creates durable memory
- `reject_proposal(lane, id)` → marks rejected
- `run_learning_cycle(db_path)` → reads recent turns + telemetry + market snapshots
  → generates reflection proposals, persona rule proposals, weekly self-note
- `get_persona_state(db_path)` → current identity summary + approved rules + stats
- `get_memory_lanes(db_path)` → separate personal/cyber/market/persona memories

#### `backend/modules/identity/provider.py`
Functions:
- `get_provider_status(db_path)` → current provider + available options
- `set_provider(db_path, provider, model)` → admin-only switch
- `ollama_health(base_url)` → ping Ollama, return status
- `ollama_models(base_url)` → list available models
- `ollama_pull(base_url, model)` → queue model download
- `vllm_health(base_url)` → ping vLLM server

Allowed providers: local_symbolic_core, ollama, vllm_local, auto
Disallowed: claude-hosted, openai-hosted (in identity path)

#### `backend/modules/identity/missions.py`
Functions:
- `create_mission(db_path, name, objective)` → new cyber mission
- `list_missions(db_path)` → all missions with findings count
- `add_finding(db_path, mission_id, severity, summary, details)` → attach finding
- `generate_remediation(db_path, mission_id)` → build remediation package from findings
- `apply_remediation(db_path, mission_id)` → non-destructive audit-emitting apply

#### `backend/modules/identity/routes.py`
All routes under `/api/identity/`:
```
GET  /api/identity/state
GET  /api/identity/provider-status
POST /api/identity/provider-status        (admin)
GET  /api/identity/memory/pending/:lane
POST /api/identity/memory/:id/approve     (admin)
POST /api/identity/memory/:id/reject      (admin)
GET  /api/identity/reflections/pending
POST /api/identity/reflections/:id/approve (admin)
POST /api/identity/reflections/:id/reject  (admin)
GET  /api/identity/rules/pending
POST /api/identity/rules/:id/approve      (admin)
POST /api/identity/rules/:id/reject       (admin)
GET  /api/identity/self-notes/pending
POST /api/identity/self-notes/:id/approve (admin)
POST /api/identity/self-notes/:id/reject  (admin)
POST /api/identity/learning/cycle/run     (admin)
GET  /api/identity/ollama/health
GET  /api/identity/ollama/models
POST /api/identity/ollama/pull            (admin)
POST /api/identity/missions               (admin)
GET  /api/identity/missions
POST /api/identity/missions/:id/findings  (admin)
POST /api/identity/missions/:id/remediation/generate (admin)
POST /api/identity/missions/:id/remediation/apply    (admin)
```

### Frontend Additions

#### `frontend/src/panels/IdentityPanel.jsx`
- Shows persona state summary
- Shows approved memories by lane (personal/cyber/market/persona)
- Shows pending proposals with approve/reject buttons
- Shows active persona rules

#### `frontend/src/panels/LearningDock.jsx`
- Run learning cycle button
- Shows reflection proposals with approve/reject
- Shows self-notes with approve/reject
- Shows persona rule proposals with approve/reject

#### `frontend/src/panels/ModelManager.jsx`
- Current provider display
- Switch provider (admin)
- Ollama health status
- Available Ollama models
- Pull new model

#### `frontend/src/panels/CyberMissionPanel.jsx`
- Create mission
- List missions with findings count
- Add findings to mission
- Generate remediation package
- Apply remediation (non-destructive)

### Biomimetic Loop Integration

The learning cycle connects all three cores:

1. **SENSE** — Ingest from:
   - Recent conversation turns
   - Market snapshot history
   - Forecast run results
   - (Future: scan findings, incidents, telemetry from cyber core)

2. **INTERPRET** — Generate:
   - Memory proposals (scored, sourced)
   - Reflection proposals
   - Persona rule proposals

3. **DECIDE** — Admin reviews:
   - Approve/reject each proposal
   - Promoted items become durable

4. **ACT** — Durable changes:
   - Approved memories feed into conversation context
   - Approved persona rules modify system prompts
   - Approved market memories feed into forecast context

5. **REFLECT** — Weekly self-note:
   - Summarizes conversation patterns
   - Summarizes market activity
   - Summarizes learning outcomes
   - Stored for long-term identity continuity

---

## Build Order

1. Add identity tables to database.py
2. Build identity/store.py (CRUD for all proposal types)
3. Build identity/engine.py (learning cycle, persona state)
4. Build identity/provider.py (Ollama/vLLM management)
5. Build identity/missions.py (cyber mission memory)
6. Build identity/routes.py (all endpoints)
7. Register blueprint in app.py
8. Build frontend panels (4 panels)
9. Wire panels into App.jsx mode system
10. Update README and API_CONTRACT
11. Test everything

---

## What This Does NOT Do

- Does not replace or restyle the existing cinematic intro, avatar, or sound engine
- Does not auto-trade (paper only unless admin-promoted)
- Does not let public traffic rewrite QC's identity
- Does not claim to be a "true from-scratch LLM"
- Does not promise prediction accuracy
- Does not make the quantum module the sole decision engine

---

*Queen Califia CyberAI — Designed and built by Jonathan Peoples at Tamerian Materials*
