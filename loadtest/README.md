# Load testing (k6)

This repository includes **`loadtest/k6_qc.js`**:

- **Smoke mode (default):** `GET /api/health`, `GET /api/dashboard`, `GET /api/incidents`, optional `POST /api/vulns/scan` (probabilistic).
- **Full stress mode (`QC_K6_FULL_SUITE=1`):** samples **~70+ read routes** (same surface as `scripts/qc_perpetual_learner.py`: identity, market/FRED, mesh, intel, evolution, predictor, telemetry, etc.) plus optional writes/chat/heavy scans via env flags.

It validates budgeting headers when enabled and writes `summary.json` / `summary.txt`.

## Run via Docker Compose

**Windows:** if the CLI is installed but commands fail with `dockerDesktopLinuxEngine`, **start Docker Desktop** and wait until the engine is running, then:

```powershell
.\scripts\run_k6_docker.ps1
```

1) Start the stack:

```bash
docker compose up --build
```

2) Run k6 (requires the `loadtest` profile):

```bash
# Optional: set an API key so budgeting/rate limits are per-principal
export QC_LOADTEST_API_KEY="<your_api_key>"

# Optional: keep scans fast/deterministic while load testing
export QC_SCAN_DRY_RUN=1

# Tune load
export QC_K6_VUS=25
export QC_K6_DURATION=60s
export QC_K6_ENABLE_SCAN=1

# Validate budgeting headers (default: 1 in compose)
export QC_K6_EXPECT_BUDGET_HEADERS=1

docker compose --profile loadtest run --rm k6
```

### Full stress (all major QC functions)

Use a real **`QC_LOADTEST_API_KEY`** (same as server `QC_API_KEY`). Tune **scan target** to something on your **`QC_SCAN_ALLOWLIST`** (default in script: `10.0.0.1`).

```bash
export QC_LOADTEST_API_KEY="<your_api_key>"
export QC_SCAN_DRY_RUN=1

export QC_K6_FULL_SUITE=1
export QC_K6_SAMPLES_PER_ITER=14
export QC_K6_VUS=30
export QC_K6_DURATION=120s

# Optional: match perpetual learner–style load (LLM $ + CPU)
export QC_K6_ENABLE_POSTS=1
export QC_K6_ENABLE_CHAT=1

# Rare vuln / one-click (use only on authorized targets)
# export QC_K6_ENABLE_HEAVY=1
# export QC_K6_SCAN_TARGET=10.0.0.1

export QC_K6_ENABLE_SCAN=1
export QC_K6_EXPECT_BUDGET_HEADERS=1

docker compose --profile loadtest run --rm k6
```

**Windows (PowerShell):**

```powershell
$env:QC_LOADTEST_API_KEY = "<your_api_key>"
$env:QC_K6_FULL_SUITE = "1"
$env:QC_K6_ENABLE_POSTS = "1"
$env:QC_K6_VUS = "25"
$env:QC_K6_DURATION = "90s"
docker compose --profile loadtest run --rm k6
```

| Variable | Meaning |
|----------|---------|
| `QC_K6_FULL_SUITE` | `1` = stress breadth (many GETs per iteration) |
| `QC_K6_SAMPLES_PER_ITER` | Random GETs per VU iteration (default `12`) |
| `QC_K6_ENABLE_POSTS` | `1` = occasional events / forecast / predictor / evolution / telemetry POSTs |
| `QC_K6_ENABLE_CHAT` | `1` = occasional `/api/chat/` (slow; uses LLM quota) |
| `QC_K6_ENABLE_HEAVY` | `1` = rare async vuln scan + one-click (authorized targets only) |
| `QC_K6_SCAN_TARGET` | Host passed to scan endpoints (must be allowlisted) |
| `QC_K6_P95_MS` / `QC_K6_HTTP_FAIL_RATE` | Override thresholds (full suite defaults are looser) |

### Output
Compose mounts `./data/loadtest` into the k6 container at `/output`.

Reports are written to:

- `./data/loadtest/summary.json`
- `./data/loadtest/summary.txt`

## Run locally (without Docker)

Install k6, then:

```bash
export QC_API_BASE="http://localhost:5000"
export QC_API_KEY="<your_api_key>"
export QC_K6_VUS=20
export QC_K6_DURATION=30s
export QC_K6_ENABLE_SCAN=1
export QC_K6_REPORT_DIR="."
export QC_K6_EXPECT_BUDGET_HEADERS=1

k6 run ./loadtest/k6_qc.js
```

### Full stress locally (k6 installed)

```bash
export QC_API_BASE="http://localhost:5000"
export QC_API_KEY="<your_api_key>"
export QC_K6_FULL_SUITE=1
export QC_K6_SAMPLES_PER_ITER=14
export QC_K6_ENABLE_POSTS=1
export QC_K6_VUS=25
export QC_K6_DURATION=90s
export QC_K6_REPORT_DIR="."

k6 run ./loadtest/k6_qc.js
```
