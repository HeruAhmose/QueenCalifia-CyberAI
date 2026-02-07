# Load testing (k6)

This repository includes a small k6 script that exercises:

- `GET /api/health`
- `GET /api/dashboard`
- `GET /api/incidents`
- `POST /api/vulns/scan` (enqueue only, probabilistic)

It also validates budgeting headers (when enabled) and writes a summarized report.

## Run via Docker Compose

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
