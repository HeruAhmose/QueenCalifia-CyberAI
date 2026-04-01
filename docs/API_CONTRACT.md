# QC OS — API Contract

This document reflects the repository as currently wired:

- Frontend is hosted on Google Cloud Storage static website hosting (see `docs/DEPLOY_DASHBOARD_GCS.md`; legacy Firebase config may still exist in-repo).
- Backend runs on Render using `backend/app.py` + the root security gateway.
- The current checked-in Render profile sets `QC_NO_AUTH=1` for dashboard UX.
- In stricter deployments, the same routes can be protected by API/admin keys.

## GET /healthz
Health check. No auth.

## GET /api/config
Public config: name, persona, modes, capabilities, welcome message.

## POST /api/chat/
Conversation with LLM brain (mode: cyber/research/lab). Public in the current Render profile; requires API auth in strict mode.

## GET /api/chat/memories
List user memories. Public in the current Render profile; requires API auth in strict mode.

## GET /api/market/snapshot?asset_type=&symbol=
Unified market snapshot. Types: crypto, forex, stock, macro. Public in the current Render profile; requires API auth in strict mode.

## GET /api/market/fred/{series_id}
FRED economic series. Public/API-key access depending on deployment, plus `FRED_API_KEY` if the provider requires it.

## GET /api/market/nasdaq/{dataset}
Nasdaq Data Link dataset. Public/API-key access depending on deployment, plus `NASDAQ_API_KEY` if the provider requires it.

## GET /api/market/sources
List trusted sources and their status. Public in the current Render profile; requires API auth in strict mode.

## POST /api/forecast/run
Forecast run (regime detection, scenario, risk budget). Public in the current Render profile; requires API auth in strict mode.

## POST /api/forecast/portfolio/create
Create paper trading portfolio. Public in the current Render profile; requires API auth in strict mode.

## GET /api/forecast/portfolio/list
List paper portfolios. Public in the current Render profile; requires API auth in strict mode.

## POST /api/forecast/portfolio/analyze
Detailed portfolio analysis. Public in the current Render profile; requires API auth in strict mode.

## POST /api/forecast/portfolio/risk
Risk budget analysis. Public in the current Render profile; requires API auth in strict mode.

## POST /api/forecast/quant/run
Admin-only quant optimizer. Uses `X-QC-Admin-Key` in strict mode.

## POST /api/forecast/admin/promote-signal
Admin-only: promote a forecast signal. Uses `X-QC-Admin-Key` in strict mode.

## GET /api/identity/state
Identity Core state overview. Public in the current Render profile; requires API auth in strict mode.

## GET /api/identity/memory/pending?lane={personal|cyber|market|persona}
Pending memory proposals. Public in the current Render profile; requires API auth in strict mode.

## POST /api/identity/memory/{id}/approve
Approve a memory proposal. Uses `X-QC-Admin-Key` in strict mode.

## POST /api/identity/memory/{id}/reject
Reject a memory proposal. Uses `X-QC-Admin-Key` in strict mode.

## GET /api/vulns/scan/{scan_id}
Retrieve vulnerability scan status / result.

## POST /api/vulns/scan
Queue a vulnerability scan. Requires `acknowledge_authorized: true`. Public in the current Render profile; requires API auth in strict mode.

## POST /api/vulns/webapp
Run a web-application-focused scan. Requires `acknowledge_authorized: true`.

## POST /api/v1/one-click/scan-and-fix
One-click scan/remediation workflow. Requires `acknowledge_authorized: true`.

## GET /api/v1/evolution/status
Evolution engine status.

## GET /api/v1/evolution/storage
Memory persistence and backup status. Requires `X-QC-Memory-Token` or admin principal.

## GET /api/v1/evolution/backups
List available evolution memory snapshots. Requires `X-QC-Memory-Token` or admin principal.

## POST /api/v1/evolution/backup
Create a point-in-time evolution memory backup. Requires `X-QC-Memory-Token` or admin principal.
