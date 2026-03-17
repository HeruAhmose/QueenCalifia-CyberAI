# QC OS — API Contract

## GET /healthz
Health check. No auth.

## GET /api/config
Public config: name, persona, modes, capabilities, welcome message.

## POST /api/chat/
Conversation with LLM brain (mode: cyber/research/lab). Requires QC_API_KEY.

## GET /api/chat/memories
List user memories. Requires QC_API_KEY.

## GET /api/market/snapshot?asset_type=&symbol=
Unified market snapshot. Types: crypto, forex, stock, macro. Requires QC_API_KEY.

## GET /api/market/fred/{series_id}
FRED economic series. Requires QC_API_KEY + FRED_API_KEY.

## GET /api/market/nasdaq/{dataset}
Nasdaq Data Link dataset. Requires QC_API_KEY + NASDAQ_API_KEY.

## GET /api/market/sources
List trusted sources and their status. Requires QC_API_KEY.

## POST /api/market/portfolio/analyze
Portfolio analysis with PnL, weights, concentration risk. Requires QC_API_KEY.

## POST /api/market/forecast/run
Forecast from stored history (momentum/vol/mean). Requires QC_API_KEY.

## POST /api/market/quant/run
Admin-only quant optimizer. Requires QC_ADMIN_TOKEN header.

## POST /api/forecast/run
Forecast run (regime detection, scenario, risk budget). Requires QC_API_KEY.

## POST /api/forecast/portfolio/create
Create paper trading portfolio. Requires QC_API_KEY.

## GET /api/forecast/portfolio/list
List paper portfolios. Requires QC_API_KEY.

## POST /api/forecast/portfolio/analyze
Risk budget analysis. Requires QC_API_KEY.

## POST /api/forecast/admin/promote-signal
Admin-only: promote a forecast signal. Requires QC_ADMIN_TOKEN.
