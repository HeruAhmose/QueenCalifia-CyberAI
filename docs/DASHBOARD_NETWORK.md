# Dashboard “Failed to fetch live backend data”

The unified dashboard uses `fetch()` to `VITE_API_URL` / `VITE_QC_API_URL` (default production: `https://queencalifia-cyberai.onrender.com`). A **network** failure surfaces as `TypeError: Failed to fetch` (often a CORS block, timeout, or blocked request).

## Checklist

1. **DevTools → Network**  
   - Request **pending forever** → Render cold start; retry after ~30–60s.  
   - **(failed)** or **CORS error** in console → see below.  
   - **401/403** → not a fetch failure; re-enter API key in the dashboard auth panel.

2. **Correct API URL in the built site**  
   Firebase Hosting bakes env at **build** time.  
   - `frontend/.env.production` should set `VITE_API_URL=https://queencalifia-cyberai.onrender.com` (no trailing slash).  
   - Rebuild and redeploy: `cd frontend && npm run build` then `firebase deploy`.

3. **`QC_CORS_ORIGINS` on Render (exact match)**  
   The API must list your dashboard **Origin** exactly (scheme + host, no path), comma-separated, e.g.  
   `https://queencalifia-cyberai.web.app,https://queencalifia-cyberai.firebaseapp.com`  
   Add **preview channel** URLs if you use them, e.g.  
   `https://queencalifia-cyberai--channel-abc123.web.app`  
   Custom domains (e.g. `https://app.example.com`) **must** appear here; suffix rules alone are not enough for arbitrary domains.

4. **VPN / adblock / corporate proxy**  
   Try another network or disable extensions; some block `*.onrender.com`.

5. **API keys**  
   After a full reload, paste the key again (sessionStorage). Structured keys must be the **raw** key the server accepts.

## Intermittent disconnections

Common on **Render** when the web service **sleeps** (free/hobby) or is **restarting**: the first requests after idle can return **502/503** or fail with **Failed to fetch** until Gunicorn is warm.

Mitigations:

1. **Paid / always-on** instance on Render (or an external uptime ping every few minutes — use responsibly).
2. **Dashboard retries:** `qcGet` / `qcPost` and the **Vulnerability** tab’s `apiFetch` use `qcFetchWithRetry` (defaults **4** attempts, base **~1100ms**; production `.env.production` may set **5** / **1400ms**). Tune at build time:
   - `VITE_QC_FETCH_RETRIES` — number of attempts (1–8)
   - `VITE_QC_FETCH_RETRY_MS` — base delay in ms before backoff multiplier (200–8000)
3. **Gunicorn timeout:** `render.yaml` uses `--timeout 120` so long cold LLM/chat calls are less likely to be killed mid-request.
4. **Rate limits:** burst traffic can yield **429**; space out tab refreshes and heavy parallel panels.

## Vulnerability scan stuck on `PENDING` (UUID `scan_id`)

The dashboard’s async scanner polls `GET /api/vulns/scan/<id>`. **`PENDING`** with a **UUID** task id means the API **queued a Celery job** but **no worker** is consuming the **`scans`** queue (or Redis/broker is miswired).

**Fix (pick one):**

1. **Single API service (e.g. Render web only):** set **`QC_USE_CELERY=0`** on the API. Scans then use the **in-process** queue + SQLite job store (`ScanJobManager`); `scan_id` is shorter (hex), not a UUID.
2. **Scaled / worker topology:** deploy the **Celery worker** with the same **`QC_REDIS_URL`** and **`QC_USE_CELERY=1`**, command like:  
   `celery -A celery_app.celery_app worker -l INFO --concurrency 1 -Q scans`  
   (matches `render.yaml` worker service.)

Do **not** assume Redis alone runs scans — Redis is also used for rate limits and budgeting.

## Related code

- Dashboard API base: `frontend/src/QueenCalifia_Unified_Command_Dashboard.jsx` (`QC_API`, `qcGet` / `qcPost`, `qcFetchWithRetry`).  
- Shared helper: `frontend/src/lib/api.js` (`VITE_API_URL` / `VITE_QC_API_URL` — keep in sync with dashboard).  
- CORS: `api/gateway.py` (`_browser_cors_origin_allowed`), Flask CORS on `/api/*` in `backend/app.py`.  
- Async scan routing: `api/gateway.py` (`_vuln_async_queue_uses_celery`, `POST /api/vulns/scan`).
