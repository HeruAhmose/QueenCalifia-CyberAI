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
2. **Dashboard retries:** `qcGet` / `qcPost` retry transient failures automatically (default **3** attempts, backoff from **~900ms**). Tune at build time:
   - `VITE_QC_FETCH_RETRIES` — number of attempts (1–6, default 3)
   - `VITE_QC_FETCH_RETRY_MS` — base delay in ms before backoff multiplier (default 900)
3. **Gunicorn timeout:** `render.yaml` uses `--timeout 120` so long cold LLM/chat calls are less likely to be killed mid-request.
4. **Rate limits:** burst traffic can yield **429**; space out tab refreshes and heavy parallel panels.

## Related code

- Dashboard API base: `frontend/src/QueenCalifia_Unified_Command_Dashboard.jsx` (`QC_API`, `qcGet` / `qcPost`, `qcFetchWithRetry`).  
- Shared helper: `frontend/src/lib/api.js` (`VITE_API_URL` / `VITE_QC_API_URL` — keep in sync with dashboard).  
- CORS: `api/gateway.py` (`_browser_cors_origin_allowed`), Flask CORS on `/api/*` in `backend/app.py`.
