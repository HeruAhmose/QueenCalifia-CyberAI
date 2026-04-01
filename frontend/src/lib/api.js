/**
 * QC OS — Shared API Helper v4.3
 * Centralised fetch with auth headers + retries (Render cold start / transient 502).
 */

import { getQcApiBase } from "../utils/qcApiBase.js";

const API = getQcApiBase();
const CONFIGURED_API_KEY = import.meta.env.VITE_QC_API_KEY || "";

// Same env names as QueenCalifia_Unified_Command_Dashboard (qcFetchWithRetry)
const RETRIES = Math.max(1, Math.min(8, Number(import.meta.env.VITE_QC_FETCH_RETRIES || 4)));
const RETRY_MS = Math.max(200, Math.min(8000, Number(import.meta.env.VITE_QC_FETCH_RETRY_MS || 1100)));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const networkish = (err) =>
  /failed to fetch|networkerror|load failed|aborted|timeout/i.test(String(err?.message || err || ""));
const statusRetry = (s) => s === 502 || s === 503 || s === 504;

async function fetchWithRetry(url, init) {
  let lastErr;
  for (let attempt = 0; attempt < RETRIES; attempt++) {
    try {
      const r = await fetch(url, init);
      if (statusRetry(r.status) && attempt < RETRIES - 1) {
        await sleep(RETRY_MS * (attempt + 1));
        continue;
      }
      return r;
    } catch (e) {
      lastErr = e;
      if (attempt < RETRIES - 1 && networkish(e)) {
        await sleep(RETRY_MS * (attempt + 1));
        continue;
      }
      throw e;
    }
  }
  throw lastErr ?? new Error("fetch failed");
}

/** Build standard headers; optionally include admin key. */
export function hdrs(adminKey) {
  const h = { "Content-Type": "application/json" };
  if (CONFIGURED_API_KEY) h["X-QC-API-Key"] = CONFIGURED_API_KEY;
  if (adminKey) h["X-QC-Admin-Key"] = adminKey;
  return h;
}

/** GET helper — returns parsed JSON or throws. */
export async function apiGet(path, adminKey) {
  const r = await fetchWithRetry(`${API}${path}`, { headers: hdrs(adminKey) });
  const d = await r.json();
  if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
  return d;
}

/** POST helper — returns parsed JSON or throws. */
export async function apiPost(path, body, adminKey) {
  const r = await fetchWithRetry(`${API}${path}`, {
    method: "POST",
    headers: hdrs(adminKey),
    body: JSON.stringify(body ?? {}),
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
  return d;
}

export { API, fetchWithRetry };
