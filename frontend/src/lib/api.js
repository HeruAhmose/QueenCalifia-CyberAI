/**
 * QC OS — Shared API Helper v4.3
 * Centralised fetch with auth headers for all panel components.
 */

const API = (import.meta.env.VITE_API_URL || "http://localhost:5000").replace(/\/$/, "");
const CONFIGURED_API_KEY = import.meta.env.VITE_QC_API_KEY || "";

/** Build standard headers; optionally include admin key. */
export function hdrs(adminKey) {
  const h = { "Content-Type": "application/json" };
  if (CONFIGURED_API_KEY) h["X-QC-API-Key"] = CONFIGURED_API_KEY;
  if (adminKey) h["X-QC-Admin-Key"] = adminKey;
  return h;
}

/** GET helper — returns parsed JSON or throws. */
export async function apiGet(path, adminKey) {
  const r = await fetch(`${API}${path}`, { headers: hdrs(adminKey) });
  const d = await r.json();
  if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
  return d;
}

/** POST helper — returns parsed JSON or throws. */
export async function apiPost(path, body, adminKey) {
  const r = await fetch(`${API}${path}`, {
    method: "POST",
    headers: hdrs(adminKey),
    body: JSON.stringify(body ?? {}),
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
  return d;
}

export { API };
