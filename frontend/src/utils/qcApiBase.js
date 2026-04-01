/**
 * API origin for browser fetch (no trailing slash).
 * - Set VITE_QC_API_URL or VITE_API_URL for Firebase/GCS → Render (or any backend).
 * - Set VITE_SAME_ORIGIN_API=1 at build time when nginx (or another edge) proxies /api/* to the API.
 */
export function getQcApiBase() {
  const fromEnv = import.meta.env.VITE_QC_API_URL || import.meta.env.VITE_API_URL;
  if (fromEnv) return String(fromEnv).replace(/\/$/, "");
  if (import.meta.env.VITE_SAME_ORIGIN_API === "1") return "";
  if (import.meta.env.DEV) return "http://localhost:5000";
  return "https://queencalifia-cyberai.onrender.com";
}
