/**
 * QC OS — ModelManager v4.3
 * ──────────────────────────
 * Provider status + switch (local_symbolic_core | ollama | vllm_local | auto)
 * Ollama health check, installed models list, pull new model.
 * Provider switch and pull require adminKey.
 */
import { useEffect, useState, useCallback } from "react";
import { apiGet, apiPost } from "../lib/api";

const PROVIDERS = ["local_symbolic_core", "ollama", "vllm_local", "auto"];

function humanSize(bytes) {
  if (!bytes) return "—";
  const gb = bytes / 1e9;
  return gb >= 1 ? `${gb.toFixed(1)} GB` : `${(bytes / 1e6).toFixed(0)} MB`;
}

export default function ModelManager({ adminKey }) {
  const [status, setStatus] = useState(null);
  const [ollamaHealth, setOllamaHealth] = useState(null);
  const [models, setModels] = useState([]);
  const [pullName, setPullName] = useState("");
  const [pullMsg, setPullMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  /* ── Load provider status ── */
  const loadStatus = useCallback(async () => {
    try { setStatus(await apiGet("/api/identity/provider-status")); }
    catch (e) { setErr(e.message); }
  }, []);

  useEffect(() => { loadStatus(); }, [loadStatus]);

  /* ── Ollama health + models ── */
  async function checkOllama() {
    setErr("");
    try {
      const [h, m] = await Promise.all([
        apiGet("/api/identity/ollama/health"),
        apiGet("/api/identity/ollama/models"),
      ]);
      setOllamaHealth(h);
      setModels(m.models || []);
    } catch (e) { setErr(e.message); }
  }

  /* ── Switch provider ── */
  async function switchProvider(prov) {
    if (!adminKey) { setErr("Admin key required"); return; }
    setBusy(true); setErr("");
    try {
      await apiPost("/api/identity/provider-status", { provider: prov }, adminKey);
      await loadStatus();
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }

  /* ── Pull model ── */
  async function pullModel() {
    if (!adminKey || !pullName.trim()) { setErr("Admin key and model name required"); return; }
    setBusy(true); setErr(""); setPullMsg("Pulling…");
    try {
      const d = await apiPost("/api/identity/ollama/pull", { model: pullName.trim() }, adminKey);
      setPullMsg(d.ok ? `✓ ${d.model} pulled` : `✗ ${d.error}`);
      if (d.ok) { setPullName(""); await checkOllama(); }
    } catch (e) { setPullMsg(""); setErr(e.message); }
    finally { setBusy(false); }
  }

  const cur = status?.current;

  return (
    <div className="mm-panel">
      <h2 className="mm-title">⚙ Model Manager</h2>

      {/* ── Current provider ── */}
      {cur && (
        <div className="mm-current">
          <div className="mm-row">
            <span className="mm-label">Provider</span>
            <code className="mm-val">{cur.provider}</code>
          </div>
          {cur.model && (
            <div className="mm-row">
              <span className="mm-label">Model</span>
              <code className="mm-val">{cur.model}</code>
            </div>
          )}
          <div className="mm-row">
            <span className="mm-label">Ollama</span>
            <span className={`mm-dot ${status.ollama_reachable ? "on" : "off"}`} />
          </div>
          <div className="mm-row">
            <span className="mm-label">vLLM</span>
            <span className={`mm-dot ${status.vllm_reachable ? "on" : "off"}`} />
          </div>
        </div>
      )}

      {/* ── Provider switch ── */}
      <div className="mm-switch">
        {PROVIDERS.map(p => (
          <button key={p}
            className={`mm-prov-btn ${cur?.provider === p ? "active" : ""}`}
            disabled={busy || !adminKey || cur?.provider === p}
            onClick={() => switchProvider(p)}>
            {p.replace(/_/g, " ")}
          </button>
        ))}
      </div>

      {/* ── Ollama section ── */}
      <div className="mm-ollama">
        <div className="mm-ollama-head">
          <span className="mm-section-label">Ollama</span>
          <button className="mm-sm-btn" onClick={checkOllama} disabled={busy}>Refresh</button>
        </div>

        {ollamaHealth && (
          <div className="mm-row">
            <span className="mm-label">Status</span>
            <code className={`mm-val ${ollamaHealth.reachable ? "ok" : "err"}`}>
              {ollamaHealth.reachable ? "Healthy" : ollamaHealth.status}
            </code>
          </div>
        )}

        {models.length > 0 && (
          <div className="mm-models">
            {models.map(m => (
              <div key={m.name} className="mm-model-row">
                <span className="mm-model-name">{m.name}</span>
                <span className="mm-model-size">{humanSize(m.size)}</span>
              </div>
            ))}
          </div>
        )}

        {/* ── Pull ── */}
        <div className="mm-pull">
          <input className="mm-pull-input" value={pullName}
            onChange={e => setPullName(e.target.value)}
            placeholder="e.g. mistral:7b" disabled={busy} />
          <button className="mm-sm-btn" disabled={busy || !adminKey || !pullName.trim()}
            onClick={pullModel}>Pull</button>
        </div>
        {pullMsg && <p className="mm-pull-msg">{pullMsg}</p>}
      </div>

      {err && <div className="mm-error">{err}</div>}
    </div>
  );
}
