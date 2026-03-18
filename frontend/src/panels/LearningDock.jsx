/**
 * QC OS — LearningDock v4.3
 * ──────────────────────────
 * Trigger the biomimetic sense→interpret→propose cycle.
 * Shows last run results (proposals/reflections/rules/self-notes generated).
 * Requires adminKey.
 */
import { useState } from "react";
import { apiPost } from "../lib/api";

export default function LearningDock({ adminKey }) {
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function runCycle() {
    if (!adminKey) { setErr("Admin key required"); return; }
    setBusy(true); setErr(""); setResult(null);
    try {
      const d = await apiPost("/api/identity/learning/cycle/run", {}, adminKey);
      setResult(d);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }

  return (
    <div className="ld-panel">
      <div className="ld-head">
        <h2 className="ld-title">🧬 Learning Dock</h2>
        <button className="ld-run-btn" disabled={busy || !adminKey}
          onClick={runCycle}>{busy ? "Running…" : "Run Cycle"}</button>
      </div>

      {result && (
        <div className="ld-result">
          <div className="ld-row"><span className="ld-label">Run</span><code className="ld-val">{result.run_at}</code></div>

          <div className="ld-section-label">Sensed</div>
          <div className="ld-stats">
            <div className="ld-stat"><span className="ld-stat-n">{result.sensed?.conversation_turns ?? 0}</span><span className="ld-stat-l">Turns</span></div>
            <div className="ld-stat"><span className="ld-stat-n">{result.sensed?.market_snapshots ?? 0}</span><span className="ld-stat-l">Mkt</span></div>
            <div className="ld-stat"><span className="ld-stat-n">{result.sensed?.forecast_runs ?? 0}</span><span className="ld-stat-l">Fcst</span></div>
            <div className="ld-stat"><span className="ld-stat-n">{result.sensed?.audit_events ?? 0}</span><span className="ld-stat-l">Events</span></div>
          </div>

          <div className="ld-section-label">Generated</div>
          <div className="ld-stats">
            <div className="ld-stat"><span className="ld-stat-n">{result.generated?.proposals ?? 0}</span><span className="ld-stat-l">Proposals</span></div>
            <div className="ld-stat"><span className="ld-stat-n">{result.generated?.reflections ?? 0}</span><span className="ld-stat-l">Reflctn</span></div>
            <div className="ld-stat"><span className="ld-stat-n">{result.generated?.rules ?? 0}</span><span className="ld-stat-l">Rules</span></div>
            <div className="ld-stat"><span className="ld-stat-n">{result.generated?.self_notes ?? 0}</span><span className="ld-stat-l">Notes</span></div>
          </div>
        </div>
      )}

      {!result && !err && <p className="muted">Trigger a cycle to sense, interpret, and propose.</p>}
      {err && <div className="ld-error">{err}</div>}
    </div>
  );
}
