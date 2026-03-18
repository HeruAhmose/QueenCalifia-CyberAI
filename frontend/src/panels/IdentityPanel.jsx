/**
 * QC OS — IdentityPanel v4.3
 * ─────────────────────────────
 * Persona state overview + tabbed approval queues:
 *   Proposals · Reflections · Rules · Self-Notes
 * All mutations require adminKey.
 */
import { useEffect, useState, useCallback } from "react";
import { apiGet, apiPost } from "../lib/api";

const TABS = ["proposals", "reflections", "rules", "notes"];
const LANES = ["personal", "cyber", "market", "persona"];

export default function IdentityPanel({ adminKey }) {
  const [state, setState] = useState(null);
  const [tab, setTab] = useState("proposals");
  const [items, setItems] = useState([]);
  const [lane, setLane] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  /* ── Persona state ── */
  const loadState = useCallback(async () => {
    try { setState(await apiGet("/api/identity/state")); }
    catch (e) { setErr(e.message); }
  }, []);

  useEffect(() => { loadState(); }, [loadState]);

  /* ── Tab data ── */
  const loadTab = useCallback(async () => {
    setErr(""); setItems([]);
    try {
      let data;
      if (tab === "proposals") {
        const qs = lane ? `?lane=${lane}` : "";
        data = await apiGet(`/api/identity/memory/pending${qs}`);
      } else if (tab === "reflections") {
        data = await apiGet("/api/identity/reflections/pending");
      } else if (tab === "rules") {
        data = await apiGet("/api/identity/rules/pending");
      } else {
        data = await apiGet("/api/identity/self-notes/pending");
      }
      setItems(data.items || []);
    } catch (e) { setErr(e.message); }
  }, [tab, lane]);

  useEffect(() => { loadTab(); }, [loadTab]);

  /* ── Actions ── */
  async function act(action, id) {
    if (!adminKey) { setErr("Admin key required"); return; }
    setBusy(true); setErr("");
    try {
      const prefix = tab === "proposals" ? "/api/identity/memory"
        : tab === "reflections" ? "/api/identity/reflections"
        : tab === "rules" ? "/api/identity/rules"
        : "/api/identity/self-notes";
      await apiPost(`${prefix}/${id}/${action}`, {}, adminKey);
      await loadTab();
      await loadState();
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }

  return (
    <div className="id-panel">
      <h2 className="id-title">♛ Identity Core</h2>

      {/* ── State summary ── */}
      {state && (
        <div className="id-state">
          <div className="id-stat"><span className="id-stat-n">{state.pending_items}</span><span className="id-stat-l">Pending</span></div>
          <div className="id-stat"><span className="id-stat-n">{state.approved_rules_count}</span><span className="id-stat-l">Rules</span></div>
          <div className="id-stat"><span className="id-stat-n">{state.approved_notes_count}</span><span className="id-stat-l">Notes</span></div>
          {LANES.map(l => (
            <div key={l} className="id-stat">
              <span className="id-stat-n">{state.memory_lanes?.[l] ?? 0}</span>
              <span className="id-stat-l">{l}</span>
            </div>
          ))}
        </div>
      )}

      {/* ── Tab nav ── */}
      <div className="id-tabs">
        {TABS.map(t => (
          <button key={t} className={`id-tab ${tab === t ? "active" : ""}`}
            onClick={() => setTab(t)}>{t}</button>
        ))}
      </div>

      {/* ── Lane filter (proposals only) ── */}
      {tab === "proposals" && (
        <div className="id-lane-filter">
          <button className={`id-lane-btn ${lane === "" ? "active" : ""}`}
            onClick={() => setLane("")}>All</button>
          {LANES.map(l => (
            <button key={l} className={`id-lane-btn ${lane === l ? "active" : ""}`}
              onClick={() => setLane(l)}>{l}</button>
          ))}
        </div>
      )}

      {/* ── Items ── */}
      <div className="id-queue">
        {items.length === 0 && <p className="muted">No pending items.</p>}
        {items.map(it => (
          <div key={it.id} className="id-item">
            <div className="id-item-head">
              <span className="id-item-id">#{it.id}</span>
              {it.lane && <span className={`id-lane-tag ${it.lane}`}>{it.lane}</span>}
              {it.kind && <span className="id-kind-tag">{it.kind}</span>}
              {it.score != null && <span className="id-score">{(it.score * 100).toFixed(0)}%</span>}
            </div>
            <p className="id-item-body">{it.content || it.rule_text || it.note_text || ""}</p>
            <div className="id-item-actions">
              <button className="id-btn approve" disabled={busy || !adminKey}
                onClick={() => act("approve", it.id)}>Approve</button>
              <button className="id-btn reject" disabled={busy || !adminKey}
                onClick={() => act("reject", it.id)}>Reject</button>
            </div>
          </div>
        ))}
      </div>

      {err && <div className="id-error">{err}</div>}
    </div>
  );
}
