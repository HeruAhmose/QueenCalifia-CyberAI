/**
 * QC OS — CyberMissionPanel v4.3
 * ─────────────────────────────────
 * Mission CRUD, finding attachment (severity-tagged),
 * remediation package generation and non-destructive apply.
 * All mutations require adminKey.
 */
import { useEffect, useState, useCallback } from "react";
import { apiGet, apiPost } from "../lib/api";

const SEVERITIES = ["info", "low", "medium", "high", "critical"];
const SEV_COLOR = { info: "#6b7f99", low: "#69f0ae", medium: "#ffd740", high: "#ff9100", critical: "#ff5252" };

export default function CyberMissionPanel({ adminKey }) {
  const [missions, setMissions] = useState([]);
  const [selected, setSelected] = useState(null);       // full mission detail
  const [newName, setNewName] = useState("");
  const [newObj, setNewObj] = useState("");
  const [findForm, setFindForm] = useState({ severity: "medium", summary: "", details: "" });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  /* ── List missions ── */
  const loadList = useCallback(async () => {
    try {
      const d = await apiGet("/api/identity/missions");
      setMissions(d.items || []);
    } catch (e) { setErr(e.message); }
  }, []);

  useEffect(() => { loadList(); }, [loadList]);

  /* ── Load single mission detail ── */
  async function loadDetail(id) {
    setErr("");
    try {
      const d = await apiGet(`/api/identity/missions/${id}`);
      setSelected(d);
    } catch (e) { setErr(e.message); }
  }

  /* ── Create mission ── */
  async function createMission() {
    if (!adminKey) { setErr("Admin key required"); return; }
    if (!newName.trim() || !newObj.trim()) { setErr("Name and objective required"); return; }
    setBusy(true); setErr("");
    try {
      const d = await apiPost("/api/identity/missions", { name: newName.trim(), objective: newObj.trim() }, adminKey);
      setNewName(""); setNewObj("");
      await loadList();
      await loadDetail(d.id);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }

  /* ── Add finding ── */
  async function addFinding() {
    if (!adminKey || !selected) { setErr("Admin key required"); return; }
    if (!findForm.summary.trim()) { setErr("Finding summary required"); return; }
    setBusy(true); setErr("");
    try {
      const body = {
        severity: findForm.severity,
        summary: findForm.summary.trim(),
      };
      if (findForm.details.trim()) {
        try { body.details = JSON.parse(findForm.details); } catch { body.details = { raw: findForm.details.trim() }; }
      }
      await apiPost(`/api/identity/missions/${selected.id}/findings`, body, adminKey);
      setFindForm({ severity: "medium", summary: "", details: "" });
      await loadDetail(selected.id);
      await loadList();
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }

  /* ── Generate remediation ── */
  async function genRemediation() {
    if (!adminKey || !selected) return;
    setBusy(true); setErr("");
    try {
      await apiPost(`/api/identity/missions/${selected.id}/remediation/generate`, {}, adminKey);
      await loadDetail(selected.id);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }

  /* ── Apply remediation ── */
  async function applyRemediation() {
    if (!adminKey || !selected) return;
    setBusy(true); setErr("");
    try {
      await apiPost(`/api/identity/missions/${selected.id}/remediation/apply`, {}, adminKey);
      await loadDetail(selected.id);
      await loadList();
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }

  /* ── Parse package JSON safely ── */
  function parsePackage(pkg) {
    try { return JSON.parse(pkg.package_json); } catch { return null; }
  }

  return (
    <div className="cm-panel">
      <h2 className="cm-title">🎯 Cyber Missions</h2>

      <div className="cm-layout">
        {/* ── Left: mission list + create ── */}
        <div className="cm-sidebar">
          <div className="cm-create">
            <input className="cm-input" value={newName}
              onChange={e => setNewName(e.target.value)}
              placeholder="Mission name" disabled={busy} />
            <input className="cm-input" value={newObj}
              onChange={e => setNewObj(e.target.value)}
              placeholder="Objective" disabled={busy} />
            <button className="cm-btn primary" disabled={busy || !adminKey}
              onClick={createMission}>+ Create</button>
          </div>

          <div className="cm-list">
            {missions.length === 0 && <p className="muted">No missions yet.</p>}
            {missions.map(m => (
              <button key={m.id}
                className={`cm-mission-row ${selected?.id === m.id ? "active" : ""}`}
                onClick={() => loadDetail(m.id)}>
                <span className={`cm-status-dot ${m.status}`} />
                <span className="cm-mission-name">{m.name}</span>
                <span className="cm-mission-meta">
                  {m.findings_count}F{m.has_remediation ? " · R" : ""}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* ── Right: mission detail ── */}
        <div className="cm-detail">
          {!selected ? (
            <p className="muted">Select or create a mission.</p>
          ) : (
            <>
              {/* Header */}
              <div className="cm-detail-head">
                <h3 className="cm-detail-name">{selected.name}</h3>
                <span className={`cm-status-badge ${selected.status}`}>{selected.status}</span>
              </div>
              <p className="cm-detail-obj">{selected.objective}</p>

              {/* Findings */}
              <div className="cm-section">
                <span className="cm-section-label">
                  Findings ({selected.findings?.length || 0})
                </span>
                <div className="cm-findings">
                  {(selected.findings || []).map(f => (
                    <div key={f.id} className="cm-finding">
                      <span className="cm-sev-badge" style={{ color: SEV_COLOR[f.severity] }}>
                        {f.severity}
                      </span>
                      <span className="cm-finding-text">{f.summary}</span>
                    </div>
                  ))}
                </div>

                {/* Add finding form */}
                <div className="cm-add-finding">
                  <select className="cm-select" value={findForm.severity}
                    onChange={e => setFindForm(f => ({ ...f, severity: e.target.value }))}>
                    {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                  <input className="cm-input flex" value={findForm.summary}
                    onChange={e => setFindForm(f => ({ ...f, summary: e.target.value }))}
                    placeholder="Finding summary" disabled={busy} />
                  <button className="cm-btn" disabled={busy || !adminKey}
                    onClick={addFinding}>+ Finding</button>
                </div>
                <textarea className="cm-textarea" rows={2} value={findForm.details}
                  onChange={e => setFindForm(f => ({ ...f, details: e.target.value }))}
                  placeholder="Optional details (JSON or text)" disabled={busy} />
              </div>

              {/* Remediation */}
              <div className="cm-section">
                <span className="cm-section-label">Remediation</span>
                <div className="cm-remed-actions">
                  <button className="cm-btn primary" disabled={busy || !adminKey || !(selected.findings?.length)}
                    onClick={genRemediation}>Generate Package</button>
                  <button className="cm-btn apply" disabled={busy || !adminKey}
                    onClick={applyRemediation}>Apply Latest</button>
                </div>

                {(selected.remediation_packages || []).map(pkg => {
                  const parsed = parsePackage(pkg);
                  return (
                    <div key={pkg.id} className={`cm-remed-pkg ${pkg.applied ? "applied" : ""}`}>
                      <div className="cm-remed-head">
                        <span className="cm-remed-id">PKG-{pkg.id}</span>
                        <span className={`cm-remed-status ${pkg.applied ? "applied" : "pending"}`}>
                          {pkg.applied ? "Applied" : "Pending"}
                        </span>
                      </div>
                      {parsed?.steps?.map((step, i) => (
                        <div key={i} className="cm-remed-step">
                          <span className="cm-sev-badge sm" style={{ color: SEV_COLOR[step.severity] }}>
                            P{step.priority}
                          </span>
                          <span className="cm-remed-action">{step.action}</span>
                        </div>
                      ))}
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </div>
      </div>

      {err && <div className="cm-error">{err}</div>}
    </div>
  );
}
