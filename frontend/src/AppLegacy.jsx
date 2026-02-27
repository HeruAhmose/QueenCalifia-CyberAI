import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createOptimisticEvidence, replaceOptimisticEvidence, rollbackOptimisticEvidence } from "./lib/evidenceOptimistic.js";

/**
 * QueenCalifia v2 — Premium SOC Dashboard (single-file component)
 *
 * Security: persists only non-sensitive preferences (API base, polling interval, density).
 * API key remains in-memory only.
 */

function makeRequestId() {
  try {
    if (typeof crypto !== "undefined" && crypto.randomUUID) return crypto.randomUUID();
  } catch {}
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function clampInt(value, min, max, fallback) {
  const n = Number.parseInt(String(value || ""), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function useLocalStorageState(key, initialValue) {
  const [v, setV] = useState(() => {
    try {
      const raw = localStorage.getItem(key);
      if (raw == null) return initialValue;
      return JSON.parse(raw);
    } catch {
      return initialValue;
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem(key, JSON.stringify(v));
    } catch {}
  }, [key, v]);

  return [v, setV];
}

const T = {
  void: "#060a12",
  bg: "#0a0f1a",
  panel: "#0d1322",
  panelHover: "#111b2e",
  border: "#151f35",
  borderLit: "#1e3a5f",
  borderHot: "#2563eb",
  text: "#d4dced",
  textSoft: "#8aa0bf",
  textDim: "#5c7394",
  accent: "#2563eb",
  accentGlow: "rgba(37,99,235,0.12)",
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "#16a34a",
  ok: "#059669",
  info: "#0891b2",
  warn: "#f59e0b",
};

const FONT_MONO =
  "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace";
const FONT_UI =
  "ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, 'Apple Color Emoji', 'Segoe UI Emoji'";

const TABS = [
  { key: "command", label: "Command" },
  { key: "predict", label: "Predict" },
  { key: "hunt", label: "Hunt" },
  { key: "threats", label: "Threats" },
  { key: "incidents", label: "Incidents" },
];

function severityColor(sev) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return T.critical;
  if (s === "high") return T.high;
  if (s === "medium") return T.medium;
  if (s === "low") return T.low;
  return T.textDim;
}

function statusPillColor(status) {
  const s = String(status || "").toLowerCase();
  if (["open", "active", "investigating", "triage"].includes(s)) return T.warn;
  if (["contained", "mitigated", "in_progress"].includes(s)) return T.info;
  if (["resolved", "closed", "completed"].includes(s)) return T.ok;
  if (["denied", "failed"].includes(s)) return T.critical;
  return T.textDim;
}

function nowMs() {
  return Date.now();
}

function parseIsoMs(iso) {
  const t = Date.parse(iso || "");
  return Number.isFinite(t) ? t : null;
}

function withinWindow(iso, windowKey) {
  if (windowKey === "all") return true;
  const t = parseIsoMs(iso);
  if (!t) return true;
  const ageMs = nowMs() - t;
  const day = 24 * 60 * 60 * 1000;
  const map = { "1h": 60 * 60 * 1000, "24h": day, "7d": 7 * day, "30d": 30 * day };
  const lim = map[windowKey] ?? null;
  if (!lim) return true;
  return ageMs <= lim;
}

function uniq(arr) {
  return Array.from(new Set(arr.filter(Boolean)));
}

function safeJson(obj) {
  try {
    return JSON.stringify(obj, null, 2);
  } catch {
    return JSON.stringify({ error: "unserializable" }, null, 2);
  }
}

function downloadText(filename, text) {
  const blob = new Blob([text], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function TechniqueChip({ technique, why, density }) {
  const id = technique?.id || technique?.technique_id || technique?.technique || "";
  const name = technique?.name || technique?.technique_name || "";
  const tactic = technique?.tactic || technique?.tactics || "";

  const href = id ? `https://attack.mitre.org/techniques/${id.replace(/^T/, "T")}/` : null;

  const chip = (
    <span
      title={why ? `${id} ${name}\n\nWhy: ${why}` : `${id} ${name}`}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 8,
        borderRadius: 999,
        border: `1px solid ${T.border}`,
        background: T.panel,
        padding: density === "compact" ? "4px 10px" : "6px 12px",
        fontFamily: FONT_MONO,
        fontSize: density === "compact" ? 12 : 13,
        color: T.text,
        cursor: href ? "pointer" : "default",
        userSelect: "none",
      }}
      onClick={() => {
        if (href) window.open(href, "_blank", "noopener,noreferrer");
      }}
    >
      <span style={{ color: T.textSoft }}>{id || "MITRE"}</span>
      <span style={{ color: T.textDim }}>{tactic ? `· ${tactic}` : ""}</span>
    </span>
  );

  return chip;
}

function Banner({ kind, title, body, actionLabel, onAction }) {
  const c =
    kind === "error" ? T.critical : kind === "warn" ? T.warn : kind === "info" ? T.info : T.accent;

const evidenceDialog = (
  <Modal
    open={evidenceModalOpen}
    title="Add evidence artifact"
    onClose={() => setEvidenceModalOpen(false)}
    footer={
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 10 }}>
        <button
          onClick={() => setEvidenceModalOpen(false)}
          style={{
            border: `1px solid ${T.border}`,
            background: "transparent",
            color: T.textSoft,
            borderRadius: 12,
            padding: "10px 12px",
            fontFamily: FONT_UI,
            fontSize: 13,
            cursor: "pointer",
          }}
        >
          Cancel
        </button>
        <button
          onClick={submitEvidence}
          style={{
            border: `1px solid ${T.borderLit}`,
            background: "rgba(34,197,94,0.12)",
            color: T.text,
            borderRadius: 12,
            padding: "10px 12px",
            fontFamily: FONT_UI,
            fontSize: 13,
            cursor: "pointer",
            fontWeight: 800,
          }}
        >
          Add
        </button>
      </div>
    }
  >
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
      <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        <span style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textDim }}>Type</span>
        <input
          value={evidenceDraft.evidence_type}
          onChange={(e) => setEvidenceDraft((p) => ({ ...p, evidence_type: e.target.value }))}
          placeholder="pcap | log | screenshot | artifact"
          style={{
            border: `1px solid ${T.border}`,
            background: "rgba(255,255,255,0.03)",
            color: T.text,
            borderRadius: 12,
            padding: "10px 10px",
            fontFamily: FONT_MONO,
            fontSize: 12,
            outline: "none",
          }}
        />
      </label>

      <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        <span style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textDim }}>Source</span>
        <input
          value={evidenceDraft.source}
          onChange={(e) => setEvidenceDraft((p) => ({ ...p, source: e.target.value }))}
          placeholder="sensor / analyst / system"
          style={{
            border: `1px solid ${T.border}`,
            background: "rgba(255,255,255,0.03)",
            color: T.text,
            borderRadius: 12,
            padding: "10px 10px",
            fontFamily: FONT_UI,
            fontSize: 13,
            outline: "none",
          }}
        />
      </label>

      <label style={{ display: "flex", flexDirection: "column", gap: 6, gridColumn: "1 / -1" }}>
        <span style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textDim }}>Storage location</span>
        <input
          value={evidenceDraft.storage_location}
          onChange={(e) => setEvidenceDraft((p) => ({ ...p, storage_location: e.target.value }))}
          placeholder="s3://bucket/path | /vault/case/.. | ticket://.."
          style={{
            border: `1px solid ${T.border}`,
            background: "rgba(255,255,255,0.03)",
            color: T.text,
            borderRadius: 12,
            padding: "10px 10px",
            fontFamily: FONT_MONO,
            fontSize: 12,
            outline: "none",
          }}
        />
      </label>

      <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        <span style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textDim }}>SHA-256 hash</span>
        <input
          value={evidenceDraft.hash_sha256}
          onChange={(e) => setEvidenceDraft((p) => ({ ...p, hash_sha256: e.target.value }))}
          placeholder="hex digest"
          style={{
            border: `1px solid ${T.border}`,
            background: "rgba(255,255,255,0.03)",
            color: T.text,
            borderRadius: 12,
            padding: "10px 10px",
            fontFamily: FONT_MONO,
            fontSize: 12,
            outline: "none",
          }}
        />
      </label>

      <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        <span style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textDim }}>Size (bytes)</span>
        <input
          value={evidenceDraft.size_bytes}
          onChange={(e) => setEvidenceDraft((p) => ({ ...p, size_bytes: e.target.value }))}
          placeholder="0"
          inputMode="numeric"
          style={{
            border: `1px solid ${T.border}`,
            background: "rgba(255,255,255,0.03)",
            color: T.text,
            borderRadius: 12,
            padding: "10px 10px",
            fontFamily: FONT_MONO,
            fontSize: 12,
            outline: "none",
          }}
        />
      </label>

      <label style={{ display: "flex", flexDirection: "column", gap: 6, gridColumn: "1 / -1" }}>
        <span style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textDim }}>Notes</span>
        <textarea
          value={evidenceDraft.notes}
          onChange={(e) => setEvidenceDraft((p) => ({ ...p, notes: e.target.value }))}
          placeholder="Chain-of-custody notes, acquisition method, context…"
          rows={4}
          style={{
            border: `1px solid ${T.border}`,
            background: "rgba(255,255,255,0.03)",
            color: T.text,
            borderRadius: 12,
            padding: "10px 10px",
            fontFamily: FONT_UI,
            fontSize: 13,
            outline: "none",
            resize: "vertical",
          }}
        />
      </label>
    </div>

    <div style={{ marginTop: 10, fontFamily: FONT_UI, fontSize: 12, color: T.textDim, lineHeight: 1.35 }}>
      Tip: hashes + immutable storage location make evidence audit-friendly.
    </div>
  </Modal>
);

  return (
    <div
      style={{
        border: `1px solid ${c}`,
        background: "rgba(0,0,0,0.22)",
        borderRadius: 14,
        padding: "10px 12px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 12,
      }}
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
        <div style={{ fontFamily: FONT_UI, fontSize: 14, color: T.text, fontWeight: 650 }}>
          {title}
        </div>
        {body ? (
          <div style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textSoft, lineHeight: 1.3 }}>
            {body}
          </div>
        ) : null}
      </div>
      {actionLabel ? (
        <button
          onClick={onAction}
          style={{
            border: `1px solid ${c}`,
            background: "transparent",
            color: T.text,
            borderRadius: 12,
            padding: "8px 10px",
            fontFamily: FONT_UI,
            fontSize: 13,
            cursor: "pointer",
            whiteSpace: "nowrap",
          }}
        >
          {actionLabel}
        </button>
      ) : null}
    </div>
  );
}

function Modal({ open, title, children, onClose, footer }) {
  if (!open) return null;
  return (
    <div
      role="dialog"
      aria-modal="true"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.55)",
        display: "grid",
        placeItems: "center",
        zIndex: 1000,
        padding: 18,
      }}
    >
      <div
        style={{
          width: "min(720px, 100%)",
          borderRadius: 20,
          border: `1px solid ${T.borderLit}`,
          background: T.panel,
          boxShadow: "0 20px 60px rgba(0,0,0,0.55)",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            padding: "14px 16px",
            borderBottom: `1px solid ${T.border}`,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 10,
          }}
        >
          <div style={{ fontFamily: FONT_UI, fontSize: 15, color: T.text, fontWeight: 700 }}>
            {title}
          </div>
          <button
            onClick={onClose}
            style={{
              border: `1px solid ${T.border}`,
              background: "transparent",
              color: T.textSoft,
              borderRadius: 12,
              padding: "6px 10px",
              fontFamily: FONT_UI,
              cursor: "pointer",
            }}
          >
            Close
          </button>
        </div>
        <div style={{ padding: 16 }}>{children}</div>
        {footer ? (
          <div style={{ padding: 16, borderTop: `1px solid ${T.border}` }}>{footer}</div>
        ) : null}
      </div>
    </div>
  );
}

function Skeleton({ h = 14, w = "100%", r = 12 }) {
  return (
    <div
      style={{
        height: h,
        width: w,
        borderRadius: r,
        background:
          "linear-gradient(90deg, rgba(255,255,255,0.05), rgba(255,255,255,0.10), rgba(255,255,255,0.05))",
        backgroundSize: "200% 100%",
        animation: "qc_skeleton 1.25s ease-in-out infinite",
      }}
    />
  );
}

function StepPill({ label, active }) {
  return (
    <div
      style={{
        padding: "6px 10px",
        borderRadius: 999,
        border: `1px solid ${active ? T.borderHot : T.border}`,
        background: active ? "rgba(37,99,235,0.12)" : T.panel,
        color: active ? T.text : T.textSoft,
        fontFamily: FONT_UI,
        fontSize: 12,
        fontWeight: active ? 700 : 600,
        whiteSpace: "nowrap",
      }}
    >
      {label}
    </div>
  );
}

function inferLifecyclePhase(incident) {
  const s = String(incident?.status || "").toLowerCase();
  const actions = Array.isArray(incident?.response_actions) ? incident.response_actions : [];
  const hasPending = actions.some((a) => String(a.status || "").toLowerCase() === "pending");
  const hasCompleted = actions.some((a) => String(a.status || "").toLowerCase() === "completed");

  if (["resolved", "closed"].includes(s)) return "post";
  if (hasCompleted) return "recover";
  if (hasPending) return "contain";
  return "detect";
}

function formatIncidentSummary(inc) {
  const id = inc?.id || inc?.incident_id || "unknown";
  const title = inc?.title || inc?.name || "Incident";
  const sev = inc?.severity || "unknown";
  const status = inc?.status || "unknown";
  const created = inc?.created_at || inc?.created || null;

  const assets = uniq([...(inc?.assets || []), ...(inc?.hosts || []), ...(inc?.affected_assets || [])]);
  const iocs = uniq([...(inc?.iocs || []), ...(inc?.indicators || [])]);

  const mitre = Array.isArray(inc?.mitre) ? inc.mitre : [];
  const lines = [
    `Incident ${id}: ${title}`,
    `Severity: ${sev} | Status: ${status}`,
    created ? `Created: ${created}` : null,
    assets.length ? `Assets: ${assets.join(", ")}` : null,
    iocs.length ? `IOCs: ${iocs.join(", ")}` : null,
    mitre.length
      ? `MITRE: ${mitre
          .map((m) => `${m.id || m.technique_id || ""}${m.name ? ` (${m.name})` : ""}`)
          .filter(Boolean)
          .join(", ")}`
      : null,
  ].filter(Boolean);
  return lines.join("\n");
}

// ── Command Tab: Infrastructure & SPKI Pin Runbook Monitor ──────────────

function SpkiAttemptRow({ ev }) {
  const ok = ev.rc === 0;
  const color = ok ? T.low : ev.rc === 3 ? T.critical : ev.rc === 2 ? T.medium : T.high;
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "90px 60px 56px 80px 80px 1fr",
        gap: 6,
        padding: "5px 8px",
        fontSize: 12,
        fontFamily: FONT_MONO,
        borderBottom: `1px solid ${T.border}`,
        color: T.textSoft,
        alignItems: "center",
      }}
    >
      <span style={{ color: T.textDim }}>{ev.timestamp?.split("T")[1]?.replace("Z", "") || "—"}</span>
      <span style={{ color }}>rc={ev.rc}</span>
      <span>#{ev.attempt}</span>
      <span>{ev.scheduled_sleep_ms != null ? `${ev.scheduled_sleep_ms}ms` : "—"}</span>
      <span>{ev.elapsed_ms != null ? `${ev.elapsed_ms}ms` : "—"}</span>
      <span style={{ color: T.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {ev.target || "—"}
      </span>
    </div>
  );
}

function SpkiSummaryCard({ ev }) {
  const ok = ev.rc === 0;
  const dotColor = ok ? T.low : T.critical;
  return (
    <div
      style={{
        borderRadius: 14,
        border: `1px solid ${ok ? "rgba(74,222,128,0.18)" : "rgba(248,113,113,0.18)"}`,
        background: ok ? "rgba(74,222,128,0.04)" : "rgba(248,113,113,0.04)",
        padding: "10px 12px",
        display: "grid",
        gridTemplateColumns: "1fr 1fr 1fr 1fr",
        gap: 8,
        fontFamily: FONT_MONO,
        fontSize: 12,
      }}
    >
      <div>
        <div style={{ color: T.textDim, fontSize: 10, fontFamily: FONT_UI, fontWeight: 700, marginBottom: 2 }}>
          TARGET
        </div>
        <div style={{ color: T.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {ev.target || "—"}
        </div>
      </div>
      <div>
        <div style={{ color: T.textDim, fontSize: 10, fontFamily: FONT_UI, fontWeight: 700, marginBottom: 2 }}>
          RESULT
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <span style={{ width: 7, height: 7, borderRadius: "50%", background: dotColor, display: "inline-block" }} />
          <span style={{ color: dotColor }}>rc={ev.rc}</span>
        </div>
      </div>
      <div>
        <div style={{ color: T.textDim, fontSize: 10, fontFamily: FONT_UI, fontWeight: 700, marginBottom: 2 }}>
          ATTEMPTS / ELAPSED
        </div>
        <span style={{ color: T.text }}>{ev.attempts ?? "—"}</span>
        <span style={{ color: T.textDim }}> / </span>
        <span style={{ color: T.textSoft }}>{ev.elapsed_ms != null ? `${ev.elapsed_ms}ms` : "—"}</span>
      </div>
      <div>
        <div style={{ color: T.textDim, fontSize: 10, fontFamily: FONT_UI, fontWeight: 700, marginBottom: 2 }}>
          TIMESTAMP
        </div>
        <span style={{ color: T.textSoft }}>{ev.timestamp?.replace("T", " ").replace("Z", "") || "—"}</span>
      </div>
    </div>
  );
}

function CommandTab({ spkiLog, loadingSpki, onRefresh, ui }) {
  const hasSummaries = spkiLog.summaries.length > 0;
  const hasAttempts = spkiLog.attempts.length > 0;
  const lastSummary = hasSummaries ? spkiLog.summaries[spkiLog.summaries.length - 1] : null;
  const lastOk = lastSummary?.rc === 0;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {/* Infrastructure Health KPIs */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 10 }}>
        <div style={{ borderRadius: 18, border: `1px solid ${T.border}`, background: T.panel, padding: ui.pad, display: "flex", flexDirection: "column", gap: 6, minHeight: 78 }}>
          <div style={{ fontFamily: FONT_UI, fontSize: ui.textLabel, color: T.textSoft, fontWeight: 750 }}>SPKI Pin Status</div>
          <div style={{ fontFamily: FONT_MONO, fontSize: 18, fontWeight: 800, color: lastSummary ? (lastOk ? T.low : T.critical) : T.textDim }}>
            {lastSummary ? (lastOk ? "VERIFIED" : "FAILED") : "—"}
          </div>
          <div style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textDim }}>Last runbook result</div>
        </div>
        <div style={{ borderRadius: 18, border: `1px solid ${T.border}`, background: T.panel, padding: ui.pad, display: "flex", flexDirection: "column", gap: 6, minHeight: 78 }}>
          <div style={{ fontFamily: FONT_UI, fontSize: ui.textLabel, color: T.textSoft, fontWeight: 750 }}>Runbook Events</div>
          <div style={{ fontFamily: FONT_MONO, fontSize: 18, color: T.text, fontWeight: 800 }}>{spkiLog.total_events || 0}</div>
          <div style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textDim }}>Summary + attempt records</div>
        </div>
        <div style={{ borderRadius: 18, border: `1px solid ${T.border}`, background: T.panel, padding: ui.pad, display: "flex", flexDirection: "column", gap: 6, minHeight: 78 }}>
          <div style={{ fontFamily: FONT_UI, fontSize: ui.textLabel, color: T.textSoft, fontWeight: 750 }}>Last Target</div>
          <div style={{ fontFamily: FONT_MONO, fontSize: 14, color: T.text, fontWeight: 700, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {lastSummary?.target || "—"}
          </div>
          <div style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textDim }}>SIEM correlation target</div>
        </div>
        <div style={{ borderRadius: 18, border: `1px solid ${T.border}`, background: T.panel, padding: ui.pad, display: "flex", flexDirection: "column", gap: 6, minHeight: 78 }}>
          <div style={{ fontFamily: FONT_UI, fontSize: ui.textLabel, color: T.textSoft, fontWeight: 750 }}>Retry Attempts</div>
          <div style={{ fontFamily: FONT_MONO, fontSize: 18, color: hasAttempts ? T.warn : T.text, fontWeight: 800 }}>{spkiLog.attempts.length}</div>
          <div style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textDim }}>QC_SPKI_ATTEMPT_JSON records</div>
        </div>
      </div>

      {/* Runbook Summaries */}
      <div style={{ borderRadius: 18, border: `1px solid ${T.border}`, background: T.panel, overflow: "hidden" }}>
        <div style={{ padding: "12px 14px", borderBottom: `1px solid ${T.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ fontFamily: FONT_UI, fontSize: 14, fontWeight: 800, color: T.text }}>SPKI Pin Runbook — Summaries</div>
          <button
            onClick={onRefresh}
            style={{
              background: "rgba(37,99,235,0.10)",
              border: "1px solid rgba(37,99,235,0.25)",
              borderRadius: 8,
              color: T.accent,
              fontFamily: FONT_UI,
              fontSize: 12,
              fontWeight: 700,
              padding: "5px 12px",
              cursor: "pointer",
            }}
          >
            {loadingSpki ? "Loading…" : "Refresh"}
          </button>
        </div>
        <div style={{ padding: 12, display: "flex", flexDirection: "column", gap: 8, maxHeight: 260, overflow: "auto" }}>
          {hasSummaries ? (
            [...spkiLog.summaries].reverse().map((ev, i) => <SpkiSummaryCard key={i} ev={ev} />)
          ) : (
            <div style={{ fontFamily: FONT_UI, fontSize: 13, color: T.textDim, padding: "12px 0", lineHeight: 1.5 }}>
              No runbook summaries yet. Run{" "}
              <code style={{ fontFamily: FONT_MONO, background: "rgba(255,255,255,0.06)", padding: "2px 5px", borderRadius: 4, fontSize: 12 }}>
                make spki-pin-runbook URL=rediss://… --json --out data/spki.jsonl
              </code>{" "}
              with{" "}
              <code style={{ fontFamily: FONT_MONO, background: "rgba(255,255,255,0.06)", padding: "2px 5px", borderRadius: 4, fontSize: 12 }}>
                QC_SPKI_SUMMARY_JSON=1
              </code>{" "}
              to populate this panel. Target URL/host:port is included for SIEM correlation.
            </div>
          )}
        </div>
      </div>

      {/* Per-Attempt Retry Timeline */}
      <div style={{ borderRadius: 18, border: `1px solid ${T.border}`, background: T.panel, overflow: "hidden" }}>
        <div style={{ padding: "12px 14px", borderBottom: `1px solid ${T.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ fontFamily: FONT_UI, fontSize: 14, fontWeight: 800, color: T.text }}>Per-Attempt Retry Log</div>
          <div style={{ fontFamily: FONT_MONO, fontSize: 11, color: T.textDim }}>QC_SPKI_ATTEMPT_JSON={hasAttempts ? "1" : "0"}</div>
        </div>
        {hasAttempts ? (
          <div style={{ maxHeight: 240, overflow: "auto" }}>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "90px 60px 56px 80px 80px 1fr",
                gap: 6,
                padding: "6px 8px",
                fontSize: 10,
                fontFamily: FONT_UI,
                fontWeight: 800,
                color: T.textDim,
                borderBottom: `1px solid ${T.border}`,
                textTransform: "uppercase",
                letterSpacing: 0.5,
              }}
            >
              <span>Time</span><span>Result</span><span>Attempt</span><span>Sleep</span><span>Elapsed</span><span>Target</span>
            </div>
            {[...spkiLog.attempts].reverse().map((ev, i) => <SpkiAttemptRow key={i} ev={ev} />)}
          </div>
        ) : (
          <div style={{ padding: "16px 14px", fontFamily: FONT_UI, fontSize: 13, color: T.textDim, lineHeight: 1.5 }}>
            No per-attempt records. Set{" "}
            <code style={{ fontFamily: FONT_MONO, background: "rgba(255,255,255,0.06)", padding: "2px 5px", borderRadius: 4, fontSize: 12 }}>
              QC_SPKI_ATTEMPT_JSON=1
            </code>{" "}
            to emit one JSONL record per retry — each includes target, attempt number, return code,
            scheduled sleep, and wall-clock elapsed time for SIEM ingestion.
          </div>
        )}
      </div>
    </div>
  );
}

export default function QueenCalifiaV2Perfected() {
  // Non-sensitive preferences
  const [apiBase, setApiBase] = useLocalStorageState("QC_API_BASE", "");
  const [pollMs, setPollMs] = useLocalStorageState("QC_POLL_MS", 5000);
  const [density, setDensity] = useLocalStorageState("QC_UI_DENSITY", "compact");

  // Sensitive secret (in-memory only)
  const [apiKey, setApiKey] = useState("");

  const [tab, setTab] = useState("incidents");
  const [dashboard, setDashboard] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [incidentDetail, setIncidentDetail] = useState(null);
  const [evidenceItems, setEvidenceItems] = useState([]);
  const [loadingEvidence, setLoadingEvidence] = useState(false);

  const [loadingDash, setLoadingDash] = useState(false);
  const [loadingIncidents, setLoadingIncidents] = useState(false);
  const [loadingDetail, setLoadingDetail] = useState(false);

  const [degraded, setDegraded] = useState(false);
  const [lastError, setLastError] = useState(null);

  const [spkiLog, setSpkiLog] = useState({ summaries: [], attempts: [], total_events: 0 });
  const [loadingSpki, setLoadingSpki] = useState(false);

  const [settingsOpen, setSettingsOpen] = useState(false);
  const [reasonModal, setReasonModal] = useState({ open: false, kind: null, action: null });
  const [reasonText, setReasonText] = useState("");

  const [evidenceModalOpen, setEvidenceModalOpen] = useState(false);
  const [evidenceDraft, setEvidenceDraft] = useState({
    evidence_type: "artifact",
    source: "",
    storage_location: "",
    hash_sha256: "",
    size_bytes: "",
    notes: "",
  });

  const abortRef = useRef(new AbortController());
  const retryRef = useRef({ n: 0 });
  const pollRef = useRef(null);

  const baseUrl = useMemo(() => String(apiBase || "").replace(/\/+$/, ""), [apiBase]);

  const ui = useMemo(() => {
    const compact = density === "compact";
    return {
      compact,
      textBody: compact ? 13 : 14,
      textLabel: compact ? 12 : 12,
      pad: compact ? 10 : 12,
      rowH: compact ? 34 : 40,
    };
  }, [density]);

  const request = useCallback(
    async (path, opts = {}) => {
      const url = baseUrl ? `${baseUrl}${path}` : path;

      const maxRetries = 2;
      const backoffBase = 350;

      for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
        const reqId = makeRequestId();
        try {
          const res = await fetch(url, {
            ...opts,
            signal: abortRef.current.signal,
            headers: {
              "Content-Type": "application/json",
              "X-Request-ID": reqId,
              ...(apiKey ? { "X-QC-API-Key": apiKey } : {}),
              ...(opts.headers || {}),
            },
          });

          if (!res.ok) {
            const bodyText = await res.text().catch(() => "");
            const err = new Error(`HTTP ${res.status}`);
            err.status = res.status;
            err.body = bodyText;
            err.requestId = res.headers.get("X-Request-Id") || reqId;
            throw err;
          }

          const json = await res.json().catch(() => ({}));
          setDegraded(false);
          setLastError(null);
          retryRef.current.n = 0;
          return json;
        } catch (e) {
          // Abort -> rethrow immediately
          if (String(e?.name) === "AbortError") throw e;

          const status = e?.status || 0;

          // No retry for 401 (auth) or 403 (forbidden) or 400
          if ([400, 401, 403].includes(status)) {
            setDegraded(true);
            setLastError(e);
            throw e;
          }

          if (attempt === maxRetries) {
            setDegraded(true);
            setLastError(e);
            throw e;
          }

          await new Promise((r) => setTimeout(r, backoffBase * Math.pow(2, attempt)));
        }
      }
      return null;
    },
    [apiKey, baseUrl]
  );

  const loadDashboard = useCallback(async () => {
    setLoadingDash(true);
    try {
      const d = await request("/api/dashboard", { method: "GET" });
      setDashboard(d || null);
    } finally {
      setLoadingDash(false);
    }
  }, [request]);

  const loadIncidents = useCallback(async () => {
    setLoadingIncidents(true);
    try {
      const d = await request("/api/incidents", { method: "GET" });
      const list = Array.isArray(d?.incidents) ? d.incidents : Array.isArray(d) ? d : [];
      setIncidents(list);
    } finally {
      setLoadingIncidents(false);
    }
  }, [request]);

  const loadIncidentDetail = useCallback(
    async (id) => {
      if (!id) return;
      setLoadingDetail(true);
      try {
        const d = await request(`/api/incidents/${encodeURIComponent(id)}`, { method: "GET" });
        setIncidentDetail(d?.incident || d || null);
      } finally {
        setLoadingDetail(false);
      }
    },
    [request]
  );

  const loadEvidence = useCallback(
  async (id) => {
    if (!id) return;
    setLoadingEvidence(true);
    try {
      const d = await request(`/api/incidents/${encodeURIComponent(id)}/evidence`, { method: "GET" });
      const items = d?.data || d?.evidence || d || [];
      setEvidenceItems(Array.isArray(items) ? items : []);
    } catch {
      setEvidenceItems([]);
    } finally {
      setLoadingEvidence(false);
    }
  },
  [request]
);

const loadSpkiLog = useCallback(async () => {
  setLoadingSpki(true);
  try {
    const res = await request("/api/infra/spki-log?limit=200");
    if (res?.data) setSpkiLog(res.data);
  } catch {
    // endpoint may not exist yet — graceful degradation
  } finally {
    setLoadingSpki(false);
  }
}, [request]);

const openEvidenceModal = useCallback(() => {
  if (!selectedIncidentId) return;
  setEvidenceDraft({
    evidence_type: "artifact",
    source: "",
    storage_location: "",
    hash_sha256: "",
    size_bytes: "",
    notes: "",
  });
  setEvidenceModalOpen(true);
}, [selectedIncidentId]);

const submitEvidence = useCallback(async () => {
  if (!selectedIncidentId) return;

  const payload = {
    evidence_type: String(evidenceDraft.evidence_type || "").slice(0, 64),
    source: String(evidenceDraft.source || "").slice(0, 128),
    storage_location: String(evidenceDraft.storage_location || "").slice(0, 512),
    hash_sha256: String(evidenceDraft.hash_sha256 || "").trim().slice(0, 128),
    size_bytes: Number(evidenceDraft.size_bytes || 0) || 0,
    notes: String(evidenceDraft.notes || "").slice(0, 2048),
  };

  const { tempId, optimistic } = createOptimisticEvidence(payload);

  setEvidenceItems((prev) => [optimistic, ...(Array.isArray(prev) ? prev : [])]);
  setEvidenceModalOpen(false);

  try {
    const r = await request(`/api/incidents/${encodeURIComponent(selectedIncidentId)}/evidence`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const created = r?.data || r;
    if (!created?.evidence_id) throw new Error("Invalid evidence response");

    setEvidenceItems((prev) => replaceOptimisticEvidence(prev, tempId, created));
  } catch (e) {
    setEvidenceItems((prev) => rollbackOptimisticEvidence(prev, tempId));
    setLastError(e instanceof Error ? e : new Error(String(e?.message || "Failed to add evidence")));
    setDegraded(true);
  }
}, [selectedIncidentId, evidenceDraft, request]);

  const refreshAll = useCallback(async () => {
    await Promise.allSettled([loadDashboard(), loadIncidents()]);
  }, [loadDashboard, loadIncidents]);

  useEffect(() => {
    // initial load
    refreshAll().catch(() => {});
  }, [refreshAll]);

  useEffect(() => {
    // polling
    if (pollRef.current) clearInterval(pollRef.current);
    const ms = clampInt(pollMs, 1000, 60000, 5000);
    pollRef.current = setInterval(() => {
      refreshAll().catch(() => {});
    }, ms);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [pollMs, refreshAll]);

  useEffect(() => {
    setPollMs((v) => clampInt(v, 1000, 60000, 5000));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    // keep detail in sync
    if (!selectedIncidentId) {
      setIncidentDetail(null);
      return;
    }
    loadIncidentDetail(selectedIncidentId).catch(() => {});
    loadEvidence(selectedIncidentId).catch(() => {});
  }, [selectedIncidentId, loadIncidentDetail, loadEvidence]);

  useEffect(() => {
    return () => {
      try {
        abortRef.current.abort();
      } catch {}
    };
  }, []);

  useEffect(() => {
    if (tab === "command") loadSpkiLog().catch(() => {});
  }, [tab, loadSpkiLog]);

  // Global search + quick filters (reduce triage time)
  const [q, setQ] = useState("");
  const [sevFilter, setSevFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [timeWindow, setTimeWindow] = useState("24h");

  const filteredIncidents = useMemo(() => {
    const needle = String(q || "").trim().toLowerCase();
    return (incidents || []).filter((inc) => {
      const sev = String(inc?.severity || "").toLowerCase();
      const st = String(inc?.status || "").toLowerCase();

      if (sevFilter !== "all" && sev !== sevFilter) return false;
      if (statusFilter !== "all" && st !== statusFilter) return false;

      const created = inc?.created_at || inc?.created || inc?.first_seen || null;
      if (timeWindow && !withinWindow(created, timeWindow)) return false;

      if (!needle) return true;

      const blob = [
        inc?.id,
        inc?.incident_id,
        inc?.title,
        inc?.name,
        inc?.summary,
        inc?.description,
        ...(inc?.assets || []),
        ...(inc?.hosts || []),
        ...(inc?.iocs || []),
        ...(inc?.indicators || []),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      return blob.includes(needle);
    });
  }, [incidents, q, sevFilter, statusFilter, timeWindow]);

  const actionCenter = useMemo(() => {
    const items = [];
    for (const inc of incidents || []) {
      const actions = Array.isArray(inc?.response_actions) ? inc.response_actions : [];
      for (const a of actions) {
        if (a?.requires_approval && String(a?.status || "").toLowerCase() === "pending") {
          items.push({
            incidentId: inc?.id || inc?.incident_id,
            incidentTitle: inc?.title || inc?.name || "Incident",
            actionId: a?.id,
            actionName: a?.name || a?.action || "Action",
            severity: inc?.severity || "unknown",
          });
        }
      }
    }
    return {
      pendingApprovals: items,
    };
  }, [incidents]);

  const openReason = useCallback((kind, action) => {
    setReasonText("");
    setReasonModal({ open: true, kind, action });
  }, []);

  const closeReason = useCallback(() => {
    setReasonModal({ open: false, kind: null, action: null });
    setReasonText("");
  }, []);

  const mutateActionOptimistic = useCallback(
    (actionId, patch) => {
      setIncidentDetail((prev) => {
        if (!prev) return prev;
        const actions = Array.isArray(prev.response_actions) ? prev.response_actions : [];
        return {
          ...prev,
          response_actions: actions.map((a) => (a?.id === actionId ? { ...a, ...patch } : a)),
        };
      });
      setIncidents((prev) =>
        (prev || []).map((inc) => {
          const iid = inc?.id || inc?.incident_id;
          if (iid !== selectedIncidentId) return inc;
          const actions = Array.isArray(inc.response_actions) ? inc.response_actions : [];
          return {
            ...inc,
            response_actions: actions.map((a) => (a?.id === actionId ? { ...a, ...patch } : a)),
          };
        })
      );
    },
    [selectedIncidentId]
  );

  const doAction = useCallback(
    async (kind, action) => {
      const incidentId = selectedIncidentId;
      if (!incidentId || !action?.id) return;

      const actionId = action.id;

      const endpoint =
        kind === "approve"
          ? `/api/incidents/${encodeURIComponent(incidentId)}/approve/${encodeURIComponent(actionId)}`
          : kind === "deny"
            ? `/api/incidents/${encodeURIComponent(incidentId)}/deny/${encodeURIComponent(actionId)}`
            : `/api/incidents/${encodeURIComponent(incidentId)}/rollback/${encodeURIComponent(actionId)}`;

      const before = JSON.parse(JSON.stringify(action));
      const optimisticPatch =
        kind === "approve"
          ? { status: "in_progress" }
          : kind === "deny"
            ? { status: "denied", denied_reason: reasonText || "operator denied" }
            : { status: "rolling_back" };

      mutateActionOptimistic(actionId, optimisticPatch);

      try {
        await request(endpoint, {
          method: "POST",
          body: JSON.stringify(reasonText ? { reason: reasonText } : {}),
        });
        await loadIncidentDetail(incidentId);
        await loadIncidents();
      } catch (e) {
        // rollback optimistic UI
        mutateActionOptimistic(actionId, before);
        setLastError(e);
        setDegraded(true);
      }
    },
    [loadIncidentDetail, loadIncidents, mutateActionOptimistic, reasonText, request, selectedIncidentId]
  );

  const kpis = useMemo(() => {
    const d = dashboard || {};
    return {
      mttd: d?.kpis?.mttd_minutes ?? d?.mttd_minutes ?? null,
      mttr: d?.kpis?.mttr_minutes ?? d?.mttr_minutes ?? null,
      openIncidents: d?.kpis?.open_incidents ?? d?.open_incidents ?? null,
      activeThreats: d?.kpis?.active_threats ?? d?.active_threats ?? null,
    };
  }, [dashboard]);

  const selectedIncident = useMemo(() => {
    if (!selectedIncidentId) return null;
    return incidents.find((i) => (i?.id || i?.incident_id) === selectedIncidentId) || null;
  }, [incidents, selectedIncidentId]);

  const detail = incidentDetail || selectedIncident;

  const lifecycle = useMemo(() => inferLifecyclePhase(detail), [detail]);

  const copyIncidentSummary = useCallback(() => {
    if (!detail) return;
    const text = formatIncidentSummary(detail);
    try {
      navigator.clipboard.writeText(text);
    } catch {
      // best effort fallback
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    }
  }, [detail]);

  const exportIncidentJson = useCallback(() => {
    if (!detail) return;
    const id = detail?.id || detail?.incident_id || "incident";
    downloadText(`incident_${id}.json`, safeJson(detail));
  }, [detail]);

  const exportIncidentListJson = useCallback(() => {
    downloadText(`incidents_export.json`, safeJson({ incidents }));
  }, [incidents]);

  const topBar = (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {degraded && lastError ? (
        <Banner
          kind={lastError.status === 401 ? "warn" : "error"}
          title={lastError.status === 401 ? "Authentication required" : "Degraded mode"}
          body={
            lastError.status === 401
              ? "Add an API key in Settings to access protected endpoints."
              : `Latest error: ${lastError.message || "request failed"}`
          }
          actionLabel="Fix connection"
          onAction={() => setSettingsOpen(true)}
        />
      ) : null}

      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
          padding: "12px 14px",
          borderRadius: 18,
          border: `1px solid ${T.border}`,
          background: T.panel,
        }}
      >
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <div style={{ fontFamily: FONT_UI, color: T.text, fontSize: 16, fontWeight: 800 }}>
            Queen Califia SOC
          </div>
          <div style={{ fontFamily: FONT_MONO, color: T.textDim, fontSize: 12 }}>
            Request-ID correlation · Tail-sampled traces · Defense-grade audit
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <button
            onClick={() => refreshAll().catch(() => {})}
            style={{
              border: `1px solid ${T.borderLit}`,
              background: "transparent",
              color: T.text,
              borderRadius: 12,
              padding: "8px 10px",
              fontFamily: FONT_UI,
              fontSize: 13,
              cursor: "pointer",
            }}
          >
            Refresh
          </button>
          <button
            onClick={() => setSettingsOpen(true)}
            style={{
              border: `1px solid ${T.borderHot}`,
              background: "rgba(37,99,235,0.10)",
              color: T.text,
              borderRadius: 12,
              padding: "8px 10px",
              fontFamily: FONT_UI,
              fontSize: 13,
              cursor: "pointer",
            }}
          >
            Settings
          </button>
        </div>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr auto auto auto auto",
          gap: 10,
          padding: "10px 12px",
          borderRadius: 18,
          border: `1px solid ${T.border}`,
          background: T.panel,
        }}
      >
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <div style={{ fontFamily: FONT_UI, fontSize: ui.textLabel, color: T.textSoft, fontWeight: 700 }}>
            Global search
          </div>
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="IOC • IP • hostname • incident ID"
            style={{
              width: "100%",
              height: ui.rowH,
              borderRadius: 12,
              border: `1px solid ${T.borderLit}`,
              background: T.bg,
              color: T.text,
              fontFamily: FONT_UI,
              fontSize: ui.textBody,
              padding: "0 12px",
              outline: "none",
            }}
          />
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <div style={{ fontFamily: FONT_UI, fontSize: ui.textLabel, color: T.textSoft, fontWeight: 700 }}>
            Severity
          </div>
          <select
            value={sevFilter}
            onChange={(e) => setSevFilter(e.target.value)}
            style={{
              height: ui.rowH,
              borderRadius: 12,
              border: `1px solid ${T.border}`,
              background: T.bg,
              color: T.text,
              fontFamily: FONT_UI,
              fontSize: ui.textBody,
              padding: "0 10px",
              outline: "none",
              minWidth: 150,
            }}
          >
            <option value="all">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <div style={{ fontFamily: FONT_UI, fontSize: ui.textLabel, color: T.textSoft, fontWeight: 700 }}>
            Status
          </div>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            style={{
              height: ui.rowH,
              borderRadius: 12,
              border: `1px solid ${T.border}`,
              background: T.bg,
              color: T.text,
              fontFamily: FONT_UI,
              fontSize: ui.textBody,
              padding: "0 10px",
              outline: "none",
              minWidth: 150,
            }}
          >
            <option value="all">All</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="contained">Contained</option>
            <option value="resolved">Resolved</option>
          </select>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <div style={{ fontFamily: FONT_UI, fontSize: ui.textLabel, color: T.textSoft, fontWeight: 700 }}>
            Time
          </div>
          <select
            value={timeWindow}
            onChange={(e) => setTimeWindow(e.target.value)}
            style={{
              height: ui.rowH,
              borderRadius: 12,
              border: `1px solid ${T.border}`,
              background: T.bg,
              color: T.text,
              fontFamily: FONT_UI,
              fontSize: ui.textBody,
              padding: "0 10px",
              outline: "none",
              minWidth: 130,
            }}
          >
            <option value="1h">1 hour</option>
            <option value="24h">24 hours</option>
            <option value="7d">7 days</option>
            <option value="30d">30 days</option>
            <option value="all">All time</option>
          </select>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <div style={{ fontFamily: FONT_UI, fontSize: ui.textLabel, color: T.textSoft, fontWeight: 700 }}>
            Density
          </div>
          <button
            onClick={() => setDensity((d) => (d === "compact" ? "comfortable" : "compact"))}
            style={{
              height: ui.rowH,
              borderRadius: 12,
              border: `1px solid ${T.borderHot}`,
              background: density === "compact" ? "rgba(37,99,235,0.08)" : "rgba(255,255,255,0.04)",
              color: T.text,
              fontFamily: FONT_UI,
              fontSize: ui.textBody,
              cursor: "pointer",
              padding: "0 10px",
            }}
            title="Toggle Compact / Comfortable"
          >
            {density === "compact" ? "Compact" : "Comfortable"}
          </button>
        </div>
      </div>
    </div>
  );

  const leftNav = (
    <div
      style={{
        borderRadius: 18,
        border: `1px solid ${T.border}`,
        background: T.panel,
        padding: 10,
        display: "flex",
        flexDirection: "column",
        gap: 8,
      }}
    >
      {TABS.map((t) => {
        const active = tab === t.key;
        return (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            style={{
              textAlign: "left",
              borderRadius: 14,
              padding: "10px 12px",
              border: `1px solid ${active ? T.borderHot : T.border}`,
              background: active ? "rgba(37,99,235,0.10)" : "transparent",
              color: active ? T.text : T.textSoft,
              fontFamily: FONT_UI,
              fontSize: 14,
              fontWeight: active ? 800 : 650,
              cursor: "pointer",
            }}
          >
            {t.label}
          </button>
        );
      })}
      <div style={{ height: 10 }} />
      <button
        onClick={exportIncidentListJson}
        style={{
          textAlign: "left",
          borderRadius: 14,
          padding: "10px 12px",
          border: `1px solid ${T.border}`,
          background: "transparent",
          color: T.textSoft,
          fontFamily: FONT_UI,
          fontSize: 13,
          cursor: "pointer",
        }}
        title="Audit-friendly export"
      >
        Export Incidents JSON
      </button>
    </div>
  );

  function KpiCard({ label, value, hint }) {
    return (
      <div
        style={{
          borderRadius: 18,
          border: `1px solid ${T.border}`,
          background: T.panel,
          padding: ui.pad,
          display: "flex",
          flexDirection: "column",
          gap: 6,
          minHeight: 78,
        }}
      >
        <div style={{ fontFamily: FONT_UI, fontSize: ui.textLabel, color: T.textSoft, fontWeight: 750 }}>
          {label}
        </div>
        {loadingDash ? (
          <Skeleton h={18} w="55%" />
        ) : (
          <div style={{ fontFamily: FONT_MONO, fontSize: 18, color: T.text, fontWeight: 800 }}>
            {value ?? "—"}
          </div>
        )}
        {hint ? (
          <div style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textDim, lineHeight: 1.2 }}>{hint}</div>
        ) : null}
      </div>
    );
  }

  const incidentList = (
    <div
      style={{
        borderRadius: 18,
        border: `1px solid ${T.border}`,
        background: T.panel,
        overflow: "hidden",
      }}
    >
      <div
        style={{
          padding: "12px 12px",
          borderBottom: `1px solid ${T.border}`,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 10,
        }}
      >
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <div style={{ fontFamily: FONT_UI, fontSize: 15, color: T.text, fontWeight: 800 }}>Incidents</div>
          <div style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textDim }}>
            {filteredIncidents.length} shown · {incidents.length} total
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textSoft }}>
            {loadingIncidents ? "Updating…" : "Live"}
          </div>
          <div
            style={{
              width: 8,
              height: 8,
              borderRadius: 999,
              background: degraded ? T.warn : T.ok,
              boxShadow: degraded ? `0 0 0 4px rgba(245,158,11,0.12)` : `0 0 0 4px rgba(5,150,105,0.12)`,
            }}
            title={degraded ? "Degraded" : "Connected"}
          />
        </div>
      </div>

      <div style={{ maxHeight: 420, overflow: "auto" }}>
        {(loadingIncidents && incidents.length === 0 ? new Array(6).fill(null) : filteredIncidents).map(
          (inc, idx) => {
            if (!inc) {
              return (
                <div
                  key={`sk-${idx}`}
                  style={{
                    padding: "10px 12px",
                    borderBottom: `1px solid ${T.border}`,
                    display: "grid",
                    gridTemplateColumns: "160px 1fr 110px 120px",
                    gap: 10,
                    alignItems: "center",
                  }}
                >
                  <Skeleton h={14} w="75%" />
                  <Skeleton h={14} w="90%" />
                  <Skeleton h={14} w="70%" />
                  <Skeleton h={14} w="70%" />
                </div>
              );
            }

            const id = inc?.id || inc?.incident_id || `#${idx + 1}`;
            const title = inc?.title || inc?.name || "Incident";
            const sev = String(inc?.severity || "unknown").toLowerCase();
            const st = String(inc?.status || "unknown").toLowerCase();
            const created = inc?.created_at || inc?.created || inc?.first_seen || "";

            const active = selectedIncidentId === (inc?.id || inc?.incident_id);

            return (
              <button
                key={id}
                onClick={() => setSelectedIncidentId(inc?.id || inc?.incident_id)}
                style={{
                  width: "100%",
                  textAlign: "left",
                  padding: "10px 12px",
                  border: "none",
                  borderBottom: `1px solid ${T.border}`,
                  background: active ? "rgba(37,99,235,0.10)" : "transparent",
                  display: "grid",
                  gridTemplateColumns: "160px 1fr 110px 120px",
                  gap: 10,
                  alignItems: "center",
                  cursor: "pointer",
                  color: T.text,
                  fontFamily: FONT_UI,
                }}
              >
                <div style={{ fontFamily: FONT_MONO, fontSize: 13, color: T.textSoft }}>{id}</div>
                <div style={{ fontSize: ui.textBody, fontWeight: 750, color: T.text }}>{title}</div>
                <div style={{ fontSize: 12, color: severityColor(sev), fontWeight: 800, textTransform: "uppercase" }}>
                  {sev}
                </div>
                <div
                  style={{
                    fontSize: 12,
                    color: T.text,
                    justifySelf: "end",
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                  }}
                >
                  <span
                    style={{
                      padding: "4px 10px",
                      borderRadius: 999,
                      border: `1px solid ${statusPillColor(st)}`,
                      color: T.text,
                      fontWeight: 750,
                    }}
                  >
                    {st}
                  </span>
                  <span style={{ color: T.textDim, fontSize: 12, fontFamily: FONT_MONO }}>
                    {created ? String(created).slice(0, 10) : "—"}
                  </span>
                </div>
              </button>
            );
          }
        )}
      </div>
    </div>
  );

  const incidentDetailPanel = (
    <div
      style={{
        borderRadius: 18,
        border: `1px solid ${T.border}`,
        background: T.panel,
        padding: 12,
        minHeight: 520,
        display: "flex",
        flexDirection: "column",
        gap: 10,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <div style={{ fontFamily: FONT_UI, fontSize: 15, color: T.text, fontWeight: 850 }}>
            Incident Detail
          </div>
          <div style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textDim }}>
            NIST lifecycle · audit-friendly actions · MITRE mapping
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <button
            onClick={copyIncidentSummary}
            disabled={!detail}
            style={{
              border: `1px solid ${T.border}`,
              background: "transparent",
              color: detail ? T.text : T.textDim,
              borderRadius: 12,
              padding: "8px 10px",
              fontFamily: FONT_UI,
              fontSize: 13,
              cursor: detail ? "pointer" : "not-allowed",
            }}
          >
            Copy Summary
          </button>
          <button
            onClick={exportIncidentJson}
            disabled={!detail}
            style={{
              border: `1px solid ${T.borderHot}`,
              background: "rgba(37,99,235,0.10)",
              color: detail ? T.text : T.textDim,
              borderRadius: 12,
              padding: "8px 10px",
              fontFamily: FONT_UI,
              fontSize: 13,
              cursor: detail ? "pointer" : "not-allowed",
            }}
          >
            Export JSON
          </button>
        </div>
      </div>

      {!detail ? (
        <div
          style={{
            borderRadius: 16,
            border: `1px dashed ${T.borderLit}`,
            padding: 14,
            color: T.textSoft,
            fontFamily: FONT_UI,
            fontSize: 13,
            lineHeight: 1.35,
          }}
        >
          Select an incident to view evidence, timeline, and response actions.
        </div>
      ) : (
        <>
          <div
            style={{
              borderRadius: 16,
              border: `1px solid ${T.border}`,
              background: T.bg,
              padding: 12,
              display: "flex",
              flexDirection: "column",
              gap: 8,
            }}
          >
            {loadingDetail ? <Skeleton h={18} w="60%" /> : null}
            <div style={{ display: "flex", flexWrap: "wrap", gap: 10, alignItems: "center" }}>
              <div style={{ fontFamily: FONT_MONO, fontSize: 13, color: T.textSoft }}>
                {detail?.id || detail?.incident_id}
              </div>
              <div style={{ fontFamily: FONT_UI, fontSize: 15, color: T.text, fontWeight: 850 }}>
                {detail?.title || detail?.name || "Incident"}
              </div>
              <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
                <span
                  style={{
                    padding: "4px 10px",
                    borderRadius: 999,
                    border: `1px solid ${severityColor(detail?.severity)}`,
                    fontFamily: FONT_UI,
                    fontSize: 12,
                    color: T.text,
                    fontWeight: 800,
                    textTransform: "uppercase",
                  }}
                >
                  {String(detail?.severity || "unknown")}
                </span>
                <span
                  style={{
                    padding: "4px 10px",
                    borderRadius: 999,
                    border: `1px solid ${statusPillColor(detail?.status)}`,
                    fontFamily: FONT_UI,
                    fontSize: 12,
                    color: T.text,
                    fontWeight: 800,
                  }}
                >
                  {String(detail?.status || "unknown")}
                </span>
              </div>
            </div>

            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              <StepPill label="Detection & Analysis" active={lifecycle === "detect"} />
              <StepPill label="Containment" active={lifecycle === "contain"} />
              <StepPill label="Recovery" active={lifecycle === "recover"} />
              <StepPill label="Post-Incident" active={lifecycle === "post"} />
            </div>

            {detail?.summary ? (
              <div style={{ fontFamily: FONT_UI, fontSize: ui.textBody, color: T.textSoft, lineHeight: 1.4 }}>
                {detail.summary}
              </div>
            ) : null}

            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              {(Array.isArray(detail?.mitre) ? detail.mitre : []).slice(0, 10).map((m, i) => (
                <TechniqueChip key={`${m?.id || m?.technique_id || i}`} technique={m} why={m?.why || m?.reason} density={density} />
              ))}
            </div>
          </div>

          <div
            style={{
              borderRadius: 16,
              border: `1px solid ${T.border}`,
              background: T.bg,
              padding: 12,
              display: "flex",
              flexDirection: "column",
              gap: 10,
            }}
          >
            <div style={{ fontFamily: FONT_UI, fontSize: 14, color: T.text, fontWeight: 850 }}>
              Response Actions
            </div>

            {Array.isArray(detail?.response_actions) && detail.response_actions.length ? (
              detail.response_actions.map((a) => {
                const st = String(a?.status || "unknown").toLowerCase();
                const canApprove = a?.requires_approval && st === "pending";
                const canDeny = a?.requires_approval && st === "pending";
                const canRollback = st === "completed" && Boolean(a?.rollback_action);

                return (
                  <div
                    key={a?.id}
                    style={{
                      borderRadius: 14,
                      border: `1px solid ${T.border}`,
                      background: T.panel,
                      padding: 10,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      gap: 10,
                    }}
                  >
                    <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                      <div style={{ fontFamily: FONT_UI, fontSize: 13, color: T.text, fontWeight: 800 }}>
                        {a?.name || a?.action || "Action"}
                      </div>
                      <div style={{ fontFamily: FONT_MONO, fontSize: 12, color: T.textDim }}>
                        {a?.id} {a?.rollback_action ? `· rollback: ${a.rollback_action}` : ""}
                      </div>
                    </div>

                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <span
                        style={{
                          padding: "4px 10px",
                          borderRadius: 999,
                          border: `1px solid ${statusPillColor(st)}`,
                          fontFamily: FONT_UI,
                          fontSize: 12,
                          color: T.text,
                          fontWeight: 800,
                        }}
                      >
                        {st}
                      </span>

                      {canApprove ? (
                        <button
                          onClick={() => openReason("approve", a)}
                          style={{
                            border: `1px solid ${T.borderHot}`,
                            background: "rgba(37,99,235,0.10)",
                            color: T.text,
                            borderRadius: 12,
                            padding: "8px 10px",
                            fontFamily: FONT_UI,
                            fontSize: 13,
                            cursor: "pointer",
                          }}
                        >
                          Approve
                        </button>
                      ) : null}

                      {canDeny ? (
                        <button
                          onClick={() => openReason("deny", a)}
                          style={{
                            border: `1px solid ${T.critical}`,
                            background: "rgba(220,38,38,0.10)",
                            color: T.text,
                            borderRadius: 12,
                            padding: "8px 10px",
                            fontFamily: FONT_UI,
                            fontSize: 13,
                            cursor: "pointer",
                          }}
                        >
                          Deny
                        </button>
                      ) : null}

                      {canRollback ? (
                        <button
                          onClick={() => openReason("rollback", a)}
                          style={{
                            border: `1px solid ${T.warn}`,
                            background: "rgba(245,158,11,0.10)",
                            color: T.text,
                            borderRadius: 12,
                            padding: "8px 10px",
                            fontFamily: FONT_UI,
                            fontSize: 13,
                            cursor: "pointer",
                          }}
                        >
                          Rollback
                        </button>
                      ) : null}
                    </div>
                  </div>
                );
              })
            ) : (
              <div style={{ fontFamily: FONT_UI, fontSize: 13, color: T.textSoft }}>
                No response actions for this incident.
              </div>
            )}
          </div>

          <div
            style={{
              borderRadius: 16,
              border: `1px solid ${T.border}`,
              background: T.bg,
              padding: 12,
              display: "flex",
              flexDirection: "column",
              gap: 8,
            }}
          >
            <div style={{ fontFamily: FONT_UI, fontSize: 14, color: T.text, fontWeight: 850 }}>
              Timeline / Evidence
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
              <div style={{ border: `1px solid ${T.border}`, borderRadius: 14, padding: 10, background: T.panel }}>
                <div style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textSoft, fontWeight: 750 }}>Assets</div>
                <div style={{ fontFamily: FONT_MONO, fontSize: 12, color: T.textDim, marginTop: 6 }}>
                  {uniq([...(detail?.assets || []), ...(detail?.hosts || []), ...(detail?.affected_assets || [])]).join(
                    ", "
                  ) || "—"}
                </div>
              </div>
              <div style={{ border: `1px solid ${T.border}`, borderRadius: 14, padding: 10, background: T.panel }}>
                <div style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textSoft, fontWeight: 750 }}>IOCs</div>
                <div style={{ fontFamily: FONT_MONO, fontSize: 12, color: T.textDim, marginTop: 6 }}>
                  {uniq([...(detail?.iocs || []), ...(detail?.indicators || [])]).join(", ") || "—"}
                </div>
              </div>
            </div>

<div style={{ border: `1px solid ${T.border}`, borderRadius: 14, padding: 10, background: T.panel }}>
  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
    <div style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textSoft, fontWeight: 750 }}>
      Evidence artifacts
    </div>
    <div style={{ fontFamily: FONT_MONO, fontSize: 12, color: T.textDim }}>
      {loadingEvidence ? "loading…" : `${(evidenceItems || []).length}`}
    </div>
  </div>

  <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 8, maxHeight: 180, overflow: "auto" }}>
    {loadingEvidence ? (
      <>
        <Skeleton h={14} />
        <Skeleton h={14} />
        <Skeleton h={14} />
      </>
    ) : evidenceItems?.length ? (
      evidenceItems.map((e) => (
        <div
          key={e?.evidence_id || Math.random()}
          style={{
            border: `1px solid ${T.border}`,
            borderRadius: 12,
            padding: 8,
            background: "rgba(255,255,255,0.03)",
            display: "flex",
            flexDirection: "column",
            gap: 6,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
            <div style={{ fontFamily: FONT_MONO, fontSize: 12, color: T.text }}>
              {e?.evidence_type || "evidence"}{" "}
              <span style={{ color: T.textDim }}>#{(e?.evidence_id || "").slice(-8)}</span>
            </div>
            {e?.tombstoned ? (
              <span
                style={{
                  fontFamily: FONT_UI,
                  fontSize: 11,
                  color: T.text,
                  background: "rgba(239,68,68,0.15)",
                  border: `1px solid ${T.bad}`,
                  padding: "2px 8px",
                  borderRadius: 999,
                }}
              >
                tombstoned
              </span>
            ) : null}
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
            <div style={{ fontFamily: FONT_UI, fontSize: 11, color: T.textDim }}>
              Source: <span style={{ color: T.textSoft }}>{e?.source || "—"}</span>
            </div>
            <div style={{ fontFamily: FONT_UI, fontSize: 11, color: T.textDim, overflow: "hidden", textOverflow: "ellipsis" }}>
              Hash: <span style={{ color: T.textSoft, fontFamily: FONT_MONO }}>{(e?.hash_sha256 || "—").slice(0, 18)}</span>
            </div>
            <div style={{ fontFamily: FONT_UI, fontSize: 11, color: T.textDim, gridColumn: "1 / -1" }}>
              Location:{" "}
              <span style={{ color: T.textSoft, fontFamily: FONT_MONO }}>
                {(e?.storage_location || "—").slice(0, 96)}
              </span>
            </div>
          </div>
        </div>
      ))
    ) : (
      <div style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textDim }}>
        No evidence artifacts attached yet.
      </div>
    )}
  </div>

  <div style={{ marginTop: 8, display: "flex", gap: 8, flexWrap: "wrap" }}>
    <button
  onClick={openEvidenceModal}
  style={{
    border: `1px solid ${T.border}`,
    background: "rgba(255,255,255,0.03)",
    color: T.text,
    borderRadius: 12,
    padding: "8px 10px",
    fontFamily: FONT_UI,
    fontSize: 13,
    cursor: "pointer",
  }}
>
  Add Evidence
</button>

<button
      onClick={() => copyToClipboard(JSON.stringify(evidenceItems || [], null, 2))}
      style={{
        border: `1px solid ${T.border}`,
        background: "rgba(255,255,255,0.03)",
        color: T.text,
        borderRadius: 12,
        padding: "8px 10px",
        fontFamily: FONT_UI,
        fontSize: 13,
        cursor: "pointer",
      }}
    >
      Export JSON
    </button>
    <button
      onClick={() => loadEvidence(selectedIncidentId)}
      style={{
        border: `1px solid ${T.border}`,
        background: "rgba(255,255,255,0.03)",
        color: T.text,
        borderRadius: 12,
        padding: "8px 10px",
        fontFamily: FONT_UI,
        fontSize: 13,
        cursor: "pointer",
      }}
    >
      Refresh
    </button>
  </div>
</div>


            <div style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textDim, lineHeight: 1.35 }}>
              Tip: use <span style={{ color: T.textSoft, fontWeight: 750 }}>Copy Summary</span> or{" "}
              <span style={{ color: T.textSoft, fontWeight: 750 }}>Export JSON</span> for audit-ready case notes.
            </div>
          </div>
        </>
      )}
    </div>
  );

  const actionRail = (
    <div
      style={{
        borderRadius: 18,
        border: `1px solid ${T.border}`,
        background: T.panel,
        padding: 12,
        display: "flex",
        flexDirection: "column",
        gap: 10,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
        <div style={{ fontFamily: FONT_UI, fontSize: 15, color: T.text, fontWeight: 850 }}>
          Action Center
        </div>
        <div style={{ fontFamily: FONT_MONO, fontSize: 12, color: T.textDim }}>
          {actionCenter.pendingApprovals.length} pending
        </div>
      </div>

      {actionCenter.pendingApprovals.length ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {actionCenter.pendingApprovals.slice(0, 6).map((p) => (
            <button
              key={`${p.incidentId}:${p.actionId}`}
              onClick={() => setSelectedIncidentId(p.incidentId)}
              style={{
                textAlign: "left",
                borderRadius: 14,
                border: `1px solid ${T.critical}`,
                background: "rgba(220,38,38,0.08)",
                padding: 10,
                cursor: "pointer",
                color: T.text,
                fontFamily: FONT_UI,
              }}
              title="Open incident to approve/deny"
            >
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
                <div style={{ fontSize: 13, fontWeight: 850 }}>
                  {p.actionName}
                </div>
                <div
                  style={{
                    fontFamily: FONT_UI,
                    fontSize: 12,
                    color: severityColor(p.severity),
                    fontWeight: 850,
                    textTransform: "uppercase",
                  }}
                >
                  {p.severity}
                </div>
              </div>
              <div style={{ fontFamily: FONT_MONO, fontSize: 12, color: T.textDim, marginTop: 4 }}>
                {p.incidentId} · {p.incidentTitle}
              </div>
            </button>
          ))}
        </div>
      ) : (
        <div
          style={{
            borderRadius: 16,
            border: `1px dashed ${T.borderLit}`,
            padding: 12,
            fontFamily: FONT_UI,
            fontSize: 13,
            color: T.textSoft,
            lineHeight: 1.35,
          }}
        >
          No approvals pending. You’re clear to hunt.
        </div>
      )}

      {degraded ? (
        <Banner
          kind="warn"
          title="Degraded connectivity"
          body="Polling is failing. Check API base, auth, and Redis health."
          actionLabel="Fix connection"
          onAction={() => setSettingsOpen(true)}
        />
      ) : null}
    </div>
  );

  const mainContent = (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {tab === "incidents" ? (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 10 }}>
            <KpiCard label="MTTD (minutes)" value={kpis.mttd} hint="Mean Time To Detect" />
            <KpiCard label="MTTR (minutes)" value={kpis.mttr} hint="Mean Time To Respond" />
            <KpiCard label="Open Incidents" value={kpis.openIncidents} hint="Active cases" />
            <KpiCard label="Active Threats" value={kpis.activeThreats} hint="Ongoing signals" />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1.15fr) minmax(0, 0.85fr)", gap: 10 }}>
            {incidentList}
            {incidentDetailPanel}
          </div>
        </>
      ) : tab === "command" ? (
        <CommandTab
          spkiLog={spkiLog}
          loadingSpki={loadingSpki}
          onRefresh={() => loadSpkiLog().catch(() => {})}
          T={T}
          ui={ui}
        />
      ) : (
        <div
          style={{
            borderRadius: 18,
            border: `1px solid ${T.border}`,
            background: T.panel,
            padding: 16,
            fontFamily: FONT_UI,
            color: T.textSoft,
            lineHeight: 1.4,
          }}
        >
          <div style={{ fontSize: 16, color: T.text, fontWeight: 850 }}>{TABS.find((t) => t.key === tab)?.label}</div>
          <div style={{ marginTop: 8 }}>
            This tab is reserved for expanded SOC workflows (playbooks, threat hunting queries, predictive analytics).
            The backend API is already wired for incident ops; expand this UI as you add endpoints.
          </div>
        </div>
      )}
    </div>
  );

  const settingsModal = (
    <Modal
      open={settingsOpen}
      title="Connection & Preferences"
      onClose={() => setSettingsOpen(false)}
      footer={
        <div style={{ display: "flex", justifyContent: "space-between", gap: 10, alignItems: "center" }}>
          <div style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textDim }}>
            API key is stored in-memory only (cleared on refresh).
          </div>
          <button
            onClick={() => {
              setSettingsOpen(false);
              refreshAll().catch(() => {});
            }}
            style={{
              border: `1px solid ${T.borderHot}`,
              background: "rgba(37,99,235,0.10)",
              color: T.text,
              borderRadius: 12,
              padding: "10px 12px",
              fontFamily: FONT_UI,
              fontSize: 13,
              cursor: "pointer",
            }}
          >
            Save & Refresh
          </button>
        </div>
      }
    >
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <div style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textSoft, fontWeight: 750 }}>
            API Base (optional)
          </div>
          <input
            value={apiBase}
            onChange={(e) => setApiBase(e.target.value)}
            placeholder="http://localhost:5000"
            style={{
              height: 40,
              borderRadius: 12,
              border: `1px solid ${T.borderLit}`,
              background: T.bg,
              color: T.text,
              fontFamily: FONT_UI,
              fontSize: 14,
              padding: "0 12px",
              outline: "none",
            }}
          />
          <div style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textDim, lineHeight: 1.3 }}>
            Leave blank for same-origin calls (`/api/...`).
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <div style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textSoft, fontWeight: 750 }}>
            Poll interval (ms)
          </div>
          <input
            value={pollMs}
            onChange={(e) => setPollMs(clampInt(e.target.value, 1000, 60000, 5000))}
            placeholder="5000"
            style={{
              height: 40,
              borderRadius: 12,
              border: `1px solid ${T.borderLit}`,
              background: T.bg,
              color: T.text,
              fontFamily: FONT_UI,
              fontSize: 14,
              padding: "0 12px",
              outline: "none",
            }}
          />
          <div style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textDim, lineHeight: 1.3 }}>
            1s–60s range.
          </div>
        </div>

        <div style={{ gridColumn: "1 / -1", display: "flex", flexDirection: "column", gap: 6 }}>
          <div style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textSoft, fontWeight: 750 }}>
            API Key (in-memory only)
          </div>
          <input
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder="X-QC-API-Key"
            style={{
              height: 40,
              borderRadius: 12,
              border: `1px solid ${T.border}`,
              background: T.bg,
              color: T.text,
              fontFamily: FONT_MONO,
              fontSize: 13,
              padding: "0 12px",
              outline: "none",
            }}
          />
          <div style={{ fontFamily: FONT_UI, fontSize: 12, color: T.textDim, lineHeight: 1.3 }}>
            Not persisted (safer). Provide a key if the API requires auth.
          </div>
        </div>
      </div>
    </Modal>
  );

  const reasonDialog = (
    <Modal
      open={reasonModal.open}
      title={
        reasonModal.kind === "approve"
          ? "Approve action"
          : reasonModal.kind === "deny"
            ? "Deny action"
            : "Rollback action"
      }
      onClose={closeReason}
      footer={
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 10 }}>
          <button
            onClick={closeReason}
            style={{
              border: `1px solid ${T.border}`,
              background: "transparent",
              color: T.textSoft,
              borderRadius: 12,
              padding: "10px 12px",
              fontFamily: FONT_UI,
              fontSize: 13,
              cursor: "pointer",
            }}
          >
            Cancel
          </button>
          <button
            onClick={async () => {
              const kind = reasonModal.kind;
              const action = reasonModal.action;
              closeReason();
              await doAction(kind, action);
            }}
            style={{
              border: `1px solid ${reasonModal.kind === "deny" ? T.critical : T.borderHot}`,
              background:
                reasonModal.kind === "deny"
                  ? "rgba(220,38,38,0.10)"
                  : "rgba(37,99,235,0.10)",
              color: T.text,
              borderRadius: 12,
              padding: "10px 12px",
              fontFamily: FONT_UI,
              fontSize: 13,
              cursor: "pointer",
            }}
          >
            Confirm
          </button>
        </div>
      }
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        <div style={{ fontFamily: FONT_UI, fontSize: 13, color: T.textSoft, lineHeight: 1.4 }}>
          Add an optional reason for audit trail. This will be attached to the action event.
        </div>
        <textarea
          value={reasonText}
          onChange={(e) => setReasonText(e.target.value)}
          placeholder="Reason (optional)…"
          rows={4}
          style={{
            width: "100%",
            borderRadius: 14,
            border: `1px solid ${T.border}`,
            background: T.bg,
            color: T.text,
            fontFamily: FONT_UI,
            fontSize: 14,
            padding: 12,
            outline: "none",
            resize: "vertical",
          }}
        />
        {reasonModal.action ? (
          <div style={{ fontFamily: FONT_MONO, fontSize: 12, color: T.textDim }}>
            {reasonModal.action.id} · {reasonModal.action.name || reasonModal.action.action || "Action"}
          </div>
        ) : null}
      </div>
    </Modal>
  );

  return (
    <div style={{ minHeight: "100vh", background: T.bg, padding: 14 }}>
      <style>{`
        @keyframes qc_skeleton {
          0% { background-position: 0% 50%; }
          100% { background-position: 200% 50%; }
        }
        * { box-sizing: border-box; }
      `}</style>

      <div style={{ maxWidth: 1400, margin: "0 auto", display: "flex", flexDirection: "column", gap: 10 }}>
        {topBar}

        <div style={{ display: "grid", gridTemplateColumns: "220px 1fr 320px", gap: 10, alignItems: "start" }}>
          {leftNav}
          {mainContent}
          {actionRail}
        </div>
      </div>

      {settingsModal}
      {reasonDialog}
      {evidenceDialog}
    </div>
  );
}
