import { useState, useEffect, useCallback, useRef, useMemo } from "react";

function makeRequestId() {
  try {
    if (typeof crypto !== "undefined" && crypto.randomUUID) return crypto.randomUUID();
  } catch {}
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}


// ═══════════════════════════════════════════════════════════════════════════
// QUEEN CALIFIA v2.0 — PREDICTIVE THREAT INTELLIGENCE DASHBOARD (PERFECTED)
// Tamerian Materials | Defense-Grade Cybersecurity AI
// ═══════════════════════════════════════════════════════════════════════════

const T = {
  void: "#060a12", bg: "#0a0f1a", panel: "#0d1322", panelHover: "#111b2e",
  border: "#151f35", borderLit: "#1e3a5f", borderHot: "#2563eb",
  text: "#d4dced", textSoft: "#7e92b0", textDim: "#4a5e7a",
  accent: "#2563eb", accentGlow: "rgba(37,99,235,0.12)",
  critical: "#dc2626", critGlow: "rgba(220,38,38,0.15)",
  high: "#ea580c", medium: "#ca8a04", low: "#16a34a",
  info: "#0891b2", success: "#059669", purple: "#7c3aed",
  gold: "#d97706", cyan: "#06b6d4", rose: "#e11d48",
  predict: "#8b5cf6", predictGlow: "rgba(139,92,246,0.12)",
  hunt: "#f59e0b", huntGlow: "rgba(245,158,11,0.10)",
};

const font = "'JetBrains Mono', 'Fira Code', 'SF Mono', monospace";

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function apiUrl(base, path) {
  if (!base) return path;
  return base.replace(/\/+$/, "") + path;
}

function formatAgo(iso) {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} hrs ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

async function fetchJsonWithRetry(url, { apiKey, method = "GET", body, timeoutMs = 8000, retries = 3 } = {}) {
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        method,
        headers: {
          "Content-Type": "application/json",
          "X-Request-ID": makeRequestId(),
          ...(apiKey ? { "X-QC-API-Key": apiKey } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
      const json = await res.json().catch(() => ({}));
      if (!res.ok) {
        const msg = json?.error || json?.message || `HTTP ${res.status}`;
        throw new Error(msg);
      }
      return json;
    } catch (e) {
      lastErr = e;
      const backoff = Math.min(4000, 250 * Math.pow(2, attempt)) + Math.floor(Math.random() * 120);
      await sleep(backoff);
    } finally {
      clearTimeout(timeout);
    }
  }
  throw lastErr || new Error("request failed");
}

function mapIncidents(apiIncidents) {
  if (!Array.isArray(apiIncidents)) return [];
  return apiIncidents.map(i => ({
    id: i.incident_id || i.id || "INC-UNKNOWN",
    title: i.title || "Incident",
    severity: String(i.severity || "MEDIUM").toUpperCase(),
    status: String(i.status || "investigating").toLowerCase(),
    actions: Array.isArray(i.response_actions) ? i.response_actions.length : (i.actions || 0),
    assets: Array.isArray(i.affected_assets) ? i.affected_assets.length : (i.assets || 0),
    created: i.created_at ? formatAgo(i.created_at) : (i.created || "—"),
    _raw: i,
  }));
}

function mergeBackendIntoIntel(predicted, dashboard, incidents) {
  const out = { ...predicted };

  const mappedInc = mapIncidents(incidents);
  if (mappedInc.length) out.incidents = mappedInc;

  const mesh = dashboard?.mesh;
  if (mesh) {
    const nodes = Array.isArray(out.meshNodes) ? out.meshNodes : [];
    const curTotal = nodes.reduce((s, n) => s + (n.events || 0), 0) || 1;
    const desired = Number(mesh.events_ingested || 0);
    const scale = desired > 0 ? desired / curTotal : 1;

    out.meshNodes = nodes.map(n => ({
      ...n,
      events: Math.max(0, Math.round((n.events || 0) * scale)),
      health: Math.max(0, Math.min(1, (n.health || 0.9) * (mesh.circuits_healthy ? 1.0 : 0.95))),
    }));

    const nodesTotal = Number(mesh.nodes_total || 0);
    const nodesActive = Number(mesh.nodes_active || 0);
    const coverage = nodesTotal > 0 ? Math.round((nodesActive / nodesTotal) * 100) : out.defensePosture.meshCoverage;

    out.defensePosture = {
      ...out.defensePosture,
      meshCoverage: coverage,
    };
  }

  out.backend = { dashboard, incidents };
  return out;
}


// ─── Predictive Engine (simulated ML output) ────────────────────────────
function generatePredictiveIntel() {
  const now = Date.now();
  const phase = (now / 60000) % 100;
  return {
    threatVelocity: {
      current: (2.4 + Math.sin(phase * 0.1) * 1.8 + Math.random() * 0.5).toFixed(1),
      trend: Math.random() > 0.4 ? "accelerating" : "decelerating",
      peak24h: (4.2 + Math.random() * 2.1).toFixed(1),
      baseline: "1.2",
    },
    defensePosture: {
      score: Math.min(98, Math.max(72, Math.floor(84 + Math.sin(phase * 0.05) * 8 + Math.random() * 4))),
      meshCoverage: Math.min(100, Math.floor(94 + Math.random() * 6)),
      signatureAge: Math.floor(Math.random() * 4),
      patchGap: Math.floor(Math.random() * 3) + 1,
      deceptionActive: Math.floor(6 + Math.random() * 3),
    },
    killChainPredictor: [
      { phase: "Reconnaissance", probability: (0.82 + Math.random() * 0.15).toFixed(2), active: true, ttps: ["T1595", "T1592"], predicted: false },
      { phase: "Weaponization", probability: (0.44 + Math.random() * 0.2).toFixed(2), active: false, ttps: ["T1587", "T1588"], predicted: true },
      { phase: "Delivery", probability: (0.31 + Math.random() * 0.15).toFixed(2), active: false, ttps: ["T1566", "T1189"], predicted: true },
      { phase: "Exploitation", probability: (0.18 + Math.random() * 0.12).toFixed(2), active: false, ttps: ["T1190", "T1203"], predicted: true },
      { phase: "Installation", probability: (0.09 + Math.random() * 0.08).toFixed(2), active: false, ttps: ["T1547", "T1053"], predicted: true },
      { phase: "C2", probability: (0.05 + Math.random() * 0.05).toFixed(2), active: false, ttps: ["T1071", "T1573"], predicted: true },
      { phase: "Actions", probability: (0.02 + Math.random() * 0.03).toFixed(2), active: false, ttps: ["T1486", "T1041"], predicted: true },
    ],
    forecast: Array.from({ length: 24 }, (_, i) => ({
      hour: i,
      predicted: Math.max(0, Math.floor(12 + Math.sin((i + phase * 0.3) * 0.5) * 18 + Math.random() * 8)),
      actual: i < new Date().getHours() ? Math.max(0, Math.floor(10 + Math.sin((i + phase * 0.3) * 0.5) * 16 + Math.random() * 10)) : null,
      confidence: Math.max(0.5, 0.95 - i * 0.018 - Math.random() * 0.05),
    })),
    huntQueries: [
      { id: "HQ-001", name: "Cobalt Strike Beacon Detection", confidence: 0.91, ttps: ["T1071.001"], status: "running", hits: Math.floor(Math.random() * 3), priority: "CRITICAL" },
      { id: "HQ-002", name: "Lateral Movement via WMI", confidence: 0.85, ttps: ["T1047"], status: "running", hits: Math.floor(Math.random() * 2), priority: "HIGH" },
      { id: "HQ-003", name: "Scheduled Task Persistence", confidence: 0.78, ttps: ["T1053.005"], status: "queued", hits: 0, priority: "HIGH" },
      { id: "HQ-004", name: "DNS Exfil via Long Queries", confidence: 0.88, ttps: ["T1048.001"], status: "running", hits: Math.floor(Math.random() * 2), priority: "HIGH" },
      { id: "HQ-005", name: "LSASS Memory Access", confidence: 0.94, ttps: ["T1003.001"], status: "complete", hits: Math.floor(Math.random() * 2), priority: "CRITICAL" },
      { id: "HQ-006", name: "RDP Brute Force Patterns", confidence: 0.72, ttps: ["T1110.001"], status: "running", hits: Math.floor(Math.random() * 4), priority: "MEDIUM" },
    ],
    deceptionLayer: [
      { id: "HNY-01", type: "SSH Honeypot", location: "DMZ-A", interactions: Math.floor(Math.random() * 12) + 3, lastHit: `${Math.floor(Math.random() * 45) + 1}m ago`, status: "active" },
      { id: "HNY-02", type: "Fake DB Server", location: "Internal-B", interactions: Math.floor(Math.random() * 5), lastHit: `${Math.floor(Math.random() * 120) + 10}m ago`, status: "active" },
      { id: "HNY-03", type: "Canary Token (Creds)", location: "AD-Forest", interactions: Math.floor(Math.random() * 3), lastHit: `${Math.floor(Math.random() * 300) + 30}m ago`, status: "active" },
      { id: "HNY-04", type: "Fake SMB Share", location: "Internal-C", interactions: Math.floor(Math.random() * 8) + 1, lastHit: `${Math.floor(Math.random() * 60) + 2}m ago`, status: "active" },
      { id: "HNY-05", type: "Web App Decoy", location: "DMZ-B", interactions: Math.floor(Math.random() * 20) + 5, lastHit: `${Math.floor(Math.random() * 15) + 1}m ago`, status: "alert" },
      { id: "HNY-06", type: "Canary Token (File)", location: "FileServer-1", interactions: Math.floor(Math.random() * 2), lastHit: "—", status: "dormant" },
    ],
    threatActors: [
      { name: "APT-PHANTOM", confidence: 0.73, ttps: 12, lastSeen: "2h ago", origin: "Eastern Europe", targeting: "Credentials", risk: "CRITICAL" },
      { name: "SCATTERED-SPIDER", confidence: 0.58, ttps: 8, lastSeen: "6h ago", origin: "Distributed", targeting: "Identity", risk: "HIGH" },
      { name: "UNKNOWN-C2-CLUSTER", confidence: 0.41, ttps: 4, lastSeen: "18h ago", origin: "SE Asia", targeting: "Network", risk: "MEDIUM" },
    ],
    meshNodes: generateMeshData(),
    threats: generateThreats(),
    incidents: generateIncidents(),
  };
}

function generateMeshData() {
  const nodes = [
    { id: "hub_net", type: "hub", label: "Network", health: 0.95 + Math.random() * 0.05, events: Math.floor(Math.random() * 200) + 800 },
    { id: "hub_end", type: "hub", label: "Endpoint", health: 0.92 + Math.random() * 0.08, events: Math.floor(Math.random() * 150) + 600 },
    { id: "hub_idn", type: "hub", label: "Identity", health: 0.96 + Math.random() * 0.04, events: Math.floor(Math.random() * 100) + 300 },
    { id: "hub_dat", type: "hub", label: "Data", health: 0.94 + Math.random() * 0.06, events: Math.floor(Math.random() * 80) + 200 },
  ];
  const radials = Array.from({ length: 12 }, (_, i) => ({
    id: `r_${i}`, type: "radial", label: `R${i + 1}`,
    health: 0.85 + Math.random() * 0.15, events: Math.floor(Math.random() * 50),
  }));
  const spirals = Array.from({ length: 8 }, (_, i) => ({
    id: `s_${i}`, type: "spiral", label: `S${i + 1}`,
    health: 0.88 + Math.random() * 0.12, events: Math.floor(Math.random() * 30),
  }));
  return [...nodes, ...radials, ...spirals];
}

function generateThreats() {
  return [
    { name: "Port Scan Detected", severity: "MEDIUM", src: "203.0.113.45", dst: "10.0.1.50", mitre: "T1046", cat: "Recon", conf: (78 + Math.random() * 18).toFixed(0) },
    { name: "Brute Force Attack", severity: "HIGH", src: "198.51.100.22", dst: "10.0.1.10", mitre: "T1110", cat: "Cred Access", conf: (82 + Math.random() * 15).toFixed(0) },
    { name: "C2 Beacon Activity", severity: "CRITICAL", src: "10.0.2.15", dst: "evil-c2.xyz", mitre: "T1071", cat: "C2", conf: (88 + Math.random() * 10).toFixed(0) },
    { name: "Ransomware File Activity", severity: "CRITICAL", src: "10.0.3.8", dst: "—", mitre: "T1486", cat: "Impact", conf: (91 + Math.random() * 8).toFixed(0) },
    { name: "DNS Tunneling", severity: "HIGH", src: "10.0.1.33", dst: "dns.exfil.cc", mitre: "T1048", cat: "Exfil", conf: (80 + Math.random() * 16).toFixed(0) },
    { name: "Credential Dump (mimikatz)", severity: "CRITICAL", src: "10.0.2.20", dst: "—", mitre: "T1003", cat: "Cred Access", conf: (93 + Math.random() * 6).toFixed(0) },
    { name: "Impossible Travel Login", severity: "HIGH", src: "91.234.56.78", dst: "10.0.1.1", mitre: "T1078", cat: "Initial Access", conf: (75 + Math.random() * 20).toFixed(0) },
    { name: "Sensitive Data Access", severity: "HIGH", src: "10.0.4.12", dst: "db-prod-01", mitre: "T1005", cat: "Collection", conf: (70 + Math.random() * 22).toFixed(0) },
  ].map((t, i) => ({ ...t, id: `THR-${String(i + 1).padStart(4, "0")}`, time: new Date(Date.now() - Math.random() * 3600000).toLocaleTimeString() }));
}

function generateIncidents() {
  return [
    { id: "INC-7A3F01BC", title: "Ransomware Kill Chain", severity: "CRITICAL", status: "containing", actions: 11, assets: 3, created: "2 min ago" },
    { id: "INC-4E8B29D1", title: "APT Lateral Movement", severity: "CRITICAL", status: "investigating", actions: 8, assets: 5, created: "18 min ago" },
    { id: "INC-9C12F4A7", title: "Data Exfiltration via DNS", severity: "HIGH", status: "containing", actions: 6, assets: 1, created: "45 min ago" },
    { id: "INC-B5D38E02", title: "Brute Force Campaign", severity: "HIGH", status: "eradicating", actions: 4, assets: 2, created: "1.2 hrs ago" },
    { id: "INC-1F7A6C53", title: "Phishing Campaign", severity: "MEDIUM", status: "closed", actions: 5, assets: 0, created: "3.1 hrs ago" },
  ];
}

// ─── UI Components ──────────────────────────────────────────────────────

function Sev({ s, small }) {
  const c = { CRITICAL: T.critical, HIGH: T.high, MEDIUM: T.medium, LOW: T.low }[s] || T.textDim;
  return <span style={{ display: "inline-block", padding: small ? "1px 5px" : "2px 7px", borderRadius: 3, fontSize: small ? 9 : 10, fontWeight: 700, letterSpacing: "0.06em", color: "#fff", background: c }}>{s}</span>;
}

function StatusBadge({ s }) {
  const c = { containing: T.high, investigating: T.accent, eradicating: T.purple, closed: T.success, recovering: T.info, new: T.critical }[s] || T.textDim;
  return <span style={{ display: "inline-block", padding: "1px 7px", borderRadius: 3, fontSize: 9, fontWeight: 600, letterSpacing: "0.05em", color: c, border: `1px solid ${c}44`, textTransform: "uppercase" }}>{s}</span>;
}

function Panel({ children, title, icon, accent, style, glow }) {
  return (
    <div style={{
      background: T.panel, border: `1px solid ${T.border}`, borderRadius: 6,
      ...(glow && { boxShadow: `inset 0 1px 0 ${accent || T.accent}15, 0 0 20px ${accent || T.accent}08` }),
      ...style,
    }}>
      {title && (
        <div style={{ padding: "10px 14px", borderBottom: `1px solid ${T.border}`, display: "flex", alignItems: "center", gap: 7 }}>
          {icon && <span style={{ fontSize: 12 }}>{icon}</span>}
          <span style={{ fontSize: 10, fontWeight: 700, color: accent || T.textSoft, letterSpacing: "0.08em", textTransform: "uppercase" }}>{title}</span>
        </div>
      )}
      <div style={{ padding: "12px 14px" }}>{children}</div>
    </div>
  );
}

function MetricBox({ label, value, sub, color, icon, trend, small }) {
  return (
    <div style={{ background: T.panel, border: `1px solid ${T.border}`, borderRadius: 6, padding: small ? "10px 12px" : "12px 14px", flex: 1, minWidth: small ? 110 : 130 }}>
      <div style={{ fontSize: 9, color: T.textDim, letterSpacing: "0.07em", textTransform: "uppercase", marginBottom: 4, display: "flex", alignItems: "center", gap: 5 }}>
        {icon && <span style={{ fontSize: 10 }}>{icon}</span>}{label}
      </div>
      <div style={{ display: "flex", alignItems: "baseline", gap: 6 }}>
        <span style={{ fontSize: small ? 20 : 24, fontWeight: 800, color: color || T.text, lineHeight: 1 }}>{value}</span>
        {trend && <span style={{ fontSize: 9, color: trend === "up" ? T.critical : T.success, fontWeight: 600 }}>{trend === "up" ? "▲" : "▼"}</span>}
      </div>
      {sub && <div style={{ fontSize: 9, color: T.textDim, marginTop: 3 }}>{sub}</div>}
    </div>
  );
}

// ─── Defense Posture Gauge ──────────────────────────────────────────────

function PostureGauge({ score }) {
  const angle = (score / 100) * 180;
  const color = score >= 85 ? T.success : score >= 70 ? T.medium : T.critical;
  const r = 64, cx = 80, cy = 72;
  const startAngle = Math.PI;
  const endAngle = startAngle + (angle / 180) * Math.PI;
  const x1 = cx + r * Math.cos(startAngle), y1 = cy + r * Math.sin(startAngle);
  const x2 = cx + r * Math.cos(endAngle), y2 = cy + r * Math.sin(endAngle);
  const largeArc = angle > 180 ? 1 : 0;

  return (
    <div style={{ textAlign: "center" }}>
      <svg width={160} height={90} viewBox="0 0 160 90">
        <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`} fill="none" stroke={T.border} strokeWidth={8} strokeLinecap="round" />
        <path d={`M ${x1} ${y1} A ${r} ${r} 0 ${largeArc} 1 ${x2} ${y2}`} fill="none" stroke={color} strokeWidth={8} strokeLinecap="round" style={{ filter: `drop-shadow(0 0 6px ${color}88)`, transition: "d 0.8s ease" }} />
        <text x={cx} y={cy - 8} textAnchor="middle" fill={color} fontSize={28} fontWeight={900} fontFamily={font}>{score}</text>
        <text x={cx} y={cy + 8} textAnchor="middle" fill={T.textDim} fontSize={8} fontFamily={font} letterSpacing="0.1em">DEFENSE SCORE</text>
      </svg>
      <div style={{ display: "flex", justifyContent: "space-between", padding: "0 8px", fontSize: 8, color: T.textDim }}>
        <span>VULNERABLE</span><span>HARDENED</span>
      </div>
    </div>
  );
}

// ─── Kill Chain Predictor ───────────────────────────────────────────────

function KillChainPredictor({ phases }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
      {phases.map((p, i) => {
        const prob = parseFloat(p.probability);
        const color = p.active ? T.critical : prob > 0.5 ? T.high : prob > 0.2 ? T.medium : T.textDim;
        const barColor = p.active ? T.critical : T.predict;
        return (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 80, fontSize: 9, color: p.active ? T.text : T.textSoft, fontWeight: p.active ? 700 : 400, textAlign: "right" }}>
              {p.active && <span style={{ color: T.critical, marginRight: 4 }}>●</span>}
              {p.phase}
            </div>
            <div style={{ flex: 1, height: 12, background: T.void, borderRadius: 2, overflow: "hidden", position: "relative" }}>
              <div style={{
                height: "100%", width: `${prob * 100}%`, borderRadius: 2,
                background: p.active ? `linear-gradient(90deg, ${T.critical}, ${T.high})` : `linear-gradient(90deg, ${barColor}cc, ${barColor}44)`,
                transition: "width 0.8s ease", boxShadow: p.active ? `0 0 8px ${T.critical}66` : "none",
              }} />
              {p.predicted && !p.active && (
                <div style={{ position: "absolute", top: 0, left: 0, height: "100%", width: `${prob * 100}%`, background: `repeating-linear-gradient(90deg, transparent, transparent 3px, ${barColor}22 3px, ${barColor}22 6px)`, borderRadius: 2 }} />
              )}
            </div>
            <div style={{ width: 36, fontSize: 10, fontWeight: 700, color, textAlign: "right" }}>{(prob * 100).toFixed(0)}%</div>
            <div style={{ width: 70, fontSize: 8, color: T.textDim }}>{p.ttps.join(", ")}</div>
          </div>
        );
      })}
      <div style={{ display: "flex", gap: 12, marginTop: 4, fontSize: 8, color: T.textDim, paddingLeft: 88 }}>
        <span><span style={{ color: T.critical }}>●</span> Active</span>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 3 }}><span style={{ display: "inline-block", width: 12, height: 3, background: `repeating-linear-gradient(90deg, ${T.predict}88, ${T.predict}88 3px, transparent 3px, transparent 6px)` }} /> Predicted</span>
      </div>
    </div>
  );
}

// ─── Forecast Chart ─────────────────────────────────────────────────────

function ForecastChart({ data }) {
  const maxVal = Math.max(...data.map(d => d.predicted), ...data.filter(d => d.actual !== null).map(d => d.actual)) + 5;
  const w = 520, h = 140, padL = 30, padR = 10, padT = 10, padB = 22;
  const chartW = w - padL - padR, chartH = h - padT - padB;
  const xScale = (i) => padL + (i / 23) * chartW;
  const yScale = (v) => padT + chartH - (v / maxVal) * chartH;
  const currentHour = new Date().getHours();

  const predictedPath = data.map((d, i) => `${i === 0 ? "M" : "L"} ${xScale(i)} ${yScale(d.predicted)}`).join(" ");
  const actualPath = data.filter(d => d.actual !== null).map((d, i) => `${i === 0 ? "M" : "L"} ${xScale(d.hour)} ${yScale(d.actual)}`).join(" ");
  const confUpper = data.map((d, i) => `${i === 0 ? "M" : "L"} ${xScale(i)} ${yScale(d.predicted * (1 + (1 - d.confidence) * 0.6))}`).join(" ");
  const confLower = data.slice().reverse().map((d) => `L ${xScale(d.hour)} ${yScale(Math.max(0, d.predicted * (1 - (1 - d.confidence) * 0.6)))}`).join(" ");

  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} style={{ display: "block", maxWidth: "100%" }}>
      {[0, 0.25, 0.5, 0.75, 1].map(f => (
        <line key={f} x1={padL} y1={padT + f * chartH} x2={w - padR} y2={padT + f * chartH} stroke={T.border} strokeWidth={0.5} />
      ))}
      <line x1={xScale(currentHour)} y1={padT} x2={xScale(currentHour)} y2={padT + chartH} stroke={T.accent} strokeWidth={1} strokeDasharray="3,3" opacity={0.5} />
      <text x={xScale(currentHour)} y={padT - 2} textAnchor="middle" fill={T.accent} fontSize={7} fontFamily={font}>NOW</text>
      <path d={`${confUpper} ${confLower} Z`} fill={T.predict} opacity={0.08} />
      <path d={predictedPath} fill="none" stroke={T.predict} strokeWidth={1.5} strokeDasharray="4,3" opacity={0.7} />
      <path d={actualPath} fill="none" stroke={T.cyan} strokeWidth={2} />
      {data.filter(d => d.actual !== null).map(d => (
        <circle key={d.hour} cx={xScale(d.hour)} cy={yScale(d.actual)} r={2} fill={T.cyan} />
      ))}
      {[0, 6, 12, 18, 23].map(h => (
        <text key={h} x={xScale(h)} y={padT + chartH + 14} textAnchor="middle" fill={T.textDim} fontSize={8} fontFamily={font}>{h}h</text>
      ))}
      {[0, Math.floor(maxVal / 2), maxVal].map((v, i) => (
        <text key={i} x={padL - 4} y={yScale(v) + 3} textAnchor="end" fill={T.textDim} fontSize={7} fontFamily={font}>{v}</text>
      ))}
    </svg>
  );
}

// ─── Mesh Visualization ─────────────────────────────────────────────────

function MeshViz({ nodes }) {
  const w = 300, h = 220, cx = w / 2, cy = h / 2;
  const hubs = nodes.filter(n => n.type === "hub");
  const rads = nodes.filter(n => n.type === "radial");
  const sprs = nodes.filter(n => n.type === "spiral");
  const hPos = hubs.map((h, i) => ({ ...h, x: cx + Math.cos((i / hubs.length) * Math.PI * 2 - Math.PI / 2) * 40, y: cy + Math.sin((i / hubs.length) * Math.PI * 2 - Math.PI / 2) * 40 }));
  const rPos = rads.map((r, i) => ({ ...r, x: cx + Math.cos((i / rads.length) * Math.PI * 2 - Math.PI / 4) * 88, y: cy + Math.sin((i / rads.length) * Math.PI * 2 - Math.PI / 4) * 80 }));
  const sPos = sprs.map((s, i) => ({ ...s, x: cx + Math.cos((i / sprs.length) * Math.PI * 2) * 60, y: cy + Math.sin((i / sprs.length) * Math.PI * 2) * 56 }));

  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} style={{ display: "block", maxWidth: "100%" }}>
      {hPos.map(h => rPos.map(r => <line key={`${h.id}-${r.id}`} x1={h.x} y1={h.y} x2={r.x} y2={r.y} stroke={T.border} strokeWidth={0.4} opacity={0.35} />))}
      {sPos.map(s => hPos.map(h => <line key={`${s.id}-${h.id}`} x1={s.x} y1={s.y} x2={h.x} y2={h.y} stroke={T.accent} strokeWidth={0.5} opacity={0.2} />))}
      {hPos.map((h1, i) => hPos.slice(i + 1).map(h2 => <line key={`h-${h1.id}-${h2.id}`} x1={h1.x} y1={h1.y} x2={h2.x} y2={h2.y} stroke={T.accent} strokeWidth={1} opacity={0.4} />))}
      {rPos.map(n => <circle key={n.id} cx={n.x} cy={n.y} r={3} fill={n.health > 0.9 ? T.success : T.medium} opacity={0.7} />)}
      {sPos.map(n => <circle key={n.id} cx={n.x} cy={n.y} r={4} fill={T.purple} opacity={0.6} />)}
      {hPos.map(n => (
        <g key={n.id}>
          <circle cx={n.x} cy={n.y} r={14} fill={T.panel} stroke={T.accent} strokeWidth={1.5} />
          <circle cx={n.x} cy={n.y} r={14} fill={T.accentGlow} />
          <text x={n.x} y={n.y + 1} textAnchor="middle" dominantBaseline="middle" fill={T.text} fontSize={7} fontWeight={700} fontFamily={font}>{n.label.slice(0, 3).toUpperCase()}</text>
        </g>
      ))}
    </svg>
  );
}

// ─── Inline Reason Input (replaces window.prompt) ───────────────────────

function ReasonInput({ label, onSubmit, onCancel, accent }) {
  const [val, setVal] = useState("");
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 4 }}>
      <input
        autoFocus
        value={val}
        onChange={e => setVal(e.target.value)}
        onKeyDown={e => { if (e.key === "Enter") onSubmit(val); if (e.key === "Escape") onCancel(); }}
        placeholder="Reason (optional)"
        style={{
          flex: 1, background: T.void, border: `1px solid ${T.border}`, borderRadius: 6,
          padding: "5px 8px", color: T.text, fontSize: 9, fontFamily: font, outline: "none",
        }}
      />
      <button onClick={() => onSubmit(val)} style={{ border: `1px solid ${accent || T.critical}`, background: "transparent", color: accent || T.critical, padding: "5px 8px", borderRadius: 6, fontSize: 9, cursor: "pointer", fontFamily: font }}>{label}</button>
      <button onClick={onCancel} style={{ border: `1px solid ${T.border}`, background: "transparent", color: T.textDim, padding: "5px 8px", borderRadius: 6, fontSize: 9, cursor: "pointer", fontFamily: font }}>Cancel</button>
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════════════
// MAIN DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════

export default function QueenCalifiaV2() {
  const [tick, setTick] = useState(0);
  const [tab, setTab] = useState("command");

  // Settings stored in React state (no localStorage)
  const [apiBase, setApiBase] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [pollMs, setPollMs] = useState(5000);
  const [showSettings, setShowSettings] = useState(false);

  const [backend, setBackend] = useState({ dashboard: null, incidents: [] });
  const [backendError, setBackendError] = useState(null);
  const [backendOk, setBackendOk] = useState(false);

  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [incidentDetail, setIncidentDetail] = useState(null);
  const [incidentDetailLoading, setIncidentDetailLoading] = useState(false);
  const [incidentDetailError, setIncidentDetailError] = useState("");
  const [approving, setApproving] = useState({});
  const [denying, setDenying] = useState({});
  const [rollingBack, setRollingBack] = useState({});
  const approvingCountRef = useRef(0);
  const [toast, setToast] = useState(null);

  // Inline reason input state (replaces window.prompt)
  const [reasonFor, setReasonFor] = useState(null); // { type: "deny"|"rollback", actionId }

  const intel = useMemo(
    () => mergeBackendIntoIntel(generatePredictiveIntel(), backend.dashboard, backend.incidents),
    [backend, tick],
  );

  useEffect(() => { approvingCountRef.current = Object.keys(approving || {}).length; }, [approving]);

  // Tick cycle (3s refresh)
  useEffect(() => {
    const t = setInterval(() => setTick(k => k + 1), 3000);
    return () => clearInterval(t);
  }, []);

  // Auto-dismiss toast after 6s
  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 6000);
    return () => clearTimeout(t);
  }, [toast]);

  // Keyboard: Escape closes drill-down
  useEffect(() => {
    const handler = (e) => {
      if (e.key === "Escape") {
        if (reasonFor) { setReasonFor(null); return; }
        if (selectedIncidentId) { setSelectedIncidentId(null); setToast(null); }
        if (showSettings) setShowSettings(false);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [selectedIncidentId, showSettings, reasonFor]);

  // Backend polling
  useEffect(() => {
    let alive = true;

    const doPoll = async () => {
      try {
        const base = apiBase || "";
        const [dash, inc] = await Promise.all([
          fetchJsonWithRetry(apiUrl(base, "/api/dashboard"), { apiKey, timeoutMs: 8000, retries: 2 }),
          fetchJsonWithRetry(apiUrl(base, "/api/incidents"), { apiKey, timeoutMs: 8000, retries: 2 }),
        ]);

        if (!alive) return;
        setBackend({
          dashboard: dash?.data || null,
          incidents: inc?.data || [],
        });
        setBackendError(null);
        setBackendOk(true);
      } catch (e) {
        if (!alive) return;
        setBackendError(String(e?.message || e));
        setBackendOk(false);
      }
    };

    doPoll();
    const t = setInterval(doPoll, Math.max(2000, pollMs || 5000));
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [apiBase, apiKey, pollMs]);


  const fetchIncidentDetail = useCallback(async (incidentId, { silent = false } = {}) => {
    if (!incidentId) return;
    const base = apiBase || "";

    if (!silent) {
      setIncidentDetailLoading(true);
      setIncidentDetailError("");
    }

    try {
      const res = await fetchJsonWithRetry(
        apiUrl(base, `/api/incidents/${encodeURIComponent(incidentId)}`),
        { apiKey, timeoutMs: 9000, retries: 2 },
      );
      setIncidentDetail(res?.data || null);
      if (!silent) setIncidentDetailError("");
      return res?.data || null;
    } catch (e) {
      const msg = String(e?.message || e);
      if (!silent) setIncidentDetailError(msg);
      throw e;
    } finally {
      if (!silent) setIncidentDetailLoading(false);
    }
  }, [apiBase, apiKey]);

  const approveIncidentAction = useCallback(async (incidentId, actionId) => {
    if (!incidentId || !actionId) return;
    const base = apiBase || "";
    const snapshot = incidentDetail;

    setApproving(p => ({ ...p, [actionId]: true }));
    setToast(null);

    setIncidentDetail(prev => {
      if (!prev) return prev;
      const actions = Array.isArray(prev.response_actions) ? prev.response_actions : [];
      return {
        ...prev,
        response_actions: actions.map(a => (
          a.action_id === actionId
            ? { ...a, status: "in_progress", approved_by: "pending", executed_at: new Date().toISOString() }
            : a
        )),
      };
    });

    try {
      await fetchJsonWithRetry(
        apiUrl(base, `/api/incidents/${encodeURIComponent(incidentId)}/approve/${encodeURIComponent(actionId)}`),
        { apiKey, method: "POST", body: {}, timeoutMs: 12000, retries: 1 },
      );
      await fetchIncidentDetail(incidentId, { silent: true });
      setToast({ type: "success", msg: "Action approved and executed." });
    } catch (e) {
      setIncidentDetail(snapshot || null);
      setToast({ type: "error", msg: String(e?.message || e) });
    } finally {
      setApproving(p => { const { [actionId]: _, ...rest } = p || {}; return rest; });
    }
  }, [apiBase, apiKey, incidentDetail, fetchIncidentDetail]);

  const denyIncidentAction = useCallback(async (incidentId, actionId, reason) => {
    if (!incidentId || !actionId) return;
    const base = apiBase || "";
    const snapshot = incidentDetail;

    setDenying(p => ({ ...p, [actionId]: true }));
    setToast(null);
    setReasonFor(null);

    setIncidentDetail(prev => {
      if (!prev) return prev;
      const actions = Array.isArray(prev.response_actions) ? prev.response_actions : [];
      return {
        ...prev,
        response_actions: actions.map(a => (
          a.action_id === actionId
            ? { ...a, status: "denied", denied_by: "pending", denied_at: new Date().toISOString(), denied_reason: reason || "" }
            : a
        )),
      };
    });

    try {
      await fetchJsonWithRetry(
        apiUrl(base, `/api/incidents/${encodeURIComponent(incidentId)}/deny/${encodeURIComponent(actionId)}`),
        { apiKey, method: "POST", body: { reason: reason || "" }, timeoutMs: 12000, retries: 1 },
      );
      await fetchIncidentDetail(incidentId, { silent: true });
      setToast({ type: "success", msg: "Action denied." });
    } catch (e) {
      setIncidentDetail(snapshot || null);
      setToast({ type: "error", msg: String(e?.message || e) });
    } finally {
      setDenying(p => { const { [actionId]: _, ...rest } = p || {}; return rest; });
    }
  }, [apiBase, apiKey, incidentDetail, fetchIncidentDetail]);

  const rollbackIncidentAction = useCallback(async (incidentId, actionId, reason) => {
    if (!incidentId || !actionId) return;
    const base = apiBase || "";
    const snapshot = incidentDetail;

    setRollingBack(p => ({ ...p, [actionId]: true }));
    setToast(null);
    setReasonFor(null);

    setIncidentDetail(prev => {
      if (!prev) return prev;
      const actions = Array.isArray(prev.response_actions) ? prev.response_actions : [];
      return {
        ...prev,
        response_actions: actions.map(a => (
          a.action_id === actionId
            ? { ...a, status: "rolled_back", rolled_back_by: "pending", rolled_back_at: new Date().toISOString(), rolled_back_reason: reason || "" }
            : a
        )),
      };
    });

    try {
      await fetchJsonWithRetry(
        apiUrl(base, `/api/incidents/${encodeURIComponent(incidentId)}/rollback/${encodeURIComponent(actionId)}`),
        { apiKey, method: "POST", body: { reason: reason || "" }, timeoutMs: 15000, retries: 1 },
      );
      await fetchIncidentDetail(incidentId, { silent: true });
      setToast({ type: "success", msg: "Rollback executed." });
    } catch (e) {
      setIncidentDetail(snapshot || null);
      setToast({ type: "error", msg: String(e?.message || e) });
    } finally {
      setRollingBack(p => { const { [actionId]: _, ...rest } = p || {}; return rest; });
    }
  }, [apiBase, apiKey, incidentDetail, fetchIncidentDetail]);


  useEffect(() => {
    if (!selectedIncidentId) {
      setIncidentDetail(null);
      setIncidentDetailError("");
      setIncidentDetailLoading(false);
      setReasonFor(null);
      return;
    }
    fetchIncidentDetail(selectedIncidentId).catch(() => null);
  }, [selectedIncidentId, fetchIncidentDetail]);

  useEffect(() => {
    if (tab !== "incidents" || !selectedIncidentId) return;
    const t = setInterval(() => {
      if (approvingCountRef.current > 0) return;
      fetchIncidentDetail(selectedIncidentId, { silent: true }).catch(() => null);
    }, Math.max(4000, pollMs || 5000));
    return () => clearInterval(t);
  }, [tab, selectedIncidentId, fetchIncidentDetail, pollMs]);

  const totalEvents = intel.meshNodes.reduce((s, n) => s + n.events, 0);
  const critThreats = intel.threats.filter(t => t.severity === "CRITICAL").length;
  const activeInc = intel.incidents.filter(i => i.status !== "closed").length;
  const dp = intel.defensePosture;
  const tv = intel.threatVelocity;

  const tabs = [
    { id: "command", label: "⚔ Command" },
    { id: "predict", label: "🔮 Predict" },
    { id: "hunt", label: "🎯 Hunt" },
    { id: "threats", label: "⚡ Threats" },
    { id: "incidents", label: "🛡 Incidents" },
  ];

  return (
    <div style={{ minHeight: "100vh", background: T.void, color: T.text, fontFamily: font, fontSize: 12 }}>
      {/* ── HEADER ── */}
      <div style={{
        background: `linear-gradient(180deg, ${T.bg} 0%, ${T.void} 100%)`,
        borderBottom: `1px solid ${T.border}`, padding: "12px 20px",
        display: "flex", alignItems: "center", justifyContent: "space-between",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{
            width: 34, height: 34, borderRadius: 6,
            background: `linear-gradient(135deg, ${T.accent}, ${T.purple})`,
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 16, fontWeight: 900, color: "#fff",
            boxShadow: `0 0 15px ${T.accent}44`,
          }}>Q</div>
          <div>
            <div style={{ fontSize: 14, fontWeight: 800, letterSpacing: "0.06em" }}>QUEEN CALIFIA</div>
            <div style={{ fontSize: 8, color: T.textDim, letterSpacing: "0.12em" }}>PREDICTIVE THREAT INTELLIGENCE v2.0 • TAMERIAN MATERIALS</div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div
            title={backendError || (backendOk ? "Backend connected" : "Backend unreachable — using simulated data")}
            style={{
              display: "flex", alignItems: "center", gap: 5,
              padding: "3px 10px", borderRadius: 16,
              background: backendOk ? T.accentGlow : T.critGlow,
              border: `1px solid ${backendOk ? T.accent : T.critical}30`,
            }}
          >
            <div style={{
              width: 6, height: 6, borderRadius: "50%",
              background: backendOk ? T.success : T.critical,
              boxShadow: `0 0 6px ${backendOk ? T.success : T.critical}`,
              animation: backendOk ? "none" : "pulse 2s infinite",
            }} />
            <span style={{ fontSize: 9, color: backendOk ? T.success : T.critical, fontWeight: 600, letterSpacing: "0.05em" }}>
              {backendOk ? "LIVE" : "SIM"}
            </span>
          </div>

          <button
            onClick={() => setShowSettings(s => !s)}
            style={{
              border: `1px solid ${showSettings ? T.borderHot : T.border}`,
              background: showSettings ? T.panelHover : "transparent",
              color: showSettings ? T.accent : T.textDim,
              padding: "5px 10px", borderRadius: 8, fontSize: 9, cursor: "pointer",
              fontFamily: font, letterSpacing: "0.05em",
            }}
          >
            ⚙ CONFIG
          </button>

          <div style={{ fontSize: 9, color: T.textDim, textAlign: "right", minWidth: 60 }}>
            <div>{new Date().toLocaleTimeString()}</div>
            <div style={{ fontSize: 8 }}>T:{tick}</div>
          </div>
        </div>
      </div>

      {/* ── SETTINGS DRAWER ── */}
      {showSettings && (
        <div style={{
          background: T.panel, borderBottom: `1px solid ${T.border}`,
          padding: "10px 20px", display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap",
        }}>
          <div style={{ fontSize: 9, color: T.textDim, fontWeight: 700, letterSpacing: "0.08em" }}>BACKEND:</div>
          <input
            value={apiBase}
            onChange={e => setApiBase(e.target.value)}
            placeholder="API base URL (e.g. http://localhost:5000)"
            style={{ width: 260, background: T.void, border: `1px solid ${T.border}`, borderRadius: 6, padding: "6px 8px", color: T.text, fontSize: 9, fontFamily: font, outline: "none" }}
          />
          <input
            type="password"
            value={apiKey}
            onChange={e => setApiKey(e.target.value)}
            placeholder="API key"
            style={{ width: 180, background: T.void, border: `1px solid ${T.border}`, borderRadius: 6, padding: "6px 8px", color: T.text, fontSize: 9, fontFamily: font, outline: "none" }}
          />
          <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <span style={{ fontSize: 9, color: T.textDim }}>Poll:</span>
            <input
              value={pollMs}
              onChange={e => setPollMs(Number(e.target.value || 0))}
              placeholder="5000"
              style={{ width: 60, background: T.void, border: `1px solid ${T.border}`, borderRadius: 6, padding: "6px 8px", color: T.text, fontSize: 9, fontFamily: font, outline: "none", textAlign: "center" }}
            />
            <span style={{ fontSize: 8, color: T.textDim }}>ms</span>
          </div>
          <div style={{ fontSize: 8, color: T.textDim, marginLeft: "auto" }}>
            {backendOk
              ? <span style={{ color: T.success }}>● Connected</span>
              : <span style={{ color: T.critical }}>● {backendError || "No backend — simulated data active"}</span>
            }
          </div>
        </div>
      )}

      {/* ── TABS ── */}
      <div style={{ display: "flex", gap: 0, borderBottom: `1px solid ${T.border}`, padding: "0 20px", background: T.bg }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            background: "none", border: "none", cursor: "pointer", fontFamily: font,
            padding: "10px 16px", fontSize: 10, fontWeight: 600, letterSpacing: "0.04em",
            color: tab === t.id ? T.accent : T.textDim,
            borderBottom: tab === t.id ? `2px solid ${T.accent}` : "2px solid transparent",
            transition: "all 0.15s",
          }}>{t.label}</button>
        ))}
      </div>

      <div style={{ padding: "16px 20px" }}>
        {/* ── TOP METRICS ── */}
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 14 }}>
          <MetricBox icon="⚡" label="Threat Velocity" value={`${tv.current}x`} sub={`Baseline: ${tv.baseline}x`} color={parseFloat(tv.current) > 3 ? T.critical : T.high} trend={tv.trend === "accelerating" ? "up" : "down"} small />
          <MetricBox icon="🛡" label="Defense Score" value={`${dp.score}%`} sub={`${dp.meshCoverage}% mesh coverage`} color={dp.score >= 85 ? T.success : dp.score >= 70 ? T.medium : T.critical} small />
          <MetricBox icon="📡" label="Events/hr" value={totalEvents.toLocaleString()} sub="ingested" color={T.accent} small />
          <MetricBox icon="⚠" label="Critical Threats" value={critThreats} sub={`${intel.threats.length} total`} color={T.critical} small />
          <MetricBox icon="🎯" label="Active Hunts" value={intel.huntQueries.filter(h => h.status === "running").length} sub={`${intel.huntQueries.reduce((s, h) => s + h.hits, 0)} hits`} color={T.hunt} small />
          <MetricBox icon="🍯" label="Deception Layer" value={dp.deceptionActive} sub={`${intel.deceptionLayer.filter(d => d.status === "alert").length} alerting`} color={T.purple} small />
          <MetricBox icon="🔮" label="Predicted Threats" value={intel.forecast.slice(12).reduce((s, f) => s + f.predicted, 0)} sub="next 12h" color={T.predict} small />
        </div>

        {/* ═══ COMMAND CENTER TAB ═══ */}
        {tab === "command" && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
            {/* Left: Kill Chain + Mesh */}
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <Panel title="Kill Chain Predictor" icon="🔮" accent={T.predict} glow>
                <KillChainPredictor phases={intel.killChainPredictor} />
              </Panel>
              <Panel title="Security Mesh" icon="🕷" accent={T.accent}>
                <MeshViz nodes={intel.meshNodes} />
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6, fontSize: 9, marginTop: 6 }}>
                  <span style={{ color: T.textDim }}>Circuits: <span style={{ color: T.success }}>6/6</span></span>
                  <span style={{ color: T.textDim }}>Self-heals: <span style={{ color: T.accent }}>{Math.floor(tick * 0.3)}</span></span>
                  <span style={{ color: T.textDim }}>Signatures: <span style={{ color: T.text }}>15 active</span></span>
                  <span style={{ color: T.textDim }}>IOCs: <span style={{ color: T.text }}>6 loaded</span></span>
                </div>
              </Panel>
            </div>

            {/* Center: Forecast + Threat Feed */}
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <Panel title="24h Threat Forecast" icon="📈" accent={T.cyan} glow>
                <ForecastChart data={intel.forecast} />
                <div style={{ display: "flex", gap: 14, marginTop: 6, fontSize: 8, color: T.textDim }}>
                  <span><span style={{ color: T.cyan }}>━</span> Actual</span>
                  <span><span style={{ color: T.predict, opacity: 0.7 }}>╌╌</span> Predicted</span>
                  <span style={{ opacity: 0.6 }}>▒ Confidence Band</span>
                </div>
              </Panel>
              <Panel title="Live Threat Feed" icon="⚡" accent={T.critical}>
                <div style={{ maxHeight: 260, overflowY: "auto" }}>
                  {intel.threats.map(t => (
                    <div key={t.id} style={{ padding: "7px 0", borderBottom: `1px solid ${T.border}`, display: "flex", alignItems: "center", gap: 8, fontSize: 11 }}>
                      <Sev s={t.severity} small />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ color: T.text, fontWeight: 600, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{t.name}</div>
                        <div style={{ color: T.textDim, fontSize: 9, marginTop: 1 }}>{t.src} → {t.dst} | {t.mitre} | {t.cat}</div>
                      </div>
                      <div style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                        <div style={{ color: T.textSoft, fontSize: 9 }}>{t.time}</div>
                        <div style={{ color: T.textDim, fontSize: 9 }}>{t.conf}%</div>
                      </div>
                    </div>
                  ))}
                </div>
              </Panel>
            </div>

            {/* Right: Defense Posture + Threat Actors + Deception */}
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <Panel title="Defense Posture" icon="🛡" accent={T.success} glow>
                <PostureGauge score={dp.score} />
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6, marginTop: 8, fontSize: 9 }}>
                  <div style={{ color: T.textDim }}>Sig Age: <span style={{ color: dp.signatureAge <= 2 ? T.success : T.medium }}>{dp.signatureAge}h</span></div>
                  <div style={{ color: T.textDim }}>Patch Gap: <span style={{ color: dp.patchGap <= 2 ? T.success : T.high }}>{dp.patchGap} CVEs</span></div>
                  <div style={{ color: T.textDim }}>Coverage: <span style={{ color: T.success }}>{dp.meshCoverage}%</span></div>
                  <div style={{ color: T.textDim }}>Deception: <span style={{ color: T.purple }}>{dp.deceptionActive} active</span></div>
                </div>
              </Panel>

              <Panel title="Threat Actor Attribution" icon="👤" accent={T.rose}>
                {intel.threatActors.map((a, i) => (
                  <div key={i} style={{ padding: "7px 0", borderBottom: `1px solid ${T.border}`, fontSize: 10 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span style={{ color: T.text, fontWeight: 700 }}>{a.name}</span>
                      <Sev s={a.risk} small />
                    </div>
                    <div style={{ display: "flex", gap: 10, marginTop: 3, fontSize: 9, color: T.textDim }}>
                      <span>Conf: {(a.confidence * 100).toFixed(0)}%</span>
                      <span>TTPs: {a.ttps}</span>
                      <span>Origin: {a.origin}</span>
                      <span>Last: {a.lastSeen}</span>
                    </div>
                  </div>
                ))}
              </Panel>

              <Panel title="Deception Layer" icon="🍯" accent={T.purple}>
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {intel.deceptionLayer.map(d => (
                    <div key={d.id} style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 0", borderBottom: `1px solid ${T.border}08`, fontSize: 9 }}>
                      <div style={{
                        width: 6, height: 6, borderRadius: "50%",
                        background: d.status === "alert" ? T.critical : d.status === "active" ? T.success : T.textDim,
                        boxShadow: d.status === "alert" ? `0 0 6px ${T.critical}` : "none",
                      }} />
                      <span style={{ flex: 1, color: d.status === "alert" ? T.text : T.textSoft }}>{d.type}</span>
                      <span style={{ color: T.textDim }}>{d.location}</span>
                      <span style={{ color: d.interactions > 5 ? T.high : T.textDim, fontWeight: d.interactions > 5 ? 700 : 400, width: 18, textAlign: "right" }}>{d.interactions}</span>
                      <span style={{ color: T.textDim, width: 42, textAlign: "right" }}>{d.lastHit}</span>
                    </div>
                  ))}
                </div>
              </Panel>
            </div>
          </div>
        )}

        {/* ═══ PREDICT TAB ═══ */}
        {tab === "predict" && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Panel title="Kill Chain Probability Forecast" icon="🔮" accent={T.predict} glow>
              <KillChainPredictor phases={intel.killChainPredictor} />
              <div style={{ marginTop: 12, padding: 10, background: T.void, borderRadius: 4, fontSize: 10, color: T.textSoft, lineHeight: 1.5 }}>
                <div style={{ color: T.predict, fontWeight: 700, marginBottom: 4, fontSize: 9, letterSpacing: "0.08em" }}>PREDICTIVE ANALYSIS</div>
                Based on current reconnaissance activity (82%+ probability), the model predicts weaponization within the next 4-8 hours. Recommended: pre-position containment rules for T1566 (Phishing) and T1190 (Exploit Public-Facing App) delivery vectors.
              </div>
            </Panel>

            <Panel title="24h Threat Forecast — Event Volume" icon="📈" accent={T.cyan} glow>
              <ForecastChart data={intel.forecast} />
              <div style={{ display: "flex", gap: 14, marginTop: 6, fontSize: 8, color: T.textDim }}>
                <span><span style={{ color: T.cyan }}>━</span> Actual</span>
                <span><span style={{ color: T.predict, opacity: 0.7 }}>╌╌</span> Predicted</span>
                <span style={{ opacity: 0.6 }}>▒ Confidence Band</span>
              </div>
              <div style={{ marginTop: 10, padding: 10, background: T.void, borderRadius: 4, fontSize: 10, color: T.textSoft, lineHeight: 1.5 }}>
                <div style={{ color: T.cyan, fontWeight: 700, marginBottom: 4, fontSize: 9, letterSpacing: "0.08em" }}>FORECAST INSIGHT</div>
                Threat volume projected to peak between 14:00-18:00 UTC. Confidence degrades beyond 18h horizon. Historical pattern match: 78% correlation with Tuesday attack cadence from APT-PHANTOM cluster.
              </div>
            </Panel>

            <Panel title="Threat Actor Behavioral Model" icon="🧬" accent={T.rose}>
              {intel.threatActors.map((a, i) => (
                <div key={i} style={{ padding: "10px 0", borderBottom: `1px solid ${T.border}` }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                    <span style={{ color: T.text, fontWeight: 700, fontSize: 11 }}>{a.name}</span>
                    <Sev s={a.risk} small />
                  </div>
                  <div style={{ display: "flex", gap: 8, fontSize: 9 }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ color: T.textDim, marginBottom: 2 }}>Attribution Confidence</div>
                      <div style={{ height: 6, background: T.void, borderRadius: 2, overflow: "hidden" }}>
                        <div style={{ height: "100%", width: `${a.confidence * 100}%`, background: T.rose, borderRadius: 2, transition: "width 0.6s ease" }} />
                      </div>
                    </div>
                    <div style={{ textAlign: "right", color: T.textDim }}>
                      <div>TTPs: {a.ttps}</div>
                      <div>Target: {a.targeting}</div>
                    </div>
                  </div>
                </div>
              ))}
            </Panel>

            <Panel title="Threat Velocity Trend" icon="⚡" accent={T.high} glow>
              <div style={{ textAlign: "center", padding: "16px 0" }}>
                <div style={{ fontSize: 48, fontWeight: 900, color: parseFloat(tv.current) > 3 ? T.critical : T.high, lineHeight: 1, textShadow: `0 0 20px ${parseFloat(tv.current) > 3 ? T.critical : T.high}44` }}>
                  {tv.current}x
                </div>
                <div style={{ fontSize: 9, color: T.textDim, letterSpacing: "0.1em", marginTop: 4 }}>CURRENT THREAT VELOCITY</div>
                <div style={{ display: "flex", justifyContent: "center", gap: 20, marginTop: 14, fontSize: 9 }}>
                  <div><div style={{ color: T.textDim }}>Baseline</div><div style={{ color: T.text, fontWeight: 700 }}>{tv.baseline}x</div></div>
                  <div><div style={{ color: T.textDim }}>24h Peak</div><div style={{ color: T.critical, fontWeight: 700 }}>{tv.peak24h}x</div></div>
                  <div><div style={{ color: T.textDim }}>Trend</div><div style={{ color: tv.trend === "accelerating" ? T.critical : T.success, fontWeight: 700, textTransform: "uppercase" }}>{tv.trend}</div></div>
                </div>
              </div>
              <div style={{ marginTop: 8, padding: 10, background: T.void, borderRadius: 4, fontSize: 10, color: T.textSoft, lineHeight: 1.5 }}>
                <div style={{ color: T.high, fontWeight: 700, marginBottom: 4, fontSize: 9, letterSpacing: "0.08em" }}>VELOCITY ANALYSIS</div>
                Current threat velocity exceeds baseline by {((parseFloat(tv.current) / parseFloat(tv.baseline)) * 100 - 100).toFixed(0)}%. When velocity exceeds 3.0x, historical data shows 89% correlation with coordinated attack campaigns within 6 hours.
              </div>
            </Panel>
          </div>
        )}

        {/* ═══ HUNT TAB ═══ */}
        {tab === "hunt" && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Panel title="Active Threat Hunts" icon="🎯" accent={T.hunt} glow style={{ gridColumn: "1 / -1" }}>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
                  <thead>
                    <tr style={{ borderBottom: `1px solid ${T.border}` }}>
                      {["ID", "Hunt Query", "Priority", "TTPs", "Confidence", "Status", "Hits"].map(h => (
                        <th key={h} style={{ textAlign: "left", padding: "7px 8px", color: T.textDim, fontWeight: 600, fontSize: 9, textTransform: "uppercase", letterSpacing: "0.06em" }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {intel.huntQueries.map(hq => (
                      <tr key={hq.id} style={{ borderBottom: `1px solid ${T.border}` }}>
                        <td style={{ padding: "9px 8px", color: T.hunt, fontWeight: 600, fontSize: 10 }}>{hq.id}</td>
                        <td style={{ padding: "9px 8px", color: T.text, fontWeight: 500 }}>{hq.name}</td>
                        <td style={{ padding: "9px 8px" }}><Sev s={hq.priority} small /></td>
                        <td style={{ padding: "9px 8px", color: T.textDim, fontSize: 10 }}>{hq.ttps.join(", ")}</td>
                        <td style={{ padding: "9px 8px" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                            <div style={{ width: 40, height: 4, background: T.void, borderRadius: 2, overflow: "hidden" }}>
                              <div style={{ height: "100%", width: `${hq.confidence * 100}%`, background: T.hunt, borderRadius: 2 }} />
                            </div>
                            <span style={{ color: T.textSoft, fontSize: 10 }}>{(hq.confidence * 100).toFixed(0)}%</span>
                          </div>
                        </td>
                        <td style={{ padding: "9px 8px" }}>
                          <span style={{
                            fontSize: 9, fontWeight: 600, letterSpacing: "0.05em", textTransform: "uppercase",
                            color: hq.status === "running" ? T.success : hq.status === "complete" ? T.accent : T.textDim,
                          }}>
                            {hq.status === "running" && "● "}{hq.status}
                          </span>
                        </td>
                        <td style={{ padding: "9px 8px", fontWeight: 700, color: hq.hits > 0 ? T.critical : T.textDim, fontSize: 12 }}>{hq.hits}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>

            <Panel title="Deception Layer — Honeypot Network" icon="🍯" accent={T.purple} glow>
              {intel.deceptionLayer.map(d => (
                <div key={d.id} style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 0", borderBottom: `1px solid ${T.border}`, fontSize: 10 }}>
                  <div style={{
                    width: 8, height: 8, borderRadius: "50%",
                    background: d.status === "alert" ? T.critical : d.status === "active" ? T.success : T.textDim,
                    boxShadow: d.status === "alert" ? `0 0 8px ${T.critical}` : "none",
                  }} />
                  <div style={{ flex: 1 }}>
                    <div style={{ color: d.status === "alert" ? T.text : T.textSoft, fontWeight: d.status === "alert" ? 700 : 400 }}>{d.type}</div>
                    <div style={{ color: T.textDim, fontSize: 9 }}>{d.location} | {d.interactions} interactions | Last: {d.lastHit}</div>
                  </div>
                  <span style={{
                    fontSize: 8, fontWeight: 600, padding: "2px 6px", borderRadius: 3, textTransform: "uppercase",
                    color: d.status === "alert" ? T.critical : d.status === "active" ? T.success : T.textDim,
                    border: `1px solid ${d.status === "alert" ? T.critical : d.status === "active" ? T.success : T.textDim}44`,
                  }}>{d.status}</span>
                </div>
              ))}
              <div style={{ marginTop: 10, padding: 8, background: T.void, borderRadius: 4, fontSize: 9, color: T.textDim }}>
                Deception network provides early warning when attackers interact with fake assets. Any interaction with a honeypot is definitively malicious — zero false-positive detection.
              </div>
            </Panel>

            <Panel title="Automated Hunt Logic" icon="🧠" accent={T.hunt}>
              <div style={{ display: "flex", flexDirection: "column", gap: 8, fontSize: 10 }}>
                {[
                  { trigger: "Threat velocity > 3.0x", action: "Deploy Cobalt Strike beacon detection hunt across all endpoints", status: "armed" },
                  { trigger: "New C2 domain in IOC feed", action: "Sweep DNS logs for historical resolution + active connections", status: "armed" },
                  { trigger: "Honeypot SSH interaction", action: "Trace source IP across all network telemetry, block at perimeter", status: "triggered" },
                  { trigger: "Credential dump signature hit", action: "Hunt for pass-the-hash/pass-the-ticket across authentication logs", status: "armed" },
                  { trigger: "Ransomware file extension pattern", action: "Emergency isolate host, snapshot memory, sweep for lateral spread", status: "armed" },
                ].map((rule, i) => (
                  <div key={i} style={{ padding: "8px 10px", background: T.void, borderRadius: 4, borderLeft: `2px solid ${rule.status === "triggered" ? T.critical : T.hunt}` }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 3 }}>
                      <span style={{ color: T.textSoft, fontSize: 9 }}>IF: {rule.trigger}</span>
                      <span style={{
                        fontSize: 8, fontWeight: 600, textTransform: "uppercase",
                        color: rule.status === "triggered" ? T.critical : T.success,
                      }}>{rule.status === "triggered" ? "⚡ " : "● "}{rule.status}</span>
                    </div>
                    <div style={{ color: T.text, fontSize: 10 }}>THEN: {rule.action}</div>
                  </div>
                ))}
              </div>
            </Panel>
          </div>
        )}

        {/* ═══ THREATS TAB ═══ */}
        {tab === "threats" && (
          <Panel title="Threat Detections — MITRE ATT&CK Mapped" icon="⚡" accent={T.critical} glow>
            <div style={{ maxHeight: 500, overflowY: "auto" }}>
              {intel.threats.map(t => (
                <div key={t.id} style={{ padding: "10px 0", borderBottom: `1px solid ${T.border}`, display: "flex", alignItems: "center", gap: 10 }}>
                  <Sev s={t.severity} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ color: T.text, fontWeight: 600, marginBottom: 2 }}>{t.name}</div>
                    <div style={{ color: T.textDim, fontSize: 10 }}>{t.src} → {t.dst} &nbsp;|&nbsp; {t.mitre} &nbsp;|&nbsp; {t.cat}</div>
                  </div>
                  <div style={{ textAlign: "right" }}>
                    <div style={{ color: T.textSoft, fontSize: 10 }}>{t.time}</div>
                    <div style={{ color: T.textDim, fontSize: 10 }}>{t.conf}% conf</div>
                  </div>
                </div>
              ))}
            </div>
          </Panel>
        )}

        {/* ═══ INCIDENTS TAB ═══ */}
        {tab === "incidents" && (
          <Panel title="Incident Response — NIST 800-61 Lifecycle" icon="🛡" accent={T.accent} glow>
            {toast && (
              <div style={{
                marginBottom: 10, padding: "10px 12px",
                border: `1px solid ${toast.type === "error" ? T.critical : T.borderHot}`,
                background: toast.type === "error" ? T.critGlow : T.accentGlow,
                color: T.text, borderRadius: 12, fontSize: 11,
                display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12,
                animation: "fadeIn 0.2s ease",
              }}>
                <div style={{ color: toast.type === "error" ? T.critical : T.accent, fontWeight: 700, fontSize: 10, letterSpacing: "0.06em", textTransform: "uppercase" }}>
                  {toast.type === "error" ? "Error" : "Success"}
                </div>
                <div style={{ flex: 1, color: T.textSoft }}>{toast.msg}</div>
                <button
                  onClick={() => setToast(null)}
                  style={{
                    border: `1px solid ${T.border}`, background: "transparent",
                    color: T.textDim, padding: "6px 10px", borderRadius: 10, fontSize: 10, cursor: "pointer",
                  }}
                >
                  ✕
                </button>
              </div>
            )}

            <div style={{ display: "flex", gap: 12, alignItems: "stretch", flexWrap: "wrap" }}>
              {/* Incidents list */}
              <div style={{ flex: "1 1 560px", minWidth: 420 }}>
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
                    <thead>
                      <tr style={{ borderBottom: `1px solid ${T.border}` }}>
                        {["ID", "Title", "Severity", "Status", "Actions", "Assets", "Created"].map(h => (
                          <th key={h} style={{ textAlign: "left", padding: "8px 10px", color: T.textDim, fontWeight: 600, fontSize: 9, textTransform: "uppercase", letterSpacing: "0.06em" }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {intel.incidents.map(inc => {
                        const selected = inc.id === selectedIncidentId;
                        return (
                          <tr
                            key={inc.id}
                            onClick={() => setSelectedIncidentId(inc.id)}
                            style={{
                              borderBottom: `1px solid ${T.border}`,
                              cursor: "pointer",
                              background: selected ? T.panelHover : "transparent",
                              transition: "background 0.15s",
                            }}
                          >
                            <td style={{ padding: "10px", color: T.accent, fontSize: 10 }}>{inc.id}</td>
                            <td style={{ padding: "10px", color: T.text, fontWeight: 500 }}>{inc.title}</td>
                            <td style={{ padding: "10px" }}><Sev s={inc.severity} small /></td>
                            <td style={{ padding: "10px" }}><StatusBadge s={inc.status} /></td>
                            <td style={{ padding: "10px", color: T.textSoft, textAlign: "center" }}>{inc.actions}</td>
                            <td style={{ padding: "10px", color: T.textSoft, textAlign: "center" }}>{inc.assets}</td>
                            <td style={{ padding: "10px", color: T.textDim, fontSize: 10 }}>{inc.created}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                <div style={{ marginTop: 10, display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                  <div style={{ color: backendOk ? T.success : T.textDim, fontSize: 10 }}>
                    {backendOk ? "● Backend OK" : "○ Simulated — connect backend for live data"}
                  </div>
                  <div style={{ color: T.textDim, fontSize: 10 }}>
                    Click incident → drill-down • Approvals require <span style={{ color: T.textSoft }}>execute</span> permission • <span style={{ color: T.textSoft }}>Esc</span> to close
                  </div>
                </div>
              </div>

              {/* Drill-down */}
              <div style={{ flex: "1 1 340px", minWidth: 320 }}>
                <div style={{
                  border: `1px solid ${T.border}`,
                  borderRadius: 16,
                  background: `linear-gradient(180deg, ${T.panel}, rgba(0,0,0,0.0))`,
                  padding: 12,
                  minHeight: 260,
                }}>
                  {!selectedIncidentId && (
                    <div style={{ color: T.textDim, fontSize: 11, lineHeight: 1.6 }}>
                      Select an incident to view full report, timeline, evidence, and response actions.
                    </div>
                  )}

                  {selectedIncidentId && incidentDetailLoading && (
                    <div style={{ color: T.textSoft, fontSize: 11 }}>Loading incident report…</div>
                  )}

                  {selectedIncidentId && !incidentDetailLoading && incidentDetailError && (
                    <div style={{ color: T.critical, fontSize: 11, lineHeight: 1.6 }}>
                      {incidentDetailError}
                      <div style={{ marginTop: 8 }}>
                        <button
                          onClick={() => fetchIncidentDetail(selectedIncidentId).catch(() => null)}
                          style={{
                            border: `1px solid ${T.borderHot}`, background: "transparent",
                            color: T.accent, padding: "8px 10px", borderRadius: 12, fontSize: 10, cursor: "pointer",
                          }}
                        >Retry</button>
                      </div>
                    </div>
                  )}

                  {selectedIncidentId && !incidentDetailLoading && !incidentDetailError && incidentDetail && (
                    <div>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "start", gap: 10 }}>
                        <div>
                          <div style={{ color: T.text, fontWeight: 700, fontSize: 12, lineHeight: 1.2 }}>
                            {incidentDetail.title || "Incident"}
                          </div>
                          <div style={{ color: T.textDim, fontSize: 10, marginTop: 4 }}>
                            {incidentDetail.incident_id} • {incidentDetail.category} • created {formatAgo(incidentDetail.created_at)}
                          </div>
                        </div>
                        <div style={{ textAlign: "right" }}>
                          <Sev s={String(incidentDetail.severity || "MEDIUM").toUpperCase()} small />
                          <div style={{ marginTop: 6 }}><StatusBadge s={String(incidentDetail.status || "investigating").toLowerCase()} /></div>
                        </div>
                      </div>

                      {incidentDetail.description && (
                        <div style={{ marginTop: 10, color: T.textSoft, fontSize: 11, lineHeight: 1.6 }}>
                          {incidentDetail.description}
                        </div>
                      )}

                      <div style={{ marginTop: 12, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                        <div>
                          <div style={{ color: T.textDim, fontSize: 9, textTransform: "uppercase", letterSpacing: "0.08em" }}>Assets</div>
                          <div style={{ color: T.textSoft, fontSize: 10, marginTop: 4 }}>
                            {(incidentDetail.affected_assets || []).slice(0, 6).join(", ") || "—"}
                            {(incidentDetail.affected_assets || []).length > 6 ? ` +${(incidentDetail.affected_assets || []).length - 6}` : ""}
                          </div>
                        </div>
                        <div>
                          <div style={{ color: T.textDim, fontSize: 9, textTransform: "uppercase", letterSpacing: "0.08em" }}>MITRE</div>
                          <div style={{ color: T.textSoft, fontSize: 10, marginTop: 4 }}>
                            {(incidentDetail.mitre_techniques || []).slice(0, 6).join(", ") || "—"}
                            {(incidentDetail.mitre_techniques || []).length > 6 ? ` +${(incidentDetail.mitre_techniques || []).length - 6}` : ""}
                          </div>
                        </div>
                      </div>

                      {/* Actions */}
                      <div style={{ marginTop: 14 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <div style={{ color: T.textDim, fontSize: 9, textTransform: "uppercase", letterSpacing: "0.08em" }}>Response actions</div>
                          <button
                            onClick={() => fetchIncidentDetail(selectedIncidentId, { silent: false }).catch(() => null)}
                            style={{
                              border: `1px solid ${T.border}`, background: "transparent",
                              color: T.textDim, padding: "6px 10px", borderRadius: 10, fontSize: 10, cursor: "pointer",
                            }}
                          >Refresh</button>
                        </div>

                        <div style={{ marginTop: 8, border: `1px solid ${T.border}`, borderRadius: 12, overflow: "hidden" }}>
                          {(Array.isArray(incidentDetail.response_actions) ? incidentDetail.response_actions : []).length === 0 ? (
                            <div style={{ padding: 10, color: T.textDim, fontSize: 11 }}>No actions recorded.</div>
                          ) : (
                            <div>
                              {(incidentDetail.response_actions || []).slice(0, 12).map(a => {
                                const pendingApproval = a.requires_approval && String(a.status) === "pending";
                                const busyApprove = Boolean(approving?.[a.action_id]);
                                const busyDeny = Boolean(denying?.[a.action_id]);
                                const busyRollback = Boolean(rollingBack?.[a.action_id]);
                                const busy = busyApprove || busyDeny || busyRollback;
                                const canRollback = String(a.status) === "completed" && Boolean(a.rollback_action);
                                const showingReason = reasonFor && reasonFor.actionId === a.action_id;

                                return (
                                  <div key={a.action_id} style={{ padding: "10px 10px", borderBottom: `1px solid ${T.border}` }}>
                                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10 }}>
                                      <div style={{ minWidth: 0 }}>
                                        <div style={{ color: T.textSoft, fontSize: 10, fontWeight: 700 }}>
                                          {a.action_type} <span style={{ color: T.textDim, fontWeight: 500 }}>→</span> {a.target || "—"}
                                        </div>
                                        <div style={{ color: T.textDim, fontSize: 10, marginTop: 2 }}>
                                          {a.action_id} • <span style={{ color: T.textSoft }}>{a.status}</span>{a.requires_approval ? " • approval" : ""}{a.approved_by ? ` • by ${a.approved_by}` : ""}{a.denied_by ? ` • denied by ${a.denied_by}` : ""}{a.rolled_back_by ? ` • rolled back by ${a.rolled_back_by}` : ""}
                                        </div>
                                        {a.error && <div style={{ color: T.critical, fontSize: 10, marginTop: 2 }}>{a.error}</div>}
                                      </div>

                                      <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
                                        {pendingApproval && !showingReason && (
                                          <>
                                            <button
                                              disabled={busy}
                                              onClick={e => { e.stopPropagation(); approveIncidentAction(selectedIncidentId, a.action_id); }}
                                              style={{
                                                border: `1px solid ${T.borderHot}`,
                                                background: busyApprove ? T.panelHover : "transparent",
                                                color: busyApprove ? T.textDim : T.accent,
                                                padding: "7px 10px", borderRadius: 12, fontSize: 10,
                                                cursor: busy ? "not-allowed" : "pointer",
                                              }}
                                            >{busyApprove ? "Approving…" : "Approve"}</button>

                                            <button
                                              disabled={busy}
                                              onClick={e => { e.stopPropagation(); setReasonFor({ type: "deny", actionId: a.action_id }); }}
                                              style={{
                                                border: `1px solid ${T.critical}`,
                                                background: busyDeny ? T.panelHover : "transparent",
                                                color: busyDeny ? T.textDim : T.critical,
                                                padding: "7px 10px", borderRadius: 12, fontSize: 10,
                                                cursor: busy ? "not-allowed" : "pointer",
                                              }}
                                            >{busyDeny ? "Denying…" : "Deny"}</button>
                                          </>
                                        )}

                                        {canRollback && !showingReason && (
                                          <button
                                            disabled={busy}
                                            onClick={e => { e.stopPropagation(); setReasonFor({ type: "rollback", actionId: a.action_id }); }}
                                            style={{
                                              border: `1px solid ${T.borderLit}`,
                                              background: busyRollback ? T.panelHover : "transparent",
                                              color: busyRollback ? T.textDim : T.textSoft,
                                              padding: "7px 10px", borderRadius: 12, fontSize: 10,
                                              cursor: busy ? "not-allowed" : "pointer",
                                            }}
                                          >{busyRollback ? "Rolling…" : "Rollback"}</button>
                                        )}
                                      </div>
                                    </div>

                                    {/* Inline reason input */}
                                    {showingReason && reasonFor.type === "deny" && (
                                      <ReasonInput
                                        label="Confirm Deny"
                                        accent={T.critical}
                                        onSubmit={reason => denyIncidentAction(selectedIncidentId, a.action_id, reason)}
                                        onCancel={() => setReasonFor(null)}
                                      />
                                    )}
                                    {showingReason && reasonFor.type === "rollback" && (
                                      <ReasonInput
                                        label="Confirm Rollback"
                                        accent={T.textSoft}
                                        onSubmit={reason => rollbackIncidentAction(selectedIncidentId, a.action_id, reason)}
                                        onCancel={() => setReasonFor(null)}
                                      />
                                    )}
                                  </div>
                                );
                              })}
                            </div>
                          )}
                        </div>

                        {/* Timeline */}
                        <div style={{ marginTop: 12 }}>
                          <div style={{ color: T.textDim, fontSize: 9, textTransform: "uppercase", letterSpacing: "0.08em" }}>Timeline</div>
                          <div style={{ marginTop: 6, maxHeight: 140, overflow: "auto", border: `1px solid ${T.border}`, borderRadius: 12 }}>
                            {(Array.isArray(incidentDetail.timeline) ? incidentDetail.timeline : []).length === 0 ? (
                              <div style={{ padding: 10, color: T.textDim, fontSize: 11 }}>No timeline entries.</div>
                            ) : (
                              (incidentDetail.timeline || []).slice(0, 40).map((t, idx) => (
                                <div key={idx} style={{ padding: "8px 10px", borderBottom: `1px solid ${T.border}` }}>
                                  <div style={{ color: T.textSoft, fontSize: 10, fontWeight: 700 }}>{t.phase || "event"} • <span style={{ color: T.textDim, fontWeight: 500 }}>{t.timestamp || ""}</span></div>
                                  {t.details && <div style={{ color: T.textDim, fontSize: 10, marginTop: 2, lineHeight: 1.5 }}>{t.details}</div>}
                                </div>
                              ))
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {selectedIncidentId && (
                  <div style={{ marginTop: 10, display: "flex", justifyContent: "space-between", gap: 10 }}>
                    <button
                      onClick={() => { setSelectedIncidentId(null); setToast(null); setReasonFor(null); }}
                      style={{
                        border: `1px solid ${T.border}`, background: "transparent",
                        color: T.textDim, padding: "8px 12px", borderRadius: 12, fontSize: 10, cursor: "pointer",
                      }}
                    >Close</button>

                    <button
                      onClick={() => fetchIncidentDetail(selectedIncidentId).catch(() => null)}
                      style={{
                        border: `1px solid ${T.borderHot}`, background: "transparent",
                        color: T.accent, padding: "8px 12px", borderRadius: 12, fontSize: 10, cursor: "pointer",
                      }}
                    >Re-sync</button>
                  </div>
                )}
              </div>
            </div>
          </Panel>
        )}

        {/* ── FOOTER ── */}
        <div style={{
          marginTop: 16, padding: "10px 0", borderTop: `1px solid ${T.border}`,
          display: "flex", justifyContent: "space-between", fontSize: 9, color: T.textDim,
        }}>
          <span>Queen Califia Predictive CyberAI v2.0 • Tamerian Materials • Defense-Grade</span>
          <span>🕷 Spider Web Mesh • 🍄 Mycelium Intel • 🔮 Predictive Engine • 🎯 Active Hunt • 🍯 Deception Layer</span>
        </div>
      </div>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(-4px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}
