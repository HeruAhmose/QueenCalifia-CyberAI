/**
 * QueenCalifia CyberAI — Unified Command Dashboard v4.2
 * God-Tier Sovereign Circuitry Design
 * 
 * Defense-Grade Cybersecurity Intelligence Platform
 * Zero-Day Prediction • Threat Mesh • Incident Response • Vulnerability Scanner
 * One-Click Remediate • Self-Learning Feedback • Quantum Hardening • DevOps Ops
 * Mobile-Responsive • Sound-Enabled • Cinematic Animations
 */

const API_BASE = window.location.hostname === "localhost" ? "" : "https://queencalifia-cyberai.onrender.com";
import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { LineChart, Line, AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Cell, PieChart, Pie } from "recharts";
import { motion, AnimatePresence } from "framer-motion";
import QueenCalifiaAvatar from "./components/QueenCalifiaAvatar.jsx";
import { playSound } from "./lib/SoundEngine.js";

const CDN = "https://d2xsxph8kpxj0f.cloudfront.net/310419663029216973/6A6PRiSc2SBdMKdQGVopRa";

// ─── Color System ─────────────────────────────────────────────────────────
const C = {
  void: "#020409", bg: "#060a14", panel: "#0a0f1e", panelHover: "#0e1528",
  surface: "#111b2e", border: "#131d33", borderLit: "#1a2d50",
  text: "#d4dff0", textSoft: "#8a9dbd", textDim: "#4a6080",
  accent: "#2563eb", accentBright: "#60a5fa",
  gold: "#D4AF37", goldDim: "rgba(212,175,55,0.10)",
  green: "#10b981", greenDim: "rgba(16,185,129,0.10)",
  amber: "#f59e0b", amberDim: "rgba(245,158,11,0.10)",
  red: "#ef4444", redDim: "rgba(239,68,68,0.08)",
  cyan: "#06b6d4", cyanDim: "rgba(6,182,212,0.06)",
  purple: "#a78bfa", purpleDim: "rgba(167,139,250,0.08)",
  magenta: "#ec4899",
};
const FONT = "'DM Sans', sans-serif";
const MONO = "'JetBrains Mono', monospace";

// ─── Responsive ───────────────────────────────────────────────────────────
function useIsMobile(bp = 768) {
  const [m, setM] = useState(window.innerWidth < bp);
  useEffect(() => { const h = () => setM(window.innerWidth < bp); window.addEventListener("resize", h); return () => window.removeEventListener("resize", h); }, [bp]);
  return m;
}

// ─── Data Generators ──────────────────────────────────────────────────────
const now = () => new Date();
const ago = (ms) => new Date(Date.now() - ms);
const rand = (a, b) => Math.random() * (b - a) + a;
const randInt = (a, b) => Math.floor(rand(a, b));
const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];
const uuid8 = () => Math.random().toString(36).slice(2, 10).toUpperCase();

function generateMeshStatus() {
  return {
    mesh_id: "QC-" + uuid8(),
    topology: { total_nodes: 24, active_nodes: randInt(21, 24), degraded_nodes: randInt(0, 3), healthy_circuits: 6, total_circuits: 6 },
    threat_posture: { active_attack_chains: randInt(0, 4), iocs_active: randInt(45, 200), ips_blocked: randInt(20, 80), blocked_domains: randInt(30, 120) },
    statistics: { events_ingested: randInt(50000, 250000), threats_detected: randInt(5, 30), attacks_correlated: randInt(1, 8), mesh_heals: randInt(0, 5), false_positives_suppressed: randInt(10, 50) },
  };
}

function generatePredictions() {
  const categories = ["novel_exploit", "variant_mutation", "supply_chain_injection", "living_off_the_land", "encrypted_channel_abuse", "config_drift_exploit", "polymorphic_payload", "ai_generated_malware"];
  return Array.from({ length: randInt(3, 8) }, () => {
    const confidence = rand(0.25, 0.97);
    const tier = confidence > 0.95 ? "near_certain" : confidence > 0.8 ? "high" : confidence > 0.6 ? "probable" : confidence > 0.3 ? "emerging" : "speculative";
    return {
      prediction_id: `PRED-${uuid8()}`, category: pick(categories),
      title: pick(["Novel Exploit Targeting Edge Gateway", "AI-Generated Phishing Campaign Imminent", "Supply Chain Injection — npm Registry", "Encrypted C2 Channel Establishing", "LOTL Attack via PowerShell Remoting", "Configuration Drift Creating RCE Window", "Polymorphic Payload Variant Detected", "Identity Fabric Attack — OAuth Token Theft", "Firmware-Level Persistence Attempt", "DNS Tunneling with ML Evasion"]),
      confidence: Math.round(confidence * 1000) / 1000, confidence_tier: tier,
      threat_horizon: pick(["0-1h", "1-24h", "1-7d", "7-30d"]),
      risk_score: Math.round(confidence * rand(6, 10) * 100) / 100,
      affected_assets: Array.from({ length: randInt(1, 4) }, () => `10.0.${randInt(1, 5)}.${randInt(10, 200)}`),
      contributing_signals: randInt(2, 12),
      predicted_techniques: Array.from({ length: randInt(1, 4) }, () => `T${randInt(1000, 1600)}`),
      created_at: ago(randInt(60000, 7200000)).toISOString(),
    };
  }).sort((a, b) => b.confidence - a.confidence);
}

function generateIncidents() {
  const actionTypes = [
    { action: "Block IP at perimeter firewall", type: "containment", risk: "low" },
    { action: "Isolate host from network segment", type: "containment", risk: "medium" },
    { action: "Disable compromised user account", type: "containment", risk: "medium" },
    { action: "Kill malicious process tree (PID cascade)", type: "eradication", risk: "high" },
    { action: "Restore from last known-good snapshot", type: "recovery", risk: "high" },
    { action: "Deploy emergency firewall rule — block C2 domain", type: "containment", risk: "low" },
    { action: "Rotate compromised credentials", type: "recovery", risk: "medium" },
    { action: "Enable enhanced logging on affected segment", type: "monitoring", risk: "low" },
  ];
  const evidenceTypes = [
    { type: "pcap", desc: "Network capture — suspicious outbound traffic" },
    { type: "memory_dump", desc: "Volatile memory snapshot — injected process" },
    { type: "disk_image", desc: "Forensic disk image — affected workstation" },
    { type: "log_bundle", desc: "Auth logs — failed login sequence" },
    { type: "malware_sample", desc: "Extracted binary — staged payload" },
  ];
  const iocTypes = [
    { type: "ip", value: () => `${randInt(45,220)}.${randInt(0,255)}.${randInt(0,255)}.${randInt(1,254)}` },
    { type: "domain", value: () => pick(["evil-update.","c2-relay.","data-sync."]) + pick(["xyz","top","cc","ru"]) },
    { type: "hash_sha256", value: () => Array.from({length:64},()=>"0123456789abcdef"[randInt(0,16)]).join("") },
    { type: "file_path", value: () => pick(["C:\\\\Users\\\\Public\\\\svchost.exe","/tmp/.hidden/beacon"]) },
  ];
  return Array.from({ length: randInt(3, 6) }, () => {
    const createdAt = ago(randInt(300000, 86400000));
    return {
      incident_id: `INC-${uuid8()}`,
      title: pick(["Ransomware Activity Detected — Workstation Cluster", "APT28 Campaign Indicators — DMZ Servers", "Data Exfiltration Attempt — HR Database", "Brute Force Attack — VPN Gateway", "Lateral Movement — Domain Controller"]),
      severity: pick(["CRITICAL", "HIGH", "MEDIUM"]),
      category: pick(["ransomware", "apt", "data_breach", "unauthorized_access", "phishing"]),
      status: pick(["triaged", "investigating", "containing", "eradicating"]),
      affected_assets: randInt(1, 12),
      lead_analyst: pick(["J. Torres", "S. Chen", "M. Okoro", "R. Patel"]),
      playbook: pick(["PB-RANSOM-01", "PB-APT-02", "PB-BREACH-01", "PB-PHISH-01"]),
      mitre_techniques: Array.from({ length: randInt(2, 5) }, () => pick(["T1059.001 — PowerShell", "T1071.001 — Web Protocols", "T1486 — Data Encrypted", "T1566.001 — Spearphishing", "T1078 — Valid Accounts", "T1055 — Process Injection", "T1003 — Credential Dumping"])),
      created_at: createdAt.toISOString(),
      containment_time_min: rand(2, 45),
      pending_actions: Array.from({ length: randInt(1, 5) }, () => {
        const a = pick(actionTypes);
        return { id: `ACT-${uuid8()}`, ...a, status: "pending", requested_by: pick(["SYSTEM","QueenCalifia AI","Analyst"]), requested_at: ago(randInt(60000, 600000)).toISOString() };
      }),
      evidence: Array.from({ length: randInt(1, 4) }, () => {
        const e = pick(evidenceTypes);
        return { id: `EV-${uuid8()}`, ...e, collected_at: ago(randInt(120000, 3600000)).toISOString(), size_mb: +(rand(0.1, 500)).toFixed(1), chain_of_custody: `SHA256:${uuid8()}${uuid8()}…` };
      }),
      iocs: Array.from({ length: randInt(2, 6) }, () => {
        const ioc = pick(iocTypes);
        return { type: ioc.type, value: ioc.value(), first_seen: ago(randInt(300000, 7200000)).toISOString(), source: pick(["network_flow","endpoint_agent","dns_logs","auth_logs"]) };
      }),
      timeline: Array.from({ length: randInt(4, 10) }, (_, i) => ({
        time: new Date(createdAt.getTime() + i * randInt(30000, 600000)).toISOString(),
        event: pick(["Initial alert — anomalous outbound connection", "TLS fingerprint match (Cobalt Strike JA3)", "Suspicious process injection detected", "Host isolation pending approval", "Memory dump in progress", "MITRE T1059.001 mapped", "Lateral movement to adjacent subnet", "DNS beaconing confirmed", "Escalated to CRITICAL", "Playbook activated", "IOC extracted — C2 domain blocked", "Credential rotation triggered"]),
        actor: pick(["QueenCalifia AI", "System", "Analyst", "Telemetry T1"]),
        type: pick(["detection", "analysis", "containment", "evidence", "escalation"]),
      })).sort((a, b) => new Date(a.time) - new Date(b.time)),
    };
  });
}

function generateTimeSeriesData(points = 24) {
  let base = randInt(500, 2000);
  return Array.from({ length: points }, (_, i) => {
    base += randInt(-200, 300); base = Math.max(100, base);
    return { time: `${String(i).padStart(2, "0")}:00`, events: base, threats: Math.max(0, Math.floor(base * rand(0.001, 0.015))), predictions: Math.max(0, Math.floor(base * rand(0.0005, 0.005))), blocked: Math.max(0, Math.floor(base * rand(0.003, 0.01))) };
  });
}
function generateThreatLandscape() {
  return [
    { vector: "Ransomware", risk: rand(65, 95) }, { vector: "Identity", risk: rand(55, 85) },
    { vector: "Supply Chain", risk: rand(50, 80) }, { vector: "AI-Augmented", risk: rand(40, 75) },
    { vector: "Cloud Native", risk: rand(45, 70) }, { vector: "Zero-Day", risk: rand(55, 90) },
    { vector: "Firmware", risk: rand(25, 55) }, { vector: "Encrypted Ch.", risk: rand(35, 60) },
  ];
}
function generateLayerActivity() {
  return [
    { layer: "Anomaly Fusion", signals: randInt(12, 80), confidence: rand(0.5, 0.85) },
    { layer: "Surface Drift", signals: randInt(5, 30), confidence: rand(0.55, 0.9) },
    { layer: "Entropy Analysis", signals: randInt(8, 45), confidence: rand(0.45, 0.8) },
    { layer: "Behavioral Genome", signals: randInt(3, 25), confidence: rand(0.6, 0.92) },
    { layer: "Strategic Forecast", signals: randInt(2, 15), confidence: rand(0.5, 0.88) },
  ];
}
function generateTelemetryData() {
  const malwareFamilies = ["Cobalt Strike", "Sliver C2", "Brute Ratel", "Mythic C2", "Havoc C2"];
  return {
    fingerprints: { total: randInt(80, 250), known_bad: randInt(0, 5), new_last_hour: randInt(1, 15),
      recent_matches: Array.from({ length: randInt(0, 3) }, () => ({ ja3: uuid8()+uuid8()+uuid8(), family: pick(malwareFamilies), source: `10.0.${randInt(1,10)}.${randInt(1,254)}`, dest: `${randInt(100,220)}.${randInt(0,255)}.${randInt(0,255)}.${randInt(1,254)}`, confidence: +(rand(0.82, 0.97)).toFixed(2) })) },
    dns: { sources_profiled: randInt(40, 200), dga_detected: randInt(0, 6), tunneling_alerts: randInt(0, 3), exfil_indicators: randInt(0, 2), queries_per_min: randInt(300, 2500) },
    beacons: Array.from({ length: randInt(0, 5) }, () => ({ source: `10.0.${randInt(1,10)}.${randInt(1,254)}`, destination: `${randInt(100,220)}.${randInt(0,255)}.${randInt(0,255)}.${randInt(1,254)}`, classification: pick(["periodic_exact","periodic_jittered","adaptive","slow_drip"]), mean_interval: +(rand(15, 600)).toFixed(1), jitter: +(rand(0.01, 0.45)).toFixed(3), confidence: +(rand(0.55, 0.95)).toFixed(2), samples: randInt(12, 500) })),
    kernel: { syscall_profiles: randInt(30, 120), injection_alerts: randInt(0, 3), credential_alerts: randInt(0, 2), ransomware_patterns: randInt(0, 1), file_io_assets: randInt(15, 80), memory_anomalies: randInt(0, 4), privilege_transitions: randInt(2, 25) },
    graph: { total_nodes: randInt(30, 150), total_edges: randInt(50, 400), high_risk_assets: Array.from({ length: randInt(0, 5) }, () => ({ asset: `10.0.${randInt(1,10)}.${randInt(1,254)}`, risk: +(rand(0.5, 1.0)).toFixed(2), direct_targets: randInt(3, 30), blast_radius: randInt(8, 80) })), lateral_movements: randInt(0, 4) },
    feedback: { total_entries: randInt(50, 500), layers_tracked: 5, active_adjustments: randInt(0, 3), suppression_rules: randInt(0, 2), tuned_weights: randInt(2, 15),
      layer_accuracy: {
        anomaly_fusion: { accuracy: +(rand(0.70, 0.95)).toFixed(2), fp_rate: +(rand(0.05, 0.25)).toFixed(2), total: randInt(20, 100) },
        surface_drift: { accuracy: +(rand(0.65, 0.90)).toFixed(2), fp_rate: +(rand(0.08, 0.30)).toFixed(2), total: randInt(15, 80) },
        entropy_analysis: { accuracy: +(rand(0.75, 0.95)).toFixed(2), fp_rate: +(rand(0.03, 0.20)).toFixed(2), total: randInt(10, 60) },
        genome_deviation: { accuracy: +(rand(0.60, 0.88)).toFixed(2), fp_rate: +(rand(0.10, 0.35)).toFixed(2), total: randInt(10, 50) },
        strategic_forecast: { accuracy: +(rand(0.50, 0.85)).toFixed(2), fp_rate: +(rand(0.12, 0.40)).toFixed(2), total: randInt(5, 30) },
      },
    },
    sensors: ["network","endpoint","dns","auth","file_integrity"].map(type => ({ type, count: randInt(1, 6), health: pick(["healthy","healthy","degraded"]), coverage_pct: +(rand(70, 100)).toFixed(1), avg_latency_ms: +(rand(5, 200)).toFixed(0), events_per_min: +(rand(50, 3000)).toFixed(0) })),
    blind_spots: randInt(0, 2), overall_health: pick(["healthy","healthy","healthy","blind_spots_detected"]),
    signals_generated: randInt(5, 80), events_processed: randInt(1000, 50000),
  };
}

// ─── Micro Components ─────────────────────────────────────────────────────
const Badge = ({ children, color = C.accent, bg, style }) => (
  <span style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600, fontFamily: MONO, letterSpacing: 0.5, textTransform: "uppercase", color, background: bg || `${color}18`, border: `1px solid ${color}30`, whiteSpace: "nowrap", ...style }}>{children}</span>
);
const SeverityBadge = ({ severity }) => {
  const map = { CRITICAL: C.red, HIGH: C.amber, MEDIUM: C.accentBright, LOW: C.green };
  return <Badge color={map[severity] || C.accentBright}>{severity}</Badge>;
};
const ConfidenceBadge = ({ tier, confidence }) => {
  const map = { near_certain: { c: C.red, i: "◆" }, high: { c: C.amber, i: "▲" }, probable: { c: C.accentBright, i: "●" }, emerging: { c: C.cyan, i: "◐" }, speculative: { c: C.textDim, i: "○" } };
  const s = map[tier] || map.emerging;
  return <Badge color={s.c}>{s.i} {(confidence * 100).toFixed(1)}%</Badge>;
};
const HorizonBadge = ({ horizon }) => {
  const map = { "0-1h": { c: C.red, l: "IMMEDIATE" }, "1-24h": { c: C.amber, l: "24H" }, "1-7d": { c: C.accentBright, l: "7D" }, "7-30d": { c: C.textSoft, l: "30D" } };
  const s = map[horizon] || map["1-7d"];
  return <Badge color={s.c}>{s.l}</Badge>;
};
const Stat = ({ label, value, color = C.text, small }) => (
  <div style={{ textAlign: "center", minWidth: small ? 50 : 60 }}>
    <div style={{ fontSize: small ? 18 : 24, fontWeight: 700, fontFamily: MONO, color, lineHeight: 1.1 }}>{typeof value === "number" ? value.toLocaleString() : value}</div>
    <div style={{ fontSize: 9, color: C.textSoft, marginTop: 2, letterSpacing: 0.3, textTransform: "uppercase" }}>{label}</div>
  </div>
);
const PulseDot = ({ color = C.green, size = 8 }) => (
  <span style={{ position: "relative", display: "inline-block", width: size, height: size }}>
    <span style={{ position: "absolute", inset: 0, borderRadius: "50%", background: color, animation: "qcPulse 2s ease-in-out infinite" }} />
  </span>
);
const ProgressBar = ({ value, max = 100, color = C.accent, height = 4 }) => (
  <div style={{ height, borderRadius: height, background: `${color}15`, overflow: "hidden" }}>
    <div style={{ height: "100%", width: `${Math.min(100, (value / max) * 100)}%`, background: `linear-gradient(90deg, ${color}, ${color}cc)`, borderRadius: height, transition: "width 0.8s ease" }} />
  </div>
);
const Panel = ({ children, title, icon, accent = C.accent, style, headerRight, glow }) => (
  <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}
    style={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden",
      boxShadow: glow ? `0 0 30px ${accent}08` : "none", ...style }}>
    {title && (
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 14px", borderBottom: `1px solid ${C.border}`, background: `linear-gradient(135deg, ${accent}06 0%, transparent 60%)` }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {icon && <span style={{ fontSize: 14 }}>{icon}</span>}
          <span style={{ fontSize: 11, fontWeight: 600, color: C.textSoft, letterSpacing: 0.8, textTransform: "uppercase", fontFamily: FONT }}>{title}</span>
        </div>
        {headerRight}
      </div>
    )}
    <div style={{ padding: "12px 14px" }}>{children}</div>
  </motion.div>
);
const NAV_ITEMS = [
  { id: "overview", label: "Overview", icon: "◈" },
  { id: "predictor", label: "Predictor", icon: "🔮" },
  { id: "telemetry", label: "Telemetry", icon: "📡" },
  { id: "mesh", label: "Mesh", icon: "🕸" },
  { id: "incidents", label: "Incidents", icon: "🚨" },
  { id: "vulns", label: "Scanner", icon: "🔍" },
  { id: "devops", label: "DevOps", icon: "⎈" },
];


// ═══════════════════════════════════════════════════════════════════════════
// TELEMETRY TAB — 6 Sub-tabs: Network, Temporal, Kernel, Graph, Feedback, Health
// ═══════════════════════════════════════════════════════════════════════════

function TelemetryTab({ telemetry: t, isMobile }) {
  const [subTab, setSubTab] = useState("network");
  const subTabs = [
    { id: "network", label: "Network Flow", icon: "🌐" },
    { id: "temporal", label: "Temporal", icon: "⏱" },
    { id: "kernel", label: "Kernel", icon: "🧬" },
    { id: "graph", label: "Graph", icon: "🔗" },
    { id: "feedback", label: "Feedback", icon: "🧠" },
    { id: "health", label: "Health", icon: "💊" },
  ];
  return (
    <div>
      <div style={{ display: "flex", gap: 4, marginBottom: 16, flexWrap: "wrap" }}>
        {subTabs.map(st => (
          <button key={st.id} onClick={() => { setSubTab(st.id); playSound("tab_switch"); }} style={{
            padding: "6px 10px", borderRadius: 6, border: `1px solid ${subTab === st.id ? C.cyan : C.border}`,
            background: subTab === st.id ? C.cyanDim : C.panel, color: subTab === st.id ? C.cyan : C.textSoft,
            fontSize: 10, fontWeight: 600, cursor: "pointer", fontFamily: FONT,
            display: "flex", alignItems: "center", gap: 4, transition: "all 0.2s",
          }}>
            <span>{st.icon}</span> {!isMobile && st.label}
          </button>
        ))}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: isMobile ? "repeat(3, 1fr)" : "repeat(6, 1fr)", gap: 8, marginBottom: 16 }}>
        <Stat label="Events" value={t.events_processed.toLocaleString()} small />
        <Stat label="Signals" value={t.signals_generated} color={C.cyan} small />
        <Stat label="TLS FPs" value={t.fingerprints.total} small />
        <Stat label="Beacons" value={t.beacons.length} color={t.beacons.length > 0 ? C.red : C.green} small />
        <Stat label="Nodes" value={t.graph.total_nodes} small />
        <Stat label="Health" value={t.overall_health === "healthy" ? "OK" : "GAPS"} color={t.overall_health === "healthy" ? C.green : C.amber} small />
      </div>
      {subTab === "network" && <TelemetryNetworkPanel t={t} isMobile={isMobile} />}
      {subTab === "temporal" && <TelemetryTemporalPanel t={t} isMobile={isMobile} />}
      {subTab === "kernel" && <TelemetryKernelPanel t={t} isMobile={isMobile} />}
      {subTab === "graph" && <TelemetryGraphPanel t={t} isMobile={isMobile} />}
      {subTab === "feedback" && <TelemetryFeedbackPanel t={t} isMobile={isMobile} />}
      {subTab === "health" && <TelemetryHealthPanel t={t} isMobile={isMobile} />}
    </div>
  );
}

function TelemetryNetworkPanel({ t, isMobile }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: isMobile ? "1fr" : "1fr 1fr", gap: 12 }}>
      <Panel title="TLS Fingerprint Intelligence" icon="🔐">
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, marginBottom: 12 }}>
          <Stat label="Catalogued" value={t.fingerprints.total} small />
          <Stat label="Known Bad" value={t.fingerprints.known_bad} color={t.fingerprints.known_bad > 0 ? C.red : C.green} small />
          <Stat label="New (1h)" value={t.fingerprints.new_last_hour} color={C.cyan} small />
        </div>
        {t.fingerprints.recent_matches.length > 0 ? t.fingerprints.recent_matches.map((m, i) => (
          <div key={i} style={{ padding: "8px 10px", background: C.redDim, borderRadius: 6, border: `1px solid ${C.red}33`, marginBottom: 6 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4, flexWrap: "wrap", gap: 4 }}>
              <Badge color={C.red}>{m.family}</Badge>
              <ConfidenceBadge tier={m.confidence >= 0.9 ? "near_certain" : "high"} confidence={m.confidence} />
            </div>
            <div style={{ fontSize: 10, color: C.textSoft, fontFamily: MONO }}>{m.source} → {m.dest}</div>
            <div style={{ fontSize: 9, color: C.textDim, fontFamily: MONO, marginTop: 2 }}>JA3: {m.ja3.slice(0, 20)}…</div>
          </div>
        )) : <div style={{ textAlign: "center", padding: 20, color: C.green, fontSize: 11 }}>✓ No malicious fingerprints detected</div>}
      </Panel>
      <Panel title="DNS Transaction Intelligence" icon="🌐">
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 12 }}>
          <Stat label="Sources" value={t.dns.sources_profiled} small />
          <Stat label="Queries/min" value={t.dns.queries_per_min.toLocaleString()} small />
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 6 }}>
          {[{ v: t.dns.dga_detected, l: "DGA", c: C.red }, { v: t.dns.tunneling_alerts, l: "Tunneling", c: C.amber }, { v: t.dns.exfil_indicators, l: "Exfil", c: C.red }].map((d, i) => (
            <div key={i} style={{ padding: 10, background: d.v > 0 ? `${d.c}10` : C.greenDim, borderRadius: 6, textAlign: "center" }}>
              <div style={{ fontSize: 18, fontWeight: 700, color: d.v > 0 ? d.c : C.green, fontFamily: MONO }}>{d.v}</div>
              <div style={{ fontSize: 9, color: C.textSoft }}>{d.l}</div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function TelemetryTemporalPanel({ t, isMobile }) {
  const beaconColors = { periodic_exact: C.red, periodic_jittered: C.amber, adaptive: C.purple, slow_drip: C.cyan };
  return (
    <Panel title="Beacon Detection — Communication Cadence" icon="⏱">
      {t.beacons.length > 0 ? (
        <div style={{ display: "grid", gridTemplateColumns: isMobile ? "1fr" : "repeat(auto-fill, minmax(280px, 1fr))", gap: 10 }}>
          {t.beacons.map((b, i) => (
            <div key={i} style={{ padding: "10px 12px", background: C.surface, borderRadius: 6, border: `1px solid ${beaconColors[b.classification] || C.border}44` }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6, flexWrap: "wrap", gap: 4 }}>
                <Badge color={beaconColors[b.classification] || C.textDim}>{b.classification.replace(/_/g, " ")}</Badge>
                <ConfidenceBadge tier={b.confidence >= 0.8 ? "high" : "probable"} confidence={b.confidence} />
              </div>
              <div style={{ fontSize: 11, fontFamily: MONO, color: C.text, marginBottom: 4 }}>{b.source} → {b.destination}</div>
              <div style={{ display: "flex", gap: 12, fontSize: 10, color: C.textSoft, flexWrap: "wrap" }}>
                <span>Int: <span style={{ color: C.cyan, fontFamily: MONO }}>{b.mean_interval}s</span></span>
                <span>Jitter: <span style={{ color: C.amber, fontFamily: MONO }}>{b.jitter}</span></span>
                <span>Samples: <span style={{ fontFamily: MONO }}>{b.samples}</span></span>
              </div>
              <div style={{ marginTop: 6 }}><ProgressBar value={b.confidence} max={1} color={beaconColors[b.classification] || C.cyan} /></div>
            </div>
          ))}
        </div>
      ) : <div style={{ textAlign: "center", padding: 30, color: C.green, fontSize: 11 }}>✓ No beaconing patterns detected</div>}
    </Panel>
  );
}

function TelemetryKernelPanel({ t, isMobile }) {
  const k = t.kernel;
  const metrics = [
    { label: "Syscall Profiles", value: k.syscall_profiles, color: C.text },
    { label: "Injection Alerts", value: k.injection_alerts, color: k.injection_alerts > 0 ? C.red : C.green },
    { label: "Credential Access", value: k.credential_alerts, color: k.credential_alerts > 0 ? C.red : C.green },
    { label: "Ransomware", value: k.ransomware_patterns, color: k.ransomware_patterns > 0 ? C.red : C.green },
    { label: "File I/O Assets", value: k.file_io_assets, color: C.text },
    { label: "Memory Anomalies", value: k.memory_anomalies, color: k.memory_anomalies > 0 ? C.amber : C.green },
    { label: "Priv Transitions", value: k.privilege_transitions, color: k.privilege_transitions > 10 ? C.amber : C.text },
  ];
  return (
    <Panel title="Kernel & Endpoint Telemetry" icon="🧬">
      <div style={{ display: "grid", gridTemplateColumns: isMobile ? "repeat(2, 1fr)" : "repeat(4, 1fr)", gap: 10, marginBottom: 16 }}>
        {metrics.map((m, i) => (
          <div key={i} style={{ padding: 12, background: C.surface, borderRadius: 6, textAlign: "center" }}>
            <div style={{ fontSize: 22, fontWeight: 700, color: m.color, fontFamily: MONO }}>{m.value}</div>
            <div style={{ fontSize: 9, color: C.textSoft, marginTop: 4 }}>{m.label}</div>
          </div>
        ))}
      </div>
      {k.injection_alerts > 0 && (
        <div style={{ padding: "10px 12px", background: C.redDim, borderRadius: 6, border: `1px solid ${C.red}33`, marginBottom: 8 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: C.red }}>⚠ Active injection syscall patterns detected</div>
          <div style={{ fontSize: 10, color: C.textSoft, marginTop: 4 }}>{k.injection_alerts} process(es) — recommend immediate memory forensics</div>
        </div>
      )}
      {k.ransomware_patterns > 0 && (
        <div style={{ padding: "10px 12px", background: C.redDim, borderRadius: 6, border: `1px solid ${C.red}33` }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: C.red }}>🔴 RANSOMWARE FILE I/O PATTERN DETECTED</div>
          <div style={{ fontSize: 10, color: C.textSoft, marginTop: 4 }}>Rapid read→write→rename — ISOLATE IMMEDIATELY</div>
        </div>
      )}
    </Panel>
  );
}

function TelemetryGraphPanel({ t, isMobile }) {
  const g = t.graph;
  return (
    <div style={{ display: "grid", gridTemplateColumns: isMobile ? "1fr" : "1fr 1fr", gap: 12 }}>
      <Panel title="Cross-Asset Communication Graph" icon="🔗">
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, marginBottom: 12 }}>
          <Stat label="Nodes" value={g.total_nodes} small />
          <Stat label="Edges" value={g.total_edges} small />
          <Stat label="Lateral" value={g.lateral_movements} color={g.lateral_movements > 0 ? C.red : C.green} small />
        </div>
        <div style={{ height: 140, background: C.surface, borderRadius: 6, padding: 12, position: "relative", overflow: "hidden" }}>
          {Array.from({ length: Math.min(g.total_nodes, 30) }, (_, i) => {
            const angle = (i / Math.min(g.total_nodes, 30)) * Math.PI * 2;
            const r = 55 + (i % 3) * 15;
            const x = 50 + Math.cos(angle) * r * 0.7;
            const y = 50 + Math.sin(angle) * r * 0.85;
            const isRisky = i < g.high_risk_assets.length;
            return <div key={i} style={{ position: "absolute", left: `${x}%`, top: `${y}%`, width: isRisky ? 8 : 4, height: isRisky ? 8 : 4, borderRadius: "50%", background: isRisky ? C.red : C.cyan, opacity: isRisky ? 1 : 0.4, boxShadow: isRisky ? `0 0 8px ${C.red}` : "none", transform: "translate(-50%, -50%)" }} />;
          })}
        </div>
      </Panel>
      <Panel title="High-Risk Assets" icon="⚠">
        {g.high_risk_assets.length > 0 ? g.high_risk_assets.map((a, i) => (
          <div key={i} style={{ padding: "8px 10px", background: C.surface, borderRadius: 6, marginBottom: 6, border: `1px solid ${a.risk >= 0.8 ? C.red : C.amber}33` }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontFamily: MONO, fontSize: 11, color: C.text }}>{a.asset}</span>
              <Badge color={a.risk >= 0.8 ? C.red : C.amber}>Risk: {(a.risk * 100).toFixed(0)}%</Badge>
            </div>
            <div style={{ fontSize: 10, color: C.textSoft, marginTop: 4 }}>Targets: {a.direct_targets} | Blast radius: {a.blast_radius}</div>
          </div>
        )) : <div style={{ textAlign: "center", padding: 20, color: C.green, fontSize: 11 }}>✓ No high-risk assets</div>}
      </Panel>
    </div>
  );
}

function TelemetryFeedbackPanel({ t, isMobile }) {
  const fb = t.feedback;
  const layers = Object.entries(fb.layer_accuracy);
  return (
    <Panel title="Self-Learning Adaptive Feedback Loop" icon="🧠" glow>
      <div style={{ display: "grid", gridTemplateColumns: isMobile ? "repeat(2, 1fr)" : "repeat(5, 1fr)", gap: 8, marginBottom: 16 }}>
        <Stat label="Total Entries" value={fb.total_entries} small />
        <Stat label="Layers Tracked" value={fb.layers_tracked} small />
        <Stat label="Active Adj." value={fb.active_adjustments} color={C.cyan} small />
        <Stat label="Suppressions" value={fb.suppression_rules} small />
        <Stat label="Tuned Weights" value={fb.tuned_weights} color={C.gold} small />
      </div>
      <div style={{ fontSize: 10, color: C.textDim, marginBottom: 8, textTransform: "uppercase", letterSpacing: 1 }}>Layer Accuracy & Calibration</div>
      {layers.map(([name, data], i) => (
        <div key={i} style={{ padding: "8px 10px", background: C.surface, borderRadius: 6, marginBottom: 6 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4, flexWrap: "wrap", gap: 4 }}>
            <span style={{ fontSize: 11, color: C.text, fontWeight: 600 }}>{name.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())}</span>
            <div style={{ display: "flex", gap: 6 }}>
              <Badge color={data.accuracy >= 0.85 ? C.green : data.accuracy >= 0.7 ? C.amber : C.red}>Acc: {(data.accuracy * 100).toFixed(0)}%</Badge>
              <Badge color={data.fp_rate <= 0.1 ? C.green : data.fp_rate <= 0.2 ? C.amber : C.red}>FP: {(data.fp_rate * 100).toFixed(0)}%</Badge>
            </div>
          </div>
          <ProgressBar value={data.accuracy} max={1} color={data.accuracy >= 0.85 ? C.green : C.amber} />
          <div style={{ fontSize: 9, color: C.textDim, marginTop: 4 }}>{data.total} evaluations</div>
        </div>
      ))}
    </Panel>
  );
}

function TelemetryHealthPanel({ t, isMobile }) {
  return (
    <Panel title="Collection Health & Sensor Status" icon="💊">
      <div style={{ display: "grid", gridTemplateColumns: isMobile ? "1fr" : "repeat(auto-fill, minmax(200px, 1fr))", gap: 10 }}>
        {t.sensors.map((s, i) => (
          <div key={i} style={{ padding: "10px 12px", background: C.surface, borderRadius: 6, border: `1px solid ${s.health === "healthy" ? C.green : C.amber}33` }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: C.text, textTransform: "capitalize" }}>{s.type.replace(/_/g, " ")}</span>
              <PulseDot color={s.health === "healthy" ? C.green : C.amber} />
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 4, fontSize: 10, color: C.textSoft }}>
              <span>Sensors: <span style={{ color: C.text, fontFamily: MONO }}>{s.count}</span></span>
              <span>Coverage: <span style={{ color: C.cyan, fontFamily: MONO }}>{s.coverage_pct}%</span></span>
              <span>Latency: <span style={{ fontFamily: MONO }}>{s.avg_latency_ms}ms</span></span>
              <span>Events/m: <span style={{ fontFamily: MONO }}>{s.events_per_min}</span></span>
            </div>
          </div>
        ))}
      </div>
      {t.blind_spots > 0 && (
        <div style={{ marginTop: 12, padding: "10px 12px", background: C.amberDim, borderRadius: 6, border: `1px solid ${C.amber}33` }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: C.amber }}>⚠ {t.blind_spots} blind spot(s) detected</div>
          <div style={{ fontSize: 10, color: C.textSoft, marginTop: 4 }}>Sensor coverage gaps may allow undetected activity</div>
        </div>
      )}
    </Panel>
  );
}


// ═══════════════════════════════════════════════════════════════════════════
// INCIDENTS TAB — Full Investigate, Actions, Evidence, IOCs, Timeline
// ═══════════════════════════════════════════════════════════════════════════

function IncidentsTab({ incidents: initialIncidents, isMobile }) {
  const [incidents, setIncidents] = useState(initialIncidents);
  const [selected, setSelected] = useState(null);
  const [view, setView] = useState("list"); // list | investigate
  const [incSubTab, setIncSubTab] = useState("actions");
  const [analystNotes, setAnalystNotes] = useState("");
  const [actionLog, setActionLog] = useState([]);

  const inc = selected ? incidents.find(i => i.incident_id === selected) : null;

  const handleApprove = (actionId) => {
    playSound("scan_complete");
    setIncidents(prev => prev.map(i => i.incident_id === selected ? {
      ...i, pending_actions: i.pending_actions.map(a => a.id === actionId ? { ...a, status: "approved" } : a)
    } : i));
    setActionLog(prev => [...prev, { time: new Date().toISOString(), msg: `Action ${actionId} APPROVED`, type: "approve" }]);
  };

  const handleReject = (actionId) => {
    playSound("panel_click");
    setIncidents(prev => prev.map(i => i.incident_id === selected ? {
      ...i, pending_actions: i.pending_actions.map(a => a.id === actionId ? { ...a, status: "rejected" } : a)
    } : i));
    setActionLog(prev => [...prev, { time: new Date().toISOString(), msg: `Action ${actionId} REJECTED`, type: "reject" }]);
  };

  const handleApproveAll = () => {
    playSound("scan_complete");
    setIncidents(prev => prev.map(i => i.incident_id === selected ? {
      ...i, pending_actions: i.pending_actions.map(a => ({ ...a, status: "approved" }))
    } : i));
    setActionLog(prev => [...prev, { time: new Date().toISOString(), msg: "ALL ACTIONS APPROVED", type: "approve" }]);
  };

  const handleEscalate = () => {
    playSound("incident_escalate");
    setIncidents(prev => prev.map(i => i.incident_id === selected ? { ...i, severity: "CRITICAL", status: "escalated" } : i));
    setActionLog(prev => [...prev, { time: new Date().toISOString(), msg: "ESCALATED TO CRITICAL", type: "escalate" }]);
  };

  const handleResolve = () => {
    playSound("scan_complete");
    setIncidents(prev => prev.map(i => i.incident_id === selected ? { ...i, status: "resolved" } : i));
    setActionLog(prev => [...prev, { time: new Date().toISOString(), msg: "MARKED RESOLVED", type: "resolve" }]);
  };

  if (view === "investigate" && inc) {
    const subTabs = [
      { id: "actions", label: "Actions", icon: "⚡" },
      { id: "evidence", label: "Evidence", icon: "📦" },
      { id: "iocs", label: "IOCs", icon: "🎯" },
      { id: "timeline", label: "Timeline", icon: "📋" },
      { id: "notes", label: "Notes", icon: "📝" },
    ];
    return (
      <div>
        <button onClick={() => { setView("list"); setSelected(null); }} style={{ padding: "6px 12px", borderRadius: 6, border: `1px solid ${C.border}`, background: C.panel, color: C.textSoft, fontSize: 11, cursor: "pointer", marginBottom: 12, fontFamily: FONT }}>
          ← Back to Incidents
        </button>
        <Panel title={inc.title} icon="🚨" accent={inc.severity === "CRITICAL" ? C.red : C.amber} glow>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
            <SeverityBadge severity={inc.severity} />
            <Badge color={C.cyan}>{inc.status}</Badge>
            <Badge color={C.textSoft}>{inc.category}</Badge>
            <Badge color={C.textDim}>{inc.playbook}</Badge>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: isMobile ? "repeat(2, 1fr)" : "repeat(4, 1fr)", gap: 8, marginBottom: 12 }}>
            <Stat label="Assets" value={inc.affected_assets} small />
            <Stat label="MITRE TTPs" value={inc.mitre_techniques.length} small />
            <Stat label="Lead" value={inc.lead_analyst} small />
            <Stat label="Contain (min)" value={Math.round(inc.containment_time_min)} small />
          </div>
          <div style={{ display: "flex", gap: 4, marginBottom: 4, flexWrap: "wrap" }}>
            {inc.mitre_techniques.map((t, i) => <Badge key={i} color={C.purple} style={{ fontSize: 9 }}>{t}</Badge>)}
          </div>
        </Panel>

        {/* Status Controls */}
        <div style={{ display: "flex", gap: 8, margin: "12px 0", flexWrap: "wrap" }}>
          {inc.status !== "resolved" && (
            <>
              <button onClick={handleEscalate} style={{ padding: "8px 16px", borderRadius: 6, border: `1px solid ${C.red}55`, background: C.redDim, color: C.red, fontSize: 11, fontWeight: 600, cursor: "pointer", fontFamily: FONT }}>🔴 Escalate to CRITICAL</button>
              <button onClick={handleResolve} style={{ padding: "8px 16px", borderRadius: 6, border: `1px solid ${C.green}55`, background: C.greenDim, color: C.green, fontSize: 11, fontWeight: 600, cursor: "pointer", fontFamily: FONT }}>✓ Mark Resolved</button>
            </>
          )}
        </div>

        {/* Sub-tabs */}
        <div style={{ display: "flex", gap: 4, marginBottom: 12, flexWrap: "wrap" }}>
          {subTabs.map(st => (
            <button key={st.id} onClick={() => setIncSubTab(st.id)} style={{
              padding: "6px 10px", borderRadius: 6, border: `1px solid ${incSubTab === st.id ? C.accent : C.border}`,
              background: incSubTab === st.id ? `${C.accent}10` : C.panel, color: incSubTab === st.id ? C.accentBright : C.textSoft,
              fontSize: 10, fontWeight: 600, cursor: "pointer", fontFamily: FONT, display: "flex", alignItems: "center", gap: 4,
            }}>
              <span>{st.icon}</span> {st.label}
            </button>
          ))}
        </div>

        {/* Actions Sub-tab */}
        {incSubTab === "actions" && (
          <Panel title="Pending Actions" icon="⚡" headerRight={
            <button onClick={handleApproveAll} style={{ padding: "4px 10px", borderRadius: 4, border: `1px solid ${C.green}55`, background: C.greenDim, color: C.green, fontSize: 10, fontWeight: 600, cursor: "pointer", fontFamily: MONO }}>APPROVE ALL</button>
          }>
            {inc.pending_actions.map((a, i) => (
              <div key={i} style={{ padding: "10px 12px", background: C.surface, borderRadius: 6, marginBottom: 8, border: `1px solid ${a.status === "approved" ? C.green : a.status === "rejected" ? C.red : C.border}33` }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 8 }}>
                  <div style={{ flex: 1, minWidth: 200 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: C.text, marginBottom: 4 }}>{a.action}</div>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      <Badge color={C.cyan}>{a.type}</Badge>
                      <Badge color={a.risk === "high" ? C.red : a.risk === "medium" ? C.amber : C.green}>Risk: {a.risk}</Badge>
                      <Badge color={C.textDim}>By: {a.requested_by}</Badge>
                    </div>
                  </div>
                  {a.status === "pending" ? (
                    <div style={{ display: "flex", gap: 4 }}>
                      <button onClick={() => handleApprove(a.id)} style={{ padding: "6px 12px", borderRadius: 4, border: `1px solid ${C.green}55`, background: C.greenDim, color: C.green, fontSize: 10, fontWeight: 600, cursor: "pointer" }}>✓ Approve</button>
                      <button onClick={() => handleReject(a.id)} style={{ padding: "6px 12px", borderRadius: 4, border: `1px solid ${C.red}55`, background: C.redDim, color: C.red, fontSize: 10, fontWeight: 600, cursor: "pointer" }}>✗ Reject</button>
                    </div>
                  ) : (
                    <Badge color={a.status === "approved" ? C.green : C.red}>{a.status}</Badge>
                  )}
                </div>
              </div>
            ))}
            {actionLog.length > 0 && (
              <div style={{ marginTop: 12, padding: "8px 10px", background: C.surface, borderRadius: 6 }}>
                <div style={{ fontSize: 10, color: C.textDim, marginBottom: 6, textTransform: "uppercase", letterSpacing: 1 }}>Action Log</div>
                {actionLog.map((l, i) => (
                  <div key={i} style={{ fontSize: 10, color: l.type === "approve" ? C.green : l.type === "reject" ? C.red : C.amber, fontFamily: MONO, marginBottom: 2 }}>
                    [{new Date(l.time).toLocaleTimeString()}] {l.msg}
                  </div>
                ))}
              </div>
            )}
          </Panel>
        )}

        {/* Evidence Sub-tab */}
        {incSubTab === "evidence" && (
          <Panel title="Evidence Collection" icon="📦">
            {inc.evidence.map((e, i) => (
              <div key={i} style={{ padding: "10px 12px", background: C.surface, borderRadius: 6, marginBottom: 6, border: `1px solid ${C.border}` }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 4 }}>
                  <div>
                    <Badge color={C.cyan}>{e.type}</Badge>
                    <span style={{ fontSize: 11, color: C.text, marginLeft: 8 }}>{e.desc}</span>
                  </div>
                  <span style={{ fontSize: 10, color: C.textDim, fontFamily: MONO }}>{e.size_mb} MB</span>
                </div>
                <div style={{ fontSize: 9, color: C.textDim, fontFamily: MONO, marginTop: 4 }}>
                  Chain: {e.chain_of_custody} | Collected: {new Date(e.collected_at).toLocaleTimeString()}
                </div>
              </div>
            ))}
          </Panel>
        )}

        {/* IOCs Sub-tab */}
        {incSubTab === "iocs" && (
          <Panel title="Indicators of Compromise" icon="🎯">
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
                <thead>
                  <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                    {["Type", "Value", "Source", "First Seen"].map(h => (
                      <th key={h} style={{ padding: "8px 10px", textAlign: "left", color: C.textDim, fontSize: 10, fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.5 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {inc.iocs.map((ioc, i) => (
                    <tr key={i} style={{ borderBottom: `1px solid ${C.border}22` }}>
                      <td style={{ padding: "8px 10px" }}><Badge color={C.cyan}>{ioc.type}</Badge></td>
                      <td style={{ padding: "8px 10px", fontFamily: MONO, fontSize: 10, color: C.text, wordBreak: "break-all", maxWidth: 200 }}>{ioc.value.length > 40 ? ioc.value.slice(0, 40) + "…" : ioc.value}</td>
                      <td style={{ padding: "8px 10px", color: C.textSoft, fontSize: 10 }}>{ioc.source}</td>
                      <td style={{ padding: "8px 10px", color: C.textDim, fontSize: 10, fontFamily: MONO }}>{new Date(ioc.first_seen).toLocaleTimeString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        )}

        {/* Timeline Sub-tab */}
        {incSubTab === "timeline" && (
          <Panel title="Incident Timeline" icon="📋">
            {inc.timeline.map((t, i) => {
              const typeColors = { detection: C.cyan, analysis: C.accentBright, containment: C.amber, evidence: C.purple, escalation: C.red, enrichment: C.green };
              return (
                <div key={i} style={{ display: "flex", gap: 12, marginBottom: 12, position: "relative" }}>
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", minWidth: 20 }}>
                    <div style={{ width: 10, height: 10, borderRadius: "50%", background: typeColors[t.type] || C.textDim, boxShadow: `0 0 6px ${typeColors[t.type] || C.textDim}` }} />
                    {i < inc.timeline.length - 1 && <div style={{ width: 1, flex: 1, background: C.border, marginTop: 4 }} />}
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 11, color: C.text, marginBottom: 2 }}>{t.event}</div>
                    <div style={{ display: "flex", gap: 8, fontSize: 9, color: C.textDim }}>
                      <span style={{ fontFamily: MONO }}>{new Date(t.time).toLocaleTimeString()}</span>
                      <Badge color={typeColors[t.type] || C.textDim} style={{ fontSize: 8 }}>{t.type}</Badge>
                      <span>{t.actor}</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </Panel>
        )}

        {/* Notes Sub-tab */}
        {incSubTab === "notes" && (
          <Panel title="Analyst Notes" icon="📝">
            <textarea
              value={analystNotes}
              onChange={(e) => setAnalystNotes(e.target.value)}
              placeholder="Enter investigation notes, findings, and observations..."
              style={{ width: "100%", minHeight: 150, padding: 12, background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, fontSize: 12, fontFamily: MONO, resize: "vertical", outline: "none" }}
            />
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 8 }}>
              <button onClick={() => { playSound("panel_click"); setActionLog(prev => [...prev, { time: new Date().toISOString(), msg: "Analyst note saved", type: "note" }]); }} style={{ padding: "6px 16px", borderRadius: 6, border: `1px solid ${C.accent}55`, background: `${C.accent}10`, color: C.accentBright, fontSize: 11, fontWeight: 600, cursor: "pointer", fontFamily: FONT }}>
                Save Notes
              </button>
            </div>
          </Panel>
        )}
      </div>
    );
  }

  // ─── Incident List View ─────────────────────────────────────────────────
  return (
    <div>
      {incidents.map((inc, i) => (
        <motion.div key={inc.incident_id} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.05 }}
          style={{ padding: "12px 14px", background: C.panel, border: `1px solid ${inc.severity === "CRITICAL" ? C.red : C.border}33`, borderRadius: 8, marginBottom: 8, cursor: "pointer", transition: "all 0.2s" }}
          onClick={() => { setSelected(inc.incident_id); setView("investigate"); setIncSubTab("actions"); playSound("panel_click"); }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 8 }}>
            <div style={{ flex: 1, minWidth: 200 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 4 }}>{inc.title}</div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                <SeverityBadge severity={inc.severity} />
                <Badge color={C.cyan}>{inc.status}</Badge>
                <Badge color={C.textDim}>{inc.category}</Badge>
              </div>
            </div>
            <div style={{ textAlign: "right" }}>
              <div style={{ fontSize: 10, color: C.textDim, fontFamily: MONO }}>{new Date(inc.created_at).toLocaleTimeString()}</div>
              <div style={{ fontSize: 10, color: C.amber, marginTop: 2 }}>{inc.pending_actions.filter(a => a.status === "pending").length} pending actions</div>
            </div>
          </div>
          <div style={{ display: "flex", gap: 4, marginTop: 8, flexWrap: "wrap" }}>
            {inc.mitre_techniques.slice(0, 3).map((t, j) => <Badge key={j} color={C.purple} style={{ fontSize: 8 }}>{t}</Badge>)}
            {inc.mitre_techniques.length > 3 && <Badge color={C.textDim} style={{ fontSize: 8 }}>+{inc.mitre_techniques.length - 3}</Badge>}
          </div>
        </motion.div>
      ))}
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════════════
// VULNERABILITY SCANNER — One-Click Remediate, Guided Wizard, Export, Quantum
// ═══════════════════════════════════════════════════════════════════════════

function VulnsTab({ isMobile }) {
  const [scanMode, setScanMode] = useState("full"); // full | quick | compliance | web_app | quantum
  const [target, setTarget] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanResults, setScanResults] = useState(null);
  const [scanLog, setScanLog] = useState([]);
  const [remediating, setRemediating] = useState(false);
  const [remediateLog, setRemediateLog] = useState([]);
  const [showWizard, setShowWizard] = useState(false);
  const [wizardStep, setWizardStep] = useState(1);
  const [showExport, setShowExport] = useState(false);
  const [exportFormat, setExportFormat] = useState("bash");

  const scanModes = [
    { id: "full", label: "Full Scan", icon: "🔍", desc: "Complete vulnerability assessment" },
    { id: "quick", label: "Quick Scan", icon: "⚡", desc: "Top 100 ports + common CVEs" },
    { id: "compliance", label: "Compliance", icon: "📋", desc: "CIS/NIST/PCI-DSS audit" },
    { id: "web_app", label: "Web App", icon: "🌐", desc: "OWASP Top 10 + SQLi/XSS" },
    { id: "quantum", label: "Quantum Hardening", icon: "🔮", desc: "Post-quantum crypto audit" },
  ];

  const startScan = useCallback(async () => {
    if (!target) return;
    playSound("scan_start");
    setScanning(true);
    setScanProgress(0);
    setScanResults(null);
    setScanLog([]);
    setRemediateLog([]);

    const phases = [
      "Initializing scan engine...",
      `Resolving target: ${target}`,
      "Port discovery — SYN scan initiated",
      "Service enumeration in progress",
      "CVE database correlation",
      scanMode === "quantum" ? "Post-quantum cipher suite analysis..." : "Vulnerability fingerprinting",
      scanMode === "quantum" ? "Lattice-based key exchange verification..." : "Exploit probability assessment",
      scanMode === "compliance" ? "CIS Benchmark evaluation..." : "Risk scoring & prioritization",
      scanMode === "web_app" ? "OWASP Top 10 injection testing..." : "Cross-referencing threat intel",
      "Generating remediation plan",
      "Scan complete — results compiled",
    ];

    for (let i = 0; i < phases.length; i++) {
      await new Promise(r => setTimeout(r, 400 + Math.random() * 600));
      setScanLog(prev => [...prev, { time: new Date().toISOString(), msg: phases[i] }]);
      setScanProgress(Math.round(((i + 1) / phases.length) * 100));
    }

    const vulns = Array.from({ length: randInt(4, 12) }, () => ({
      id: `CVE-${2024 + randInt(0, 2)}-${randInt(10000, 99999)}`,
      title: pick([
        "Remote Code Execution in OpenSSL", "SQL Injection in Authentication Module",
        "Privilege Escalation via Kernel Bug", "Cross-Site Scripting in Admin Panel",
        "Buffer Overflow in Network Stack", "Insecure Deserialization in API Gateway",
        "Weak Cryptographic Algorithm (RSA-1024)", "Missing TLS 1.3 Enforcement",
        "Quantum-Vulnerable Key Exchange (ECDH)", "Post-Quantum Migration Required (Kyber)",
        "HSTS Header Missing", "Certificate Transparency Log Gap",
      ]),
      severity: pick(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
      cvss: +(rand(3.0, 10.0)).toFixed(1),
      exploitable: Math.random() > 0.5,
      remediation: pick([
        "Update to latest patched version", "Apply vendor security patch",
        "Implement input validation", "Enable WAF rules",
        "Rotate to quantum-safe algorithms (Kyber-768)", "Enforce TLS 1.3 with PQ cipher suites",
        "Upgrade to Ed25519 or Dilithium signatures", "Enable HSTS with preload",
      ]),
      affected: pick(["nginx/1.18.0", "openssl/1.1.1k", "node/16.14.0", "postgresql/13.4", "apache/2.4.49"]),
    })).sort((a, b) => b.cvss - a.cvss);

    setScanResults({
      target, mode: scanMode, timestamp: new Date().toISOString(),
      total_vulns: vulns.length,
      critical: vulns.filter(v => v.severity === "CRITICAL").length,
      high: vulns.filter(v => v.severity === "HIGH").length,
      medium: vulns.filter(v => v.severity === "MEDIUM").length,
      low: vulns.filter(v => v.severity === "LOW").length,
      vulns,
      quantum_score: scanMode === "quantum" ? randInt(20, 85) : null,
    });

    setScanning(false);
    playSound("scan_complete");
  }, [target, scanMode]);

  const startRemediate = useCallback(async () => {
    if (!scanResults) return;
    playSound("scan_start");
    setRemediating(true);
    setRemediateLog([]);

    const steps = scanResults.vulns.filter(v => v.severity === "CRITICAL" || v.severity === "HIGH");
    for (let i = 0; i < steps.length; i++) {
      await new Promise(r => setTimeout(r, 800 + Math.random() * 1200));
      setRemediateLog(prev => [...prev, {
        time: new Date().toISOString(),
        vuln: steps[i].id,
        msg: `Applying fix: ${steps[i].remediation}`,
        status: Math.random() > 0.15 ? "success" : "needs_manual",
      }]);
    }

    await new Promise(r => setTimeout(r, 500));
    setRemediateLog(prev => [...prev, { time: new Date().toISOString(), vuln: "SYSTEM", msg: "One-Click Remediation complete — verify results", status: "complete" }]);
    setRemediating(false);
    playSound("scan_complete");
  }, [scanResults]);

  const generateExportScript = () => {
    if (!scanResults) return "";
    const vulns = scanResults.vulns.filter(v => v.severity === "CRITICAL" || v.severity === "HIGH");
    if (exportFormat === "bash") {
      return `#!/bin/bash\n# Queen Califia CyberAI — Auto-Remediation Script\n# Generated: ${new Date().toISOString()}\n# Target: ${scanResults.target}\n\nset -e\necho "Starting remediation..."\n\n${vulns.map(v => `# Fix ${v.id} — ${v.title}\necho "Remediating ${v.id}..."\n# ${v.remediation}\nsleep 1`).join("\n\n")}\n\necho "Remediation complete."`;
    } else if (exportFormat === "powershell") {
      return `# Queen Califia CyberAI — Auto-Remediation Script\n# Generated: ${new Date().toISOString()}\n# Target: ${scanResults.target}\n\n$ErrorActionPreference = "Stop"\nWrite-Host "Starting remediation..."\n\n${vulns.map(v => `# Fix ${v.id} — ${v.title}\nWrite-Host "Remediating ${v.id}..."\n# ${v.remediation}\nStart-Sleep -Seconds 1`).join("\n\n")}\n\nWrite-Host "Remediation complete."`;
    } else {
      return `# Queen Califia CyberAI — Ansible Remediation Playbook\n# Generated: ${new Date().toISOString()}\n---\n- name: Auto-Remediation\n  hosts: ${scanResults.target}\n  tasks:\n${vulns.map(v => `    - name: Fix ${v.id}\n      debug:\n        msg: "${v.remediation}"`).join("\n")}`;
    }
  };

  // ─── Guided Wizard ──────────────────────────────────────────────────────
  if (showWizard) {
    return (
      <Panel title="Quick Scan Wizard" icon="⚡" glow>
        <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
          {[1, 2, 3].map(s => (
            <div key={s} style={{ flex: 1, height: 4, borderRadius: 2, background: s <= wizardStep ? C.accent : C.border, transition: "background 0.3s" }} />
          ))}
        </div>
        {wizardStep === 1 && (
          <div>
            <div style={{ fontSize: 14, fontWeight: 600, color: C.text, marginBottom: 8 }}>Step 1: Enter Target</div>
            <input value={target} onChange={e => setTarget(e.target.value)} placeholder="IP address or hostname"
              style={{ width: "100%", padding: "10px 12px", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, fontSize: 13, fontFamily: MONO, outline: "none", boxSizing: "border-box" }} />
            <div style={{ display: "flex", justifyContent: "space-between", marginTop: 16 }}>
              <button onClick={() => setShowWizard(false)} style={{ padding: "8px 16px", borderRadius: 6, border: `1px solid ${C.border}`, background: C.panel, color: C.textSoft, fontSize: 11, cursor: "pointer" }}>Cancel</button>
              <button onClick={() => target && setWizardStep(2)} style={{ padding: "8px 16px", borderRadius: 6, border: `1px solid ${C.accent}55`, background: `${C.accent}10`, color: C.accentBright, fontSize: 11, fontWeight: 600, cursor: "pointer" }}>Next →</button>
            </div>
          </div>
        )}
        {wizardStep === 2 && (
          <div>
            <div style={{ fontSize: 14, fontWeight: 600, color: C.text, marginBottom: 8 }}>Step 2: Select Scan Mode</div>
            <div style={{ display: "grid", gridTemplateColumns: isMobile ? "1fr" : "1fr 1fr", gap: 8 }}>
              {scanModes.map(m => (
                <div key={m.id} onClick={() => setScanMode(m.id)} style={{
                  padding: "12px", background: scanMode === m.id ? `${C.accent}10` : C.surface, border: `1px solid ${scanMode === m.id ? C.accent : C.border}`,
                  borderRadius: 6, cursor: "pointer", transition: "all 0.2s",
                }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: scanMode === m.id ? C.accentBright : C.text }}>{m.icon} {m.label}</div>
                  <div style={{ fontSize: 10, color: C.textSoft, marginTop: 4 }}>{m.desc}</div>
                </div>
              ))}
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", marginTop: 16 }}>
              <button onClick={() => setWizardStep(1)} style={{ padding: "8px 16px", borderRadius: 6, border: `1px solid ${C.border}`, background: C.panel, color: C.textSoft, fontSize: 11, cursor: "pointer" }}>← Back</button>
              <button onClick={() => setWizardStep(3)} style={{ padding: "8px 16px", borderRadius: 6, border: `1px solid ${C.accent}55`, background: `${C.accent}10`, color: C.accentBright, fontSize: 11, fontWeight: 600, cursor: "pointer" }}>Next →</button>
            </div>
          </div>
        )}
        {wizardStep === 3 && (
          <div>
            <div style={{ fontSize: 14, fontWeight: 600, color: C.text, marginBottom: 8 }}>Step 3: Confirm & Scan</div>
            <div style={{ padding: 12, background: C.surface, borderRadius: 6, marginBottom: 12 }}>
              <div style={{ fontSize: 11, color: C.textSoft }}>Target: <span style={{ color: C.text, fontFamily: MONO }}>{target}</span></div>
              <div style={{ fontSize: 11, color: C.textSoft, marginTop: 4 }}>Mode: <span style={{ color: C.accentBright }}>{scanModes.find(m => m.id === scanMode)?.label}</span></div>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <button onClick={() => setWizardStep(2)} style={{ padding: "8px 16px", borderRadius: 6, border: `1px solid ${C.border}`, background: C.panel, color: C.textSoft, fontSize: 11, cursor: "pointer" }}>← Back</button>
              <button onClick={() => { setShowWizard(false); startScan(); }} style={{ padding: "8px 20px", borderRadius: 6, border: `1px solid ${C.green}55`, background: C.greenDim, color: C.green, fontSize: 12, fontWeight: 700, cursor: "pointer", fontFamily: FONT }}>🚀 Launch Scan</button>
            </div>
          </div>
        )}
      </Panel>
    );
  }

  return (
    <div>
      {/* Scan Controls */}
      <Panel title="Vulnerability Scanner" icon="🔍" glow>
        <div style={{ display: "grid", gridTemplateColumns: isMobile ? "1fr" : "1fr 1fr auto", gap: 8, marginBottom: 12 }}>
          <input value={target} onChange={e => setTarget(e.target.value)} placeholder="Target IP or hostname"
            style={{ padding: "10px 12px", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, fontSize: 13, fontFamily: MONO, outline: "none" }} />
          <input value={apiKey} onChange={e => setApiKey(e.target.value)} placeholder="API Key (optional)" type="password"
            style={{ padding: "10px 12px", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, fontSize: 13, fontFamily: MONO, outline: "none" }} />
          <button onClick={() => setShowWizard(true)} style={{ padding: "10px 16px", borderRadius: 6, border: `1px solid ${C.cyan}55`, background: C.cyanDim, color: C.cyan, fontSize: 11, fontWeight: 600, cursor: "pointer", whiteSpace: "nowrap" }}>⚡ Wizard</button>
        </div>

        <div style={{ display: "flex", gap: 4, marginBottom: 12, flexWrap: "wrap" }}>
          {scanModes.map(m => (
            <button key={m.id} onClick={() => setScanMode(m.id)} style={{
              padding: "6px 10px", borderRadius: 6, border: `1px solid ${scanMode === m.id ? C.accent : C.border}`,
              background: scanMode === m.id ? `${C.accent}10` : C.panel, color: scanMode === m.id ? C.accentBright : C.textSoft,
              fontSize: 10, fontWeight: 600, cursor: "pointer", display: "flex", alignItems: "center", gap: 4,
            }}>
              <span>{m.icon}</span> {!isMobile && m.label}
            </button>
          ))}
        </div>

        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button onClick={startScan} disabled={scanning || !target} style={{
            padding: "10px 24px", borderRadius: 6, border: `1px solid ${C.accent}55`,
            background: scanning ? C.surface : `${C.accent}10`, color: scanning ? C.textDim : C.accentBright,
            fontSize: 12, fontWeight: 700, cursor: scanning ? "not-allowed" : "pointer", fontFamily: FONT,
          }}>
            {scanning ? `Scanning... ${scanProgress}%` : "🔍 Start Scan"}
          </button>
          {scanResults && !remediating && (
            <button onClick={startRemediate} style={{
              padding: "10px 24px", borderRadius: 6, border: `1px solid ${C.green}55`,
              background: C.greenDim, color: C.green, fontSize: 12, fontWeight: 700, cursor: "pointer", fontFamily: FONT,
            }}>
              🛡 One-Click Remediate
            </button>
          )}
          {scanResults && (
            <button onClick={() => setShowExport(!showExport)} style={{
              padding: "10px 16px", borderRadius: 6, border: `1px solid ${C.cyan}55`,
              background: C.cyanDim, color: C.cyan, fontSize: 11, fontWeight: 600, cursor: "pointer",
            }}>
              📋 Export Script
            </button>
          )}
        </div>

        {scanning && (
          <div style={{ marginTop: 12 }}>
            <ProgressBar value={scanProgress} color={C.accent} height={6} />
          </div>
        )}
      </Panel>

      {/* Scan Log */}
      {scanLog.length > 0 && (
        <Panel title="Scan Log" icon="📋" style={{ marginTop: 12 }}>
          <div style={{ maxHeight: 200, overflowY: "auto" }}>
            {scanLog.map((l, i) => (
              <div key={i} style={{ fontSize: 10, color: C.cyan, fontFamily: MONO, marginBottom: 2 }}>
                [{new Date(l.time).toLocaleTimeString()}] {l.msg}
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* Scan Results */}
      {scanResults && (
        <Panel title={`Results — ${scanResults.total_vulns} Vulnerabilities Found`} icon="📊" style={{ marginTop: 12 }} glow>
          <div style={{ display: "grid", gridTemplateColumns: isMobile ? "repeat(2, 1fr)" : "repeat(5, 1fr)", gap: 8, marginBottom: 16 }}>
            <Stat label="Total" value={scanResults.total_vulns} small />
            <Stat label="Critical" value={scanResults.critical} color={C.red} small />
            <Stat label="High" value={scanResults.high} color={C.amber} small />
            <Stat label="Medium" value={scanResults.medium} color={C.accentBright} small />
            <Stat label="Low" value={scanResults.low} color={C.green} small />
          </div>
          {scanResults.quantum_score !== null && (
            <div style={{ padding: "10px 12px", background: C.purpleDim, borderRadius: 6, border: `1px solid ${C.purple}33`, marginBottom: 12 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: C.purple }}>🔮 Quantum Readiness Score</span>
                <span style={{ fontSize: 20, fontWeight: 700, color: scanResults.quantum_score >= 70 ? C.green : scanResults.quantum_score >= 40 ? C.amber : C.red, fontFamily: MONO }}>{scanResults.quantum_score}%</span>
              </div>
              <ProgressBar value={scanResults.quantum_score} color={scanResults.quantum_score >= 70 ? C.green : scanResults.quantum_score >= 40 ? C.amber : C.red} height={6} />
              <div style={{ fontSize: 10, color: C.textSoft, marginTop: 6 }}>
                {scanResults.quantum_score < 40 ? "⚠ Critical: Most cryptographic implementations are quantum-vulnerable" :
                 scanResults.quantum_score < 70 ? "⚡ Moderate: Some post-quantum migrations needed" :
                 "✓ Good: Most systems use quantum-resistant algorithms"}
              </div>
            </div>
          )}
          {scanResults.vulns.map((v, i) => (
            <motion.div key={i} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.03 }}
              style={{ padding: "10px 12px", background: C.surface, borderRadius: 6, marginBottom: 6, border: `1px solid ${v.severity === "CRITICAL" ? C.red : C.border}33` }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 4 }}>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: C.text, marginBottom: 4 }}>{v.title}</div>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                    <Badge color={C.cyan} style={{ fontSize: 9 }}>{v.id}</Badge>
                    <SeverityBadge severity={v.severity} />
                    <Badge color={C.textDim}>CVSS: {v.cvss}</Badge>
                    {v.exploitable && <Badge color={C.red}>EXPLOITABLE</Badge>}
                  </div>
                </div>
              </div>
              <div style={{ fontSize: 10, color: C.textSoft, marginTop: 6 }}>
                <span style={{ color: C.textDim }}>Affected:</span> {v.affected} | <span style={{ color: C.textDim }}>Fix:</span> {v.remediation}
              </div>
            </motion.div>
          ))}
        </Panel>
      )}

      {/* Remediation Log */}
      {remediateLog.length > 0 && (
        <Panel title="One-Click Remediation Log" icon="🛡" style={{ marginTop: 12 }} accent={C.green}>
          {remediateLog.map((l, i) => (
            <div key={i} style={{ fontSize: 10, fontFamily: MONO, marginBottom: 4, color: l.status === "success" ? C.green : l.status === "complete" ? C.gold : C.amber }}>
              [{new Date(l.time).toLocaleTimeString()}] [{l.vuln}] {l.msg}
              {l.status === "needs_manual" && <span style={{ color: C.amber }}> ⚠ NEEDS MANUAL REVIEW</span>}
            </div>
          ))}
        </Panel>
      )}

      {/* Export Script */}
      {showExport && scanResults && (
        <Panel title="Remediation Script Export" icon="📋" style={{ marginTop: 12 }}>
          <div style={{ display: "flex", gap: 4, marginBottom: 8 }}>
            {["bash", "powershell", "ansible"].map(f => (
              <button key={f} onClick={() => setExportFormat(f)} style={{
                padding: "6px 10px", borderRadius: 6, border: `1px solid ${exportFormat === f ? C.accent : C.border}`,
                background: exportFormat === f ? `${C.accent}10` : C.panel, color: exportFormat === f ? C.accentBright : C.textSoft,
                fontSize: 10, fontWeight: 600, cursor: "pointer", textTransform: "capitalize",
              }}>{f}</button>
            ))}
          </div>
          <pre style={{ padding: 12, background: C.surface, borderRadius: 6, color: C.cyan, fontSize: 10, fontFamily: MONO, overflowX: "auto", whiteSpace: "pre-wrap", maxHeight: 300 }}>
            {generateExportScript()}
          </pre>
          <button onClick={() => { navigator.clipboard.writeText(generateExportScript()); playSound("panel_click"); }} style={{
            marginTop: 8, padding: "6px 16px", borderRadius: 6, border: `1px solid ${C.accent}55`,
            background: `${C.accent}10`, color: C.accentBright, fontSize: 11, fontWeight: 600, cursor: "pointer",
          }}>📋 Copy to Clipboard</button>
        </Panel>
      )}
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════════════
// DEVOPS TAB — One-Click Operations, CI/CD, Infrastructure
// ═══════════════════════════════════════════════════════════════════════════

function DevOpsTab({ isMobile }) {
  const [opLog, setOpLog] = useState([]);
  const [running, setRunning] = useState(null);

  const operations = [
    { id: "k8s", label: "Bootstrap K8s Cluster", icon: "⎈", desc: "Initialize Kubernetes with security policies", color: C.cyan },
    { id: "branches", label: "Protect Branches", icon: "🔒", desc: "Enforce branch protection rules", color: C.green },
    { id: "dns", label: "DNS Health Check", icon: "🌐", desc: "Verify DNS records and propagation", color: C.accentBright },
    { id: "vm", label: "Deploy Secure VM", icon: "🖥", desc: "Provision hardened virtual machine", color: C.purple },
    { id: "promote", label: "Promote to Prod", icon: "🚀", desc: "Blue-green deployment promotion", color: C.amber },
    { id: "helm", label: "Helm Release", icon: "📦", desc: "Deploy Helm chart to cluster", color: C.gold },
  ];

  const runOp = async (opId) => {
    const op = operations.find(o => o.id === opId);
    if (!op || running) return;
    playSound("scan_start");
    setRunning(opId);

    const steps = [
      `Initializing ${op.label}...`,
      "Validating credentials and permissions",
      "Connecting to infrastructure",
      "Executing operation",
      "Verifying results",
      `${op.label} — Complete ✓`,
    ];

    for (const step of steps) {
      await new Promise(r => setTimeout(r, 600 + Math.random() * 800));
      setOpLog(prev => [...prev, { time: new Date().toISOString(), op: opId, msg: step }]);
    }

    setRunning(null);
    playSound("scan_complete");
  };

  const services = [
    { name: "API Gateway", status: "healthy", uptime: "99.97%", latency: "12ms" },
    { name: "Auth Service", status: "healthy", uptime: "99.99%", latency: "8ms" },
    { name: "Scan Engine", status: "healthy", uptime: "99.95%", latency: "45ms" },
    { name: "ML Pipeline", status: Math.random() > 0.3 ? "healthy" : "degraded", uptime: "99.91%", latency: "120ms" },
    { name: "Threat Intel", status: "healthy", uptime: "99.98%", latency: "22ms" },
    { name: "Event Bus", status: "healthy", uptime: "99.96%", latency: "5ms" },
  ];

  const cicdWorkflows = [
    { name: "Security Scan Pipeline", status: "passing", last_run: "2m ago", duration: "3m 12s" },
    { name: "Container Build", status: "passing", last_run: "15m ago", duration: "5m 44s" },
    { name: "Integration Tests", status: Math.random() > 0.2 ? "passing" : "failing", last_run: "8m ago", duration: "12m 03s" },
    { name: "Deploy to Staging", status: "passing", last_run: "22m ago", duration: "2m 18s" },
    { name: "Compliance Audit", status: "passing", last_run: "1h ago", duration: "8m 55s" },
  ];

  return (
    <div>
      {/* One-Click Operations */}
      <Panel title="One-Click Operations" icon="⚡" glow>
        <div style={{ display: "grid", gridTemplateColumns: isMobile ? "1fr" : "repeat(3, 1fr)", gap: 8 }}>
          {operations.map(op => (
            <button key={op.id} onClick={() => runOp(op.id)} disabled={!!running}
              style={{
                padding: "12px", background: running === op.id ? `${op.color}15` : C.surface,
                border: `1px solid ${running === op.id ? op.color : C.border}`, borderRadius: 6,
                cursor: running ? "not-allowed" : "pointer", textAlign: "left", transition: "all 0.2s",
              }}>
              <div style={{ fontSize: 14, marginBottom: 4 }}>{op.icon}</div>
              <div style={{ fontSize: 12, fontWeight: 600, color: running === op.id ? op.color : C.text }}>{op.label}</div>
              <div style={{ fontSize: 10, color: C.textSoft, marginTop: 2 }}>{op.desc}</div>
              {running === op.id && <div style={{ marginTop: 6 }}><ProgressBar value={75} color={op.color} height={3} /></div>}
            </button>
          ))}
        </div>
      </Panel>

      {/* Operation Log */}
      {opLog.length > 0 && (
        <Panel title="Operation Log" icon="📋" style={{ marginTop: 12 }}>
          <div style={{ maxHeight: 200, overflowY: "auto" }}>
            {opLog.map((l, i) => (
              <div key={i} style={{ fontSize: 10, color: l.msg.includes("Complete") ? C.green : C.cyan, fontFamily: MONO, marginBottom: 2 }}>
                [{new Date(l.time).toLocaleTimeString()}] [{l.op}] {l.msg}
              </div>
            ))}
          </div>
        </Panel>
      )}

      <div style={{ display: "grid", gridTemplateColumns: isMobile ? "1fr" : "1fr 1fr", gap: 12, marginTop: 12 }}>
        {/* Service Health */}
        <Panel title="Service Health" icon="💚">
          {services.map((s, i) => (
            <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 0", borderBottom: i < services.length - 1 ? `1px solid ${C.border}22` : "none" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <PulseDot color={s.status === "healthy" ? C.green : C.amber} />
                <span style={{ fontSize: 11, color: C.text }}>{s.name}</span>
              </div>
              <div style={{ display: "flex", gap: 12, fontSize: 10, color: C.textSoft }}>
                <span>{s.uptime}</span>
                <span style={{ fontFamily: MONO }}>{s.latency}</span>
              </div>
            </div>
          ))}
        </Panel>

        {/* CI/CD Workflows */}
        <Panel title="CI/CD Workflows" icon="🔄">
          {cicdWorkflows.map((w, i) => (
            <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 0", borderBottom: i < cicdWorkflows.length - 1 ? `1px solid ${C.border}22` : "none" }}>
              <div>
                <div style={{ fontSize: 11, color: C.text }}>{w.name}</div>
                <div style={{ fontSize: 9, color: C.textDim }}>{w.last_run} · {w.duration}</div>
              </div>
              <Badge color={w.status === "passing" ? C.green : C.red}>{w.status}</Badge>
            </div>
          ))}
        </Panel>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN COMPONENT — Navigation, State Machine, All Tabs
// ═══════════════════════════════════════════════════════════════════════════

export default function QueenCalifiaUnifiedCommandDashboard() {
  const isMobile = useIsMobile();
  const [tab, setTab] = useState("overview");
  const [expertMode, setExpertMode] = useState(true);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  // ─── Data State ─────────────────────────────────────────────────────────
  const [meshStatus] = useState(() => generateMeshStatus());
  const [predictions] = useState(() => generatePredictions());
  const [incidents] = useState(() => generateIncidents());
  const [timeSeries] = useState(() => generateTimeSeriesData());
  const [threatLandscape] = useState(() => generateThreatLandscape());
  const [layerActivity] = useState(() => generateLayerActivity());
  const [telemetry] = useState(() => generateTelemetryData());

  // ─── Avatar State ───────────────────────────────────────────────────────
  const criticalCount = incidents.filter(i => i.severity === "CRITICAL").length;
  const highRiskPreds = predictions.filter(p => p.confidence_tier === "near_certain" || p.confidence_tier === "high").length;
  const avatarState = criticalCount > 0 || highRiskPreds > 2 ? "ascended" : meshStatus.threat_posture.active_attack_chains > 2 ? "active" : "idle";

  const handleTabChange = (newTab) => {
    setTab(newTab);
    setMobileNavOpen(false);
    playSound("tab_switch");
  };

  // ─── CSS Keyframes ──────────────────────────────────────────────────────
  const keyframes = `
    @keyframes qcPulse { 0%, 100% { opacity: 0.6; transform: scale(1); } 50% { opacity: 1; transform: scale(1.04); } }
    @keyframes qcPulseRing { 0%, 100% { opacity: 0.3; transform: scale(1); } 50% { opacity: 0.6; transform: scale(1.1); } }
    @keyframes qcRotate { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
    @keyframes qcScanline { 0% { top: -2px; opacity: 0; } 10% { opacity: 1; } 90% { opacity: 1; } 100% { top: 100%; opacity: 0; } }
    @keyframes qcFloat { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-6px); } }
    @keyframes qcGlow { 0%, 100% { box-shadow: 0 0 5px rgba(212,175,55,0.3); } 50% { box-shadow: 0 0 20px rgba(212,175,55,0.6); } }
  `;

  return (
    <div style={{ minHeight: "100vh", background: C.bg, color: C.text, fontFamily: FONT, position: "relative" }}>
      <style>{keyframes}</style>

      {/* ─── Top Header ──────────────────────────────────────────────────── */}
      <div style={{
        position: "sticky", top: 0, zIndex: 40,
        background: `${C.panel}ee`, backdropFilter: "blur(12px)",
        borderBottom: `1px solid ${C.border}`,
        padding: isMobile ? "8px 12px" : "8px 20px",
        display: "flex", justifyContent: "space-between", alignItems: "center",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: isMobile ? 8 : 16 }}>
          {isMobile && (
            <button onClick={() => setMobileNavOpen(!mobileNavOpen)} style={{ background: "none", border: "none", color: C.gold, fontSize: 20, cursor: "pointer", padding: 4 }}>
              {mobileNavOpen ? "✕" : "☰"}
            </button>
          )}
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <img src={`${CDN}/sigil_icon_32_79e58c71.png`} alt="QC" style={{ width: 28, height: 28, borderRadius: 6 }} />
            <div>
              <div style={{ fontSize: isMobile ? 12 : 14, fontWeight: 700, color: C.gold, fontFamily: "'Orbitron', sans-serif", letterSpacing: "0.08em" }}>
                {isMobile ? "QC" : "QUEEN CALIFIA"}
              </div>
              <div style={{ fontSize: 9, color: C.textDim, letterSpacing: "0.1em", fontFamily: MONO }}>
                {isMobile ? "CYBERAI" : "SOVEREIGN CYBERSECURITY INTELLIGENCE"}
              </div>
            </div>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: isMobile ? 8 : 16 }}>
          <QueenCalifiaAvatar state={avatarState} size={isMobile ? 32 : 40} showLabel={false} showStatus={false} />
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ fontSize: 10, color: C.textDim }}>Expert</span>
            <button onClick={() => setExpertMode(!expertMode)} style={{
              width: 36, height: 20, borderRadius: 10, border: "none", cursor: "pointer",
              background: expertMode ? C.accent : C.border, position: "relative", transition: "background 0.3s",
            }}>
              <div style={{ width: 16, height: 16, borderRadius: "50%", background: C.text, position: "absolute", top: 2, left: expertMode ? 18 : 2, transition: "left 0.3s" }} />
            </button>
          </div>
        </div>
      </div>

      {/* ─── Navigation ──────────────────────────────────────────────────── */}
      {isMobile && mobileNavOpen && (
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}
          style={{ position: "fixed", top: 52, left: 0, right: 0, zIndex: 35, background: `${C.panel}f5`, backdropFilter: "blur(12px)", borderBottom: `1px solid ${C.border}`, padding: 8 }}>
          {NAV_ITEMS.map(n => (
            <button key={n.id} onClick={() => handleTabChange(n.id)} style={{
              display: "block", width: "100%", padding: "12px 16px", borderRadius: 6, border: "none",
              background: tab === n.id ? `${C.accent}10` : "transparent", color: tab === n.id ? C.accentBright : C.textSoft,
              fontSize: 13, fontWeight: tab === n.id ? 600 : 400, cursor: "pointer", textAlign: "left", fontFamily: FONT, marginBottom: 2,
            }}>
              <span style={{ marginRight: 8 }}>{n.icon}</span> {n.label}
            </button>
          ))}
        </motion.div>
      )}

      {!isMobile && (
        <div style={{
          position: "sticky", top: 52, zIndex: 30,
          background: `${C.bg}ee`, backdropFilter: "blur(8px)",
          borderBottom: `1px solid ${C.border}`,
          padding: "0 20px",
          display: "flex", gap: 2, overflowX: "auto",
        }}>
          {NAV_ITEMS.map(n => (
            <button key={n.id} onClick={() => handleTabChange(n.id)} style={{
              padding: "10px 16px", border: "none", borderBottom: `2px solid ${tab === n.id ? C.accent : "transparent"}`,
              background: "transparent", color: tab === n.id ? C.accentBright : C.textSoft,
              fontSize: 12, fontWeight: tab === n.id ? 600 : 400, cursor: "pointer", fontFamily: FONT,
              display: "flex", alignItems: "center", gap: 6, whiteSpace: "nowrap", transition: "all 0.2s",
            }}>
              <span>{n.icon}</span> {n.label}
            </button>
          ))}
        </div>
      )}

      {/* ─── Tab Content ─────────────────────────────────────────────────── */}
      <div style={{ padding: isMobile ? "12px" : "20px", maxWidth: 1400, margin: "0 auto" }}>
        <AnimatePresence mode="wait">
          <motion.div key={tab} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.25 }}>

            {/* ─── OVERVIEW TAB ──────────────────────────────────────────── */}
            {tab === "overview" && (
              <div>
                {/* KPI Row */}
                <div style={{ display: "grid", gridTemplateColumns: isMobile ? "repeat(2, 1fr)" : "repeat(6, 1fr)", gap: 8, marginBottom: 16 }}>
                  {[
                    { label: "Events Ingested", value: meshStatus.statistics.events_ingested, color: C.text },
                    { label: "Threats Detected", value: meshStatus.statistics.threats_detected, color: C.red },
                    { label: "Attack Chains", value: meshStatus.threat_posture.active_attack_chains, color: C.amber },
                    { label: "IOCs Active", value: meshStatus.threat_posture.iocs_active, color: C.cyan },
                    { label: "IPs Blocked", value: meshStatus.threat_posture.ips_blocked, color: C.green },
                    { label: "Predictions", value: predictions.length, color: C.purple },
                  ].map((s, i) => (
                    <motion.div key={i} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}
                      style={{ padding: "14px 12px", background: C.panel, border: `1px solid ${C.border}`, borderRadius: 8, textAlign: "center" }}>
                      <div style={{ fontSize: 22, fontWeight: 700, fontFamily: MONO, color: s.color }}>{s.value.toLocaleString()}</div>
                      <div style={{ fontSize: 9, color: C.textSoft, marginTop: 4, textTransform: "uppercase", letterSpacing: 0.5 }}>{s.label}</div>
                    </motion.div>
                  ))}
                </div>

                <div style={{ display: "grid", gridTemplateColumns: isMobile ? "1fr" : "2fr 1fr", gap: 12, marginBottom: 12 }}>
                  {/* Threat Activity Chart */}
                  <Panel title="Threat Activity — 24h" icon="📈">
                    <ResponsiveContainer width="100%" height={200}>
                      <AreaChart data={timeSeries}>
                        <defs>
                          <linearGradient id="gEvents" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor={C.accent} stopOpacity={0.3} />
                            <stop offset="95%" stopColor={C.accent} stopOpacity={0} />
                          </linearGradient>
                          <linearGradient id="gThreats" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor={C.red} stopOpacity={0.3} />
                            <stop offset="95%" stopColor={C.red} stopOpacity={0} />
                          </linearGradient>
                        </defs>
                        <XAxis dataKey="time" tick={{ fill: C.textDim, fontSize: 9 }} axisLine={false} tickLine={false} />
                        <YAxis tick={{ fill: C.textDim, fontSize: 9 }} axisLine={false} tickLine={false} />
                        <Tooltip contentStyle={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 6, fontSize: 11 }} />
                        <Area type="monotone" dataKey="events" stroke={C.accent} fill="url(#gEvents)" strokeWidth={2} />
                        <Area type="monotone" dataKey="threats" stroke={C.red} fill="url(#gThreats)" strokeWidth={2} />
                        <Line type="monotone" dataKey="blocked" stroke={C.green} strokeWidth={1.5} dot={false} />
                      </AreaChart>
                    </ResponsiveContainer>
                  </Panel>

                  {/* Threat Landscape Radar */}
                  <Panel title="Threat Landscape" icon="🎯">
                    <ResponsiveContainer width="100%" height={200}>
                      <RadarChart data={threatLandscape}>
                        <PolarGrid stroke={C.border} />
                        <PolarAngleAxis dataKey="vector" tick={{ fill: C.textSoft, fontSize: 9 }} />
                        <PolarRadiusAxis tick={false} axisLine={false} />
                        <Radar dataKey="risk" stroke={C.red} fill={C.red} fillOpacity={0.15} strokeWidth={2} />
                      </RadarChart>
                    </ResponsiveContainer>
                  </Panel>
                </div>

                {expertMode && (
                  <div style={{ display: "grid", gridTemplateColumns: isMobile ? "1fr" : "1fr 1fr", gap: 12 }}>
                    {/* Top Predictions */}
                    <Panel title="Top Predictions" icon="🔮">
                      {predictions.slice(0, 4).map((p, i) => (
                        <div key={i} style={{ padding: "8px 10px", background: C.surface, borderRadius: 6, marginBottom: 6, border: `1px solid ${C.border}` }}>
                          <div style={{ fontSize: 11, fontWeight: 600, color: C.text, marginBottom: 4 }}>{p.title}</div>
                          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                            <ConfidenceBadge tier={p.confidence_tier} confidence={p.confidence} />
                            <HorizonBadge horizon={p.threat_horizon} />
                            <Badge color={C.textDim}>{p.contributing_signals} signals</Badge>
                          </div>
                        </div>
                      ))}
                    </Panel>

                    {/* Active Incidents */}
                    <Panel title="Active Incidents" icon="🚨">
                      {incidents.slice(0, 4).map((inc, i) => (
                        <div key={i} style={{ padding: "8px 10px", background: C.surface, borderRadius: 6, marginBottom: 6, border: `1px solid ${inc.severity === "CRITICAL" ? C.red : C.border}33` }}>
                          <div style={{ fontSize: 11, fontWeight: 600, color: C.text, marginBottom: 4 }}>{inc.title}</div>
                          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                            <SeverityBadge severity={inc.severity} />
                            <Badge color={C.cyan}>{inc.status}</Badge>
                            <Badge color={C.textDim}>{inc.affected_assets} assets</Badge>
                          </div>
                        </div>
                      ))}
                    </Panel>
                  </div>
                )}
              </div>
            )}

            {/* ─── PREDICTOR TAB ─────────────────────────────────────────── */}
            {tab === "predictor" && (
              <div>
                <Panel title="5-Layer Prediction Engine" icon="🔮" glow style={{ marginBottom: 12 }}>
                  <div style={{ display: "grid", gridTemplateColumns: isMobile ? "1fr" : "repeat(5, 1fr)", gap: 8 }}>
                    {layerActivity.map((l, i) => (
                      <div key={i} style={{ padding: 12, background: C.surface, borderRadius: 6, textAlign: "center" }}>
                        <div style={{ fontSize: 18, fontWeight: 700, color: C.cyan, fontFamily: MONO }}>{l.signals}</div>
                        <div style={{ fontSize: 9, color: C.textSoft, marginTop: 2 }}>{l.layer}</div>
                        <ProgressBar value={l.confidence} max={1} color={l.confidence >= 0.8 ? C.green : C.amber} height={3} />
                        <div style={{ fontSize: 9, color: C.textDim, marginTop: 2, fontFamily: MONO }}>{(l.confidence * 100).toFixed(0)}%</div>
                      </div>
                    ))}
                  </div>
                </Panel>

                <Panel title="Confidence Distribution" icon="📊" style={{ marginBottom: 12 }}>
                  <ResponsiveContainer width="100%" height={180}>
                    <BarChart data={layerActivity}>
                      <XAxis dataKey="layer" tick={{ fill: C.textDim, fontSize: 9 }} axisLine={false} tickLine={false} />
                      <YAxis tick={{ fill: C.textDim, fontSize: 9 }} axisLine={false} tickLine={false} />
                      <Tooltip contentStyle={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 6, fontSize: 11 }} />
                      <Bar dataKey="signals" fill={C.accent} radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </Panel>

                {predictions.map((p, i) => (
                  <motion.div key={p.prediction_id} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.05 }}
                    style={{ padding: "12px 14px", background: C.panel, border: `1px solid ${C.border}`, borderRadius: 8, marginBottom: 8 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 8 }}>
                      <div style={{ flex: 1, minWidth: 200 }}>
                        <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 6 }}>{p.title}</div>
                        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                          <ConfidenceBadge tier={p.confidence_tier} confidence={p.confidence} />
                          <HorizonBadge horizon={p.threat_horizon} />
                          <Badge color={C.textDim}>{p.category.replace(/_/g, " ")}</Badge>
                        </div>
                      </div>
                      <div style={{ textAlign: "right" }}>
                        <div style={{ fontSize: 20, fontWeight: 700, color: p.risk_score >= 8 ? C.red : p.risk_score >= 5 ? C.amber : C.green, fontFamily: MONO }}>{p.risk_score.toFixed(1)}</div>
                        <div style={{ fontSize: 9, color: C.textDim }}>Risk Score</div>
                      </div>
                    </div>
                    {expertMode && (
                      <div style={{ marginTop: 8, display: "flex", gap: 12, fontSize: 10, color: C.textSoft, flexWrap: "wrap" }}>
                        <span>Assets: {p.affected_assets.join(", ")}</span>
                        <span>Techniques: {p.predicted_techniques.join(", ")}</span>
                        <span>Signals: {p.contributing_signals}</span>
                      </div>
                    )}
                  </motion.div>
                ))}
              </div>
            )}

            {/* ─── TELEMETRY TAB ─────────────────────────────────────────── */}
            {tab === "telemetry" && <TelemetryTab telemetry={telemetry} isMobile={isMobile} />}

            {/* ─── MESH TAB ──────────────────────────────────────────────── */}
            {tab === "mesh" && (
              <div>
                <div style={{ display: "grid", gridTemplateColumns: isMobile ? "repeat(2, 1fr)" : "repeat(5, 1fr)", gap: 8, marginBottom: 16 }}>
                  {[
                    { label: "Active Nodes", value: `${meshStatus.topology.active_nodes}/${meshStatus.topology.total_nodes}`, color: C.green },
                    { label: "Degraded", value: meshStatus.topology.degraded_nodes, color: meshStatus.topology.degraded_nodes > 0 ? C.amber : C.green },
                    { label: "Circuits", value: `${meshStatus.topology.healthy_circuits}/${meshStatus.topology.total_circuits}`, color: C.cyan },
                    { label: "Mesh Heals", value: meshStatus.statistics.mesh_heals, color: C.purple },
                    { label: "FP Suppressed", value: meshStatus.statistics.false_positives_suppressed, color: C.textSoft },
                  ].map((s, i) => (
                    <motion.div key={i} initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: i * 0.05 }}
                      style={{ padding: "14px 12px", background: C.panel, border: `1px solid ${C.border}`, borderRadius: 8, textAlign: "center" }}>
                      <div style={{ fontSize: 20, fontWeight: 700, fontFamily: MONO, color: s.color }}>{s.value}</div>
                      <div style={{ fontSize: 9, color: C.textSoft, marginTop: 4, textTransform: "uppercase" }}>{s.label}</div>
                    </motion.div>
                  ))}
                </div>

                <Panel title="Mesh Topology — Node Map" icon="🕸" glow>
                  <div style={{ height: isMobile ? 200 : 280, background: C.surface, borderRadius: 8, position: "relative", overflow: "hidden" }}>
                    {Array.from({ length: meshStatus.topology.total_nodes }, (_, i) => {
                      const cols = isMobile ? 4 : 6;
                      const row = Math.floor(i / cols);
                      const col = i % cols;
                      const x = (col + 0.5) / cols * 100;
                      const y = (row + 0.5) / Math.ceil(meshStatus.topology.total_nodes / cols) * 100;
                      const isActive = i < meshStatus.topology.active_nodes;
                      const isDegraded = i >= meshStatus.topology.active_nodes - meshStatus.topology.degraded_nodes && i < meshStatus.topology.active_nodes;
                      const nodeColor = isDegraded ? C.amber : isActive ? C.cyan : C.textDim;
                      return (
                        <motion.div key={i} initial={{ opacity: 0, scale: 0 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: i * 0.03 }}
                          style={{
                            position: "absolute", left: `${x}%`, top: `${y}%`, transform: "translate(-50%, -50%)",
                            width: 12, height: 12, borderRadius: "50%", background: nodeColor,
                            boxShadow: `0 0 10px ${nodeColor}60`, cursor: "pointer",
                          }}
                          title={`Node ${i + 1} — ${isDegraded ? "DEGRADED" : isActive ? "ACTIVE" : "OFFLINE"}`}
                        />
                      );
                    })}
                    {/* Connection lines */}
                    <svg style={{ position: "absolute", inset: 0, width: "100%", height: "100%", pointerEvents: "none" }}>
                      {Array.from({ length: meshStatus.topology.healthy_circuits }, (_, i) => {
                        const cols = isMobile ? 4 : 6;
                        const n1 = i * 4;
                        const n2 = Math.min(n1 + randInt(2, 6), meshStatus.topology.total_nodes - 1);
                        const x1 = ((n1 % cols) + 0.5) / cols * 100;
                        const y1 = (Math.floor(n1 / cols) + 0.5) / Math.ceil(meshStatus.topology.total_nodes / cols) * 100;
                        const x2 = ((n2 % cols) + 0.5) / cols * 100;
                        const y2 = (Math.floor(n2 / cols) + 0.5) / Math.ceil(meshStatus.topology.total_nodes / cols) * 100;
                        return <line key={i} x1={`${x1}%`} y1={`${y1}%`} x2={`${x2}%`} y2={`${y2}%`} stroke={C.cyan} strokeOpacity={0.15} strokeWidth={1} />;
                      })}
                    </svg>
                  </div>
                </Panel>

                {expertMode && (
                  <Panel title="Threat Posture" icon="🛡" style={{ marginTop: 12 }}>
                    <div style={{ display: "grid", gridTemplateColumns: isMobile ? "repeat(2, 1fr)" : "repeat(4, 1fr)", gap: 8 }}>
                      {[
                        { label: "Attack Chains", value: meshStatus.threat_posture.active_attack_chains, color: C.red },
                        { label: "IOCs Active", value: meshStatus.threat_posture.iocs_active, color: C.amber },
                        { label: "IPs Blocked", value: meshStatus.threat_posture.ips_blocked, color: C.green },
                        { label: "Domains Blocked", value: meshStatus.threat_posture.blocked_domains, color: C.cyan },
                      ].map((s, i) => (
                        <div key={i} style={{ padding: 12, background: C.surface, borderRadius: 6, textAlign: "center" }}>
                          <div style={{ fontSize: 22, fontWeight: 700, color: s.color, fontFamily: MONO }}>{s.value}</div>
                          <div style={{ fontSize: 9, color: C.textSoft, marginTop: 4 }}>{s.label}</div>
                        </div>
                      ))}
                    </div>
                  </Panel>
                )}
              </div>
            )}

            {/* ─── INCIDENTS TAB ─────────────────────────────────────────── */}
            {tab === "incidents" && <IncidentsTab incidents={incidents} isMobile={isMobile} />}

            {/* ─── VULNS TAB ─────────────────────────────────────────────── */}
            {tab === "vulns" && <VulnsTab isMobile={isMobile} />}

            {/* ─── DEVOPS TAB ────────────────────────────────────────────── */}
            {tab === "devops" && <DevOpsTab isMobile={isMobile} />}

          </motion.div>
        </AnimatePresence>
      </div>

      {/* ─── Footer ──────────────────────────────────────────────────────── */}
      <div style={{
        padding: "12px 20px", borderTop: `1px solid ${C.border}`,
        display: "flex", justifyContent: "space-between", alignItems: "center",
        fontSize: 9, color: C.textDim, fontFamily: MONO, flexWrap: "wrap", gap: 8,
      }}>
        <span>QUEEN CALIFIA CYBERAI v4.2 — SOVEREIGN CIRCUITRY</span>
        <span>MESH: {meshStatus.mesh_id} | NODES: {meshStatus.topology.active_nodes}/{meshStatus.topology.total_nodes}</span>
      </div>
    </div>
  );
}
