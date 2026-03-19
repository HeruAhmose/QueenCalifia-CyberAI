import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { LineChart, Line, AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Cell, PieChart, Pie } from "recharts";
import QueenCalifiaAvatar from "./components/QueenCalifiaAvatar.jsx";

/*
 * QueenCalifia CyberAI — Unified Command Dashboard
 * 
 * Defense-Grade Cybersecurity Intelligence Platform
 * Zero-Day Prediction • Threat Mesh • Incident Response • DevOps Ops
 * 
 * Tamerian Materials / QueenCalifia-CyberAI
 * 
 * Architecture:
 *   ┌─ STRATEGIC OVERVIEW ──────────────────────────────┐
 *   │  Threat posture • Mesh health • Predictions       │
 *   ├─ ZERO-DAY PREDICTOR ──────────────────────────────┤
 *   │  5-layer prediction engine • Campaign tracking     │
 *   ├─ SECURITY MESH ──────────────────────────────────-─┤
 *   │  Node topology • Attack chains • IOC management    │
 *   ├─ INCIDENT RESPONSE ───────────────────────────────┤
 *   │  Active incidents • Playbook execution • Forensics │
 *   ├─ VULNERABILITY SCANNER ───────────────────────────┤
 *   │  Asset inventory • CVE correlation • Compliance    │
 *   └─ DEVOPS OPERATIONS ───────────────────────────────┘
 *     K8s bootstrap • Branch protection • DNS sanity     
 */

// ─── Color System ─────────────────────────────────────────────────────────
const C = {
  void: "#020409",
  bg: "#060a14",
  panel: "#0a0f1e",
  panelHover: "#0e1528",
  surface: "#111b2e",
  border: "#131d33",
  borderLit: "#1a2d50",
  borderHot: "#2563eb",
  glow: "rgba(37,99,235,0.06)",
  glowHot: "rgba(37,99,235,0.14)",
  text: "#d4dff0",
  textSoft: "#8a9dbd",
  textDim: "#4a6080",
  accent: "#2563eb",
  accentBright: "#60a5fa",
  green: "#10b981",
  greenDim: "rgba(16,185,129,0.10)",
  greenGlow: "rgba(16,185,129,0.04)",
  amber: "#f59e0b",
  amberDim: "rgba(245,158,11,0.10)",
  red: "#ef4444",
  redDim: "rgba(239,68,68,0.08)",
  redGlow: "rgba(239,68,68,0.04)",
  cyan: "#06b6d4",
  cyanDim: "rgba(6,182,212,0.06)",
  purple: "#a78bfa",
  purpleDim: "rgba(167,139,250,0.08)",
  magenta: "#ec4899",
  magentaDim: "rgba(236,72,153,0.08)",
};

const FONT = "'DM Sans', 'SF Pro Display', -apple-system, BlinkMacSystemFont, sans-serif";
const MONO = "'JetBrains Mono', 'SF Mono', 'Fira Code', Consolas, monospace";

// ─── Simulated Data Generators ────────────────────────────────────────────

const now = () => new Date();
const ago = (ms) => new Date(Date.now() - ms);
const rand = (min, max) => Math.random() * (max - min) + min;
const randInt = (min, max) => Math.floor(rand(min, max));
const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];
const uuid8 = () => Math.random().toString(36).slice(2, 10).toUpperCase();

function generateMeshStatus() {
  return {
    mesh_id: "QC-" + uuid8(),
    topology: { total_nodes: 24, active_nodes: randInt(21, 24), degraded_nodes: randInt(0, 3), healthy_circuits: 6, total_circuits: 6 },
    threat_posture: {
      active_attack_chains: randInt(0, 4),
      iocs_active: randInt(45, 200),
      ips_blocked: randInt(20, 80),
      blocked_domains: randInt(30, 120),
    },
    statistics: {
      events_ingested: randInt(50000, 250000),
      threats_detected: randInt(5, 30),
      attacks_correlated: randInt(1, 8),
      mesh_heals: randInt(0, 5),
      false_positives_suppressed: randInt(10, 50),
    },
  };
}

function generatePredictions() {
  const categories = ["novel_exploit", "variant_mutation", "supply_chain_injection", "living_off_the_land", "encrypted_channel_abuse", "config_drift_exploit", "polymorphic_payload", "ai_generated_malware"];
  const horizons = ["0-1h", "1-24h", "1-7d", "7-30d"];
  const tiers = ["speculative", "emerging", "probable", "high", "near_certain"];
  return Array.from({ length: randInt(3, 8) }, (_, i) => {
    const confidence = rand(0.25, 0.97);
    const tier = confidence > 0.95 ? "near_certain" : confidence > 0.8 ? "high" : confidence > 0.6 ? "probable" : confidence > 0.3 ? "emerging" : "speculative";
    return {
      prediction_id: `PRED-${uuid8()}`,
      category: pick(categories),
      title: pick([
        "Novel Exploit Targeting Edge Gateway",
        "AI-Generated Phishing Campaign Imminent",
        "Supply Chain Injection — npm Registry",
        "Encrypted C2 Channel Establishing",
        "LOTL Attack via PowerShell Remoting",
        "Configuration Drift Creating RCE Window",
        "Polymorphic Payload Variant Detected",
        "Identity Fabric Attack — OAuth Token Theft",
        "Firmware-Level Persistence Attempt",
        "DNS Tunneling with ML Evasion",
      ]),
      confidence: Math.round(confidence * 1000) / 1000,
      confidence_tier: tier,
      threat_horizon: pick(horizons),
      risk_score: Math.round(confidence * rand(6, 10) * 100) / 100,
      affected_assets: Array.from({ length: randInt(1, 4) }, () => `10.0.${randInt(1, 5)}.${randInt(10, 200)}`),
      contributing_signals: randInt(2, 12),
      predicted_techniques: Array.from({ length: randInt(1, 4) }, () => `T${randInt(1000, 1600)}`),
      created_at: ago(randInt(60000, 7200000)).toISOString(),
    };
  }).sort((a, b) => b.confidence - a.confidence);
}

function generateIncidents() {
  const cats = ["ransomware", "apt", "data_breach", "unauthorized_access", "phishing", "lateral_movement"];
  const statuses = ["triaged", "investigating", "containing", "eradicating", "recovering"];
  const actionTypes = [
    { action: "Block IP at perimeter firewall", type: "containment", risk: "low" },
    { action: "Isolate host from network segment", type: "containment", risk: "medium" },
    { action: "Disable compromised user account", type: "containment", risk: "medium" },
    { action: "Quarantine malicious binary", type: "containment", risk: "low" },
    { action: "Revoke active session tokens", type: "containment", risk: "medium" },
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
    { type: "email_artifact", desc: "Phishing email with weaponized attachment" },
    { type: "registry_export", desc: "Modified Run keys — persistence mechanism" },
    { type: "screenshot", desc: "Desktop capture at time of alert" },
  ];
  const iocTypes = [
    { type: "ip", value: () => `${randInt(45,220)}.${randInt(0,255)}.${randInt(0,255)}.${randInt(1,254)}` },
    { type: "domain", value: () => pick(["evil-update.","c2-relay.","data-sync.","api-check.","cdn-fast."]) + pick(["xyz","top","cc","ru","cn","tk"]) },
    { type: "hash_sha256", value: () => Array.from({length:64},()=>"0123456789abcdef"[randInt(0,16)]).join("") },
    { type: "file_path", value: () => pick(["C:\\\\Users\\\\Public\\\\svchost.exe","C:\\\\Temp\\\\update.dll","/tmp/.hidden/beacon","/var/tmp/kworker"]) },
    { type: "user_agent", value: () => pick(["Mozilla/5.0 (compatible; MSIE 6.0)","curl/7.68.0","python-requests/2.28.1"]) },
  ];
  return Array.from({ length: randInt(3, 6) }, () => {
    const createdAt = ago(randInt(300000, 86400000));
    const numActions = randInt(1, 5);
    const numEvidence = randInt(1, 5);
    const numIocs = randInt(2, 6);
    const numTimeline = randInt(4, 10);
    return {
      incident_id: `INC-${uuid8()}`,
      title: pick(["Ransomware Activity Detected — Workstation Cluster", "APT28 Campaign Indicators — DMZ Servers", "Data Exfiltration Attempt — HR Database", "Brute Force Attack — VPN Gateway", "Phishing Campaign — Executive Team", "Lateral Movement — Domain Controller", "Credential Stuffing — SSO Portal", "Cryptominer Deployment — Build Servers"]),
      severity: pick(["CRITICAL", "HIGH", "MEDIUM"]),
      category: pick(cats),
      status: pick(statuses),
      affected_assets: randInt(1, 12),
      actions_pending: numActions,
      evidence_collected: numEvidence,
      created_at: createdAt.toISOString(),
      containment_time_min: rand(2, 45),
      lead_analyst: pick(["J. Torres", "S. Chen", "M. Okoro", "R. Patel", "A. Rodriguez"]),
      playbook: pick(["PB-RANSOM-01", "PB-APT-02", "PB-BREACH-01", "PB-PHISH-01", "PB-LATERAL-01"]),
      mitre_techniques: Array.from({ length: randInt(2, 5) }, () => pick([
        "T1059.001 — PowerShell", "T1071.001 — Web Protocols", "T1486 — Data Encrypted for Impact",
        "T1566.001 — Spearphishing Attachment", "T1078 — Valid Accounts", "T1021.001 — Remote Desktop",
        "T1053.005 — Scheduled Task", "T1055 — Process Injection", "T1003 — OS Credential Dumping",
        "T1070.004 — File Deletion", "T1105 — Ingress Tool Transfer", "T1047 — WMI",
        "T1036.005 — Match Legitimate Name", "T1497 — Virtualization Evasion", "T1083 — File Discovery",
      ])),
      pending_actions: Array.from({ length: numActions }, (_, i) => {
        const a = pick(actionTypes);
        return { id: `ACT-${uuid8()}`, ...a, status: "pending", requested_by: pick(["SYSTEM","QueenCalifia AI","Analyst"]), requested_at: ago(randInt(60000, 600000)).toISOString() };
      }),
      evidence: Array.from({ length: numEvidence }, (_, i) => {
        const e = pick(evidenceTypes);
        return { id: `EV-${uuid8()}`, ...e, collected_at: ago(randInt(120000, 3600000)).toISOString(), size_mb: +(rand(0.1, 500)).toFixed(1), chain_of_custody: `SHA256:${Array.from({length:16},()=>"0123456789abcdef"[randInt(0,16)]).join("")}…` };
      }),
      iocs: Array.from({ length: numIocs }, () => {
        const ioc = pick(iocTypes);
        return { type: ioc.type, value: ioc.value(), first_seen: ago(randInt(300000, 7200000)).toISOString(), source: pick(["network_flow","endpoint_agent","dns_logs","auth_logs","telemetry_t1"]) };
      }),
      timeline: Array.from({ length: numTimeline }, (_, i) => ({
        time: new Date(createdAt.getTime() + i * randInt(30000, 600000)).toISOString(),
        event: pick([
          "Initial alert triggered — anomalous outbound connection",
          "Correlated with TLS fingerprint match (Cobalt Strike JA3)",
          "Endpoint agent reported suspicious process injection",
          "Automated containment initiated — host isolation pending approval",
          "Evidence collection started — memory dump in progress",
          "MITRE technique mapped — T1059.001 PowerShell execution",
          "Lateral movement attempt detected to adjacent subnet",
          "DNS beaconing pattern confirmed by telemetry T2",
          "Analyst escalated to CRITICAL — multiple assets affected",
          "Playbook PB-RANSOM-01 activated — awaiting action approval",
          "IOC extracted — C2 domain added to blocklist",
          "Forensic disk image acquisition completed",
          "Credential rotation triggered for 3 affected accounts",
          "Network segment quarantine applied",
          "Threat intel enrichment — APT28 TTP match confirmed",
        ]),
        actor: pick(["QueenCalifia AI", "System", "Analyst", "Telemetry T1", "Telemetry T2", "Predictor L3"]),
        type: pick(["detection", "analysis", "containment", "evidence", "escalation", "enrichment"]),
      })).sort((a, b) => new Date(a.time) - new Date(b.time)),
    };
  });
}

function generateTimeSeriesData(points = 24) {
  let base = randInt(500, 2000);
  return Array.from({ length: points }, (_, i) => {
    base += randInt(-200, 300);
    base = Math.max(100, base);
    return {
      time: `${String(i).padStart(2, "0")}:00`,
      events: base,
      threats: Math.max(0, Math.floor(base * rand(0.001, 0.015))),
      predictions: Math.max(0, Math.floor(base * rand(0.0005, 0.005))),
      blocked: Math.max(0, Math.floor(base * rand(0.003, 0.01))),
    };
  });
}

function generateThreatLandscape() {
  return [
    { vector: "Ransomware", risk: rand(65, 95), trend: "accelerating" },
    { vector: "Identity", risk: rand(55, 85), trend: "accelerating" },
    { vector: "Supply Chain", risk: rand(50, 80), trend: "escalating" },
    { vector: "AI-Augmented", risk: rand(40, 75), trend: "emerging" },
    { vector: "Cloud Native", risk: rand(45, 70), trend: "accelerating" },
    { vector: "Zero-Day Market", risk: rand(55, 90), trend: "expanding" },
    { vector: "Firmware/HW", risk: rand(25, 55), trend: "emerging" },
    { vector: "Encrypted Ch.", risk: rand(35, 60), trend: "stable" },
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

// ─── Micro Components ─────────────────────────────────────────────────────

const Badge = ({ children, color = C.accent, bg, style }) => (
  <span style={{
    display: "inline-flex", alignItems: "center", gap: 4,
    padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600,
    fontFamily: MONO, letterSpacing: 0.5, textTransform: "uppercase",
    color, background: bg || `${color}18`, border: `1px solid ${color}30`,
    whiteSpace: "nowrap", ...style,
  }}>{children}</span>
);

const SeverityBadge = ({ severity }) => {
  const map = {
    CRITICAL: { color: C.red, label: "CRITICAL" },
    HIGH: { color: C.amber, label: "HIGH" },
    MEDIUM: { color: C.accentBright, label: "MEDIUM" },
    LOW: { color: C.green, label: "LOW" },
  };
  const s = map[severity] || map.MEDIUM;
  return <Badge color={s.color}>{s.label}</Badge>;
};

const ConfidenceBadge = ({ tier, confidence }) => {
  const map = {
    near_certain: { color: C.red, icon: "◆" },
    high: { color: C.amber, icon: "▲" },
    probable: { color: C.accentBright, icon: "●" },
    emerging: { color: C.cyan, icon: "◐" },
    speculative: { color: C.textDim, icon: "○" },
  };
  const s = map[tier] || map.emerging;
  return (
    <Badge color={s.color}>
      {s.icon} {(confidence * 100).toFixed(1)}%
    </Badge>
  );
};

const HorizonBadge = ({ horizon }) => {
  const map = {
    "0-1h": { color: C.red, label: "IMMEDIATE" },
    "1-24h": { color: C.amber, label: "24H" },
    "1-7d": { color: C.accentBright, label: "7D" },
    "7-30d": { color: C.textSoft, label: "30D" },
    "30d+": { color: C.textDim, label: "STRATEGIC" },
  };
  const s = map[horizon] || map["1-7d"];
  return <Badge color={s.color}>{s.label}</Badge>;
};

const Stat = ({ label, value, sub, color = C.text, trend, small }) => (
  <div style={{ textAlign: "center", minWidth: small ? 60 : 80 }}>
    <div style={{ fontSize: small ? 22 : 28, fontWeight: 700, fontFamily: MONO, color, lineHeight: 1.1 }}>
      {typeof value === "number" ? value.toLocaleString() : value}
    </div>
    {sub && <div style={{ fontSize: 10, color: C.textDim, fontFamily: MONO, marginTop: 2 }}>{sub}</div>}
    <div style={{ fontSize: 10, color: C.textSoft, marginTop: 2, letterSpacing: 0.3, textTransform: "uppercase" }}>{label}</div>
    {trend && <div style={{ fontSize: 9, color: trend === "up" ? C.green : trend === "down" ? C.red : C.textDim, marginTop: 1 }}>{trend === "up" ? "▲" : trend === "down" ? "▼" : "─"}</div>}
  </div>
);

const Panel = ({ children, title, icon, accent = C.accent, style, headerRight, glow }) => (
  <div style={{
    background: C.panel, border: `1px solid ${C.border}`,
    borderRadius: 8, overflow: "hidden",
    boxShadow: glow ? `0 0 30px ${accent}08, inset 0 1px 0 ${accent}10` : `inset 0 1px 0 ${C.borderLit}20`,
    ...style,
  }}>
    {title && (
      <div style={{
        display: "flex", justifyContent: "space-between", alignItems: "center",
        padding: "10px 16px", borderBottom: `1px solid ${C.border}`,
        background: `linear-gradient(135deg, ${accent}06 0%, transparent 60%)`,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {icon && <span style={{ fontSize: 14 }}>{icon}</span>}
          <span style={{ fontSize: 11, fontWeight: 600, color: C.textSoft, letterSpacing: 0.8, textTransform: "uppercase", fontFamily: FONT }}>{title}</span>
        </div>
        {headerRight}
      </div>
    )}
    <div style={{ padding: 16 }}>{children}</div>
  </div>
);

const MiniSparkline = ({ data, color = C.accent, height = 32, width = 100 }) => {
  if (!data || data.length < 2) return null;
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min || 1;
  const points = data.map((v, i) => `${(i / (data.length - 1)) * width},${height - ((v - min) / range) * (height - 4) - 2}`).join(" ");
  return (
    <svg width={width} height={height} style={{ display: "block" }}>
      <polyline points={points} fill="none" stroke={color} strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" />
      <circle cx={(data.length - 1) / (data.length - 1) * width} cy={height - ((data[data.length - 1] - min) / range) * (height - 4) - 2} r={2.5} fill={color} />
    </svg>
  );
};

const PulseDot = ({ color = C.green, size = 8 }) => (
  <span style={{ position: "relative", display: "inline-block", width: size, height: size }}>
    <span style={{
      position: "absolute", inset: 0, borderRadius: "50%", background: color,
      animation: "qcPulse 2s ease-in-out infinite",
    }} />
    <span style={{ position: "absolute", inset: -2, borderRadius: "50%", border: `1px solid ${color}40`, animation: "qcPulseRing 2s ease-in-out infinite" }} />
  </span>
);

const ProgressBar = ({ value, max = 100, color = C.accent, height = 4, bg }) => (
  <div style={{ height, borderRadius: height, background: bg || `${color}15`, overflow: "hidden" }}>
    <div style={{ height: "100%", width: `${Math.min(100, (value / max) * 100)}%`, background: `linear-gradient(90deg, ${color}, ${color}cc)`, borderRadius: height, transition: "width 0.8s ease" }} />
  </div>
);

// ─── Navigation Tabs ──────────────────────────────────────────────────────

const NAV_ITEMS = [
  { id: "overview", label: "Strategic Overview", icon: "◈" },
  { id: "predictor", label: "Zero-Day Predictor", icon: "🔮" },
  { id: "telemetry", label: "Advanced Telemetry", icon: "📡" },
  { id: "mesh", label: "Security Mesh", icon: "🕸" },
  { id: "incidents", label: "Incidents", icon: "🚨" },
  { id: "vulns", label: "Vulnerability Scanner", icon: "🔍" },
  { id: "qc", label: "QC Console", icon: "💬" },
  { id: "research", label: "Research & Quant", icon: "📊" },
  { id: "identity", label: "Identity Core", icon: "♛" },
  { id: "devops", label: "DevOps Ops", icon: "⎈" },
];

// ─── TELEMETRY DATA GENERATORS ────────────────────────────────────────────

function generateTelemetryData() {
  const beaconTypes = ["periodic_exact", "periodic_jittered", "adaptive", "slow_drip"];
  const sensorTypes = ["network", "endpoint", "dns", "auth", "file_integrity"];
  const healthStates = ["healthy", "degraded", "stale", "offline"];
  const malwareFamilies = ["Cobalt Strike", "Sliver C2", "Brute Ratel", "Mythic C2", "Havoc C2"];
  
  return {
    fingerprints: {
      total: randInt(80, 250),
      known_bad: randInt(0, 5),
      new_last_hour: randInt(1, 15),
      recent_matches: Array.from({ length: randInt(0, 3) }, () => ({
        ja3: uuid8() + uuid8() + uuid8() + uuid8(),
        family: pick(malwareFamilies),
        source: `10.0.${randInt(1, 10)}.${randInt(1, 254)}`,
        dest: `${randInt(100, 220)}.${randInt(0, 255)}.${randInt(0, 255)}.${randInt(1, 254)}`,
        time: ago(randInt(60000, 3600000)).toISOString(),
        confidence: +(rand(0.82, 0.97)).toFixed(2),
      })),
    },
    dns: {
      sources_profiled: randInt(40, 200),
      dga_detected: randInt(0, 6),
      tunneling_alerts: randInt(0, 3),
      exfil_indicators: randInt(0, 2),
      queries_per_min: randInt(300, 2500),
    },
    beacons: Array.from({ length: randInt(0, 5) }, () => ({
      source: `10.0.${randInt(1, 10)}.${randInt(1, 254)}`,
      destination: `${randInt(100, 220)}.${randInt(0, 255)}.${randInt(0, 255)}.${randInt(1, 254)}`,
      classification: pick(beaconTypes),
      mean_interval: +(rand(15, 600)).toFixed(1),
      jitter: +(rand(0.01, 0.45)).toFixed(3),
      confidence: +(rand(0.55, 0.95)).toFixed(2),
      samples: randInt(12, 500),
    })),
    kernel: {
      syscall_profiles: randInt(30, 120),
      injection_alerts: randInt(0, 3),
      credential_alerts: randInt(0, 2),
      ransomware_patterns: randInt(0, 1),
      file_io_assets: randInt(15, 80),
      memory_anomalies: randInt(0, 4),
      privilege_transitions: randInt(2, 25),
    },
    graph: {
      total_nodes: randInt(30, 150),
      total_edges: randInt(50, 400),
      high_risk_assets: Array.from({ length: randInt(0, 5) }, () => ({
        asset: `10.0.${randInt(1, 10)}.${randInt(1, 254)}`,
        risk: +(rand(0.5, 1.0)).toFixed(2),
        direct_targets: randInt(3, 30),
        blast_radius: randInt(8, 80),
      })),
      lateral_movements: randInt(0, 4),
    },
    feedback: {
      total_entries: randInt(50, 500),
      layers_tracked: 5,
      active_adjustments: randInt(0, 3),
      suppression_rules: randInt(0, 2),
      tuned_weights: randInt(2, 15),
      layer_accuracy: {
        anomaly_fusion: { accuracy: +(rand(0.70, 0.95)).toFixed(2), fp_rate: +(rand(0.05, 0.25)).toFixed(2), total: randInt(20, 100) },
        surface_drift: { accuracy: +(rand(0.65, 0.90)).toFixed(2), fp_rate: +(rand(0.08, 0.30)).toFixed(2), total: randInt(15, 80) },
        entropy_analysis: { accuracy: +(rand(0.75, 0.95)).toFixed(2), fp_rate: +(rand(0.03, 0.20)).toFixed(2), total: randInt(10, 60) },
        genome_deviation: { accuracy: +(rand(0.60, 0.88)).toFixed(2), fp_rate: +(rand(0.10, 0.35)).toFixed(2), total: randInt(10, 50) },
        strategic_forecast: { accuracy: +(rand(0.50, 0.85)).toFixed(2), fp_rate: +(rand(0.12, 0.40)).toFixed(2), total: randInt(5, 30) },
      },
    },
    sensors: sensorTypes.map(type => ({
      type,
      count: randInt(1, 6),
      health: pick(healthStates.slice(0, 2)), // mostly healthy
      coverage_pct: +(rand(70, 100)).toFixed(1),
      avg_latency_ms: +(rand(5, 200)).toFixed(0),
      events_per_min: +(rand(50, 3000)).toFixed(0),
    })),
    blind_spots: randInt(0, 2),
    overall_health: pick(["healthy", "healthy", "healthy", "blind_spots_detected"]),
    signals_generated: randInt(5, 80),
    events_processed: randInt(1000, 50000),
  };
}

// ─── TELEMETRY TAB ────────────────────────────────────────────────────────

function TelemetryTab({ telemetry: t }) {
  const [subTab, setSubTab] = useState("network");
  const subTabs = [
    { id: "network", label: "Network Flow Intel", icon: "🌐" },
    { id: "temporal", label: "Temporal Patterns", icon: "⏱" },
    { id: "kernel", label: "Kernel / Endpoint", icon: "🧬" },
    { id: "graph", label: "Asset Correlation", icon: "🔗" },
    { id: "feedback", label: "Adaptive Feedback", icon: "🧠" },
    { id: "health", label: "Collection Health", icon: "💊" },
  ];

  return (
    <div>
      {/* Sub-navigation */}
      <div style={{ display: "flex", gap: 4, marginBottom: 16, flexWrap: "wrap" }}>
        {subTabs.map(st => (
          <button key={st.id} onClick={() => setSubTab(st.id)} style={{
            padding: "6px 12px", borderRadius: 6, border: `1px solid ${subTab === st.id ? C.cyan : C.border}`,
            background: subTab === st.id ? C.cyanDim : C.panel, color: subTab === st.id ? C.cyan : C.textSoft,
            fontSize: 10, fontWeight: 600, cursor: "pointer", fontFamily: FONT,
            display: "flex", alignItems: "center", gap: 5, transition: "all 0.2s",
          }}>
            <span>{st.icon}</span> {st.label}
          </button>
        ))}
      </div>

      {/* Telemetry KPI Banner */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: 8, marginBottom: 16 }}>
        <Stat label="Events Processed" value={t.events_processed.toLocaleString()} />
        <Stat label="Signals Generated" value={t.signals_generated} color={C.cyan} />
        <Stat label="TLS Fingerprints" value={t.fingerprints.total} />
        <Stat label="Beacons Detected" value={t.beacons.length} color={t.beacons.length > 0 ? C.red : C.green} />
        <Stat label="Graph Nodes" value={t.graph.total_nodes} />
        <Stat label="Collection Health" value={t.overall_health === "healthy" ? "HEALTHY" : "GAPS"} color={t.overall_health === "healthy" ? C.green : C.amber} />
      </div>

      {/* Sub-tab content */}
      {subTab === "network" && <TelemetryNetworkPanel t={t} />}
      {subTab === "temporal" && <TelemetryTemporalPanel t={t} />}
      {subTab === "kernel" && <TelemetryKernelPanel t={t} />}
      {subTab === "graph" && <TelemetryGraphPanel t={t} />}
      {subTab === "feedback" && <TelemetryFeedbackPanel t={t} />}
      {subTab === "health" && <TelemetryHealthPanel t={t} />}
    </div>
  );
}

function TelemetryNetworkPanel({ t }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
      {/* TLS Fingerprint Intelligence */}
      <Panel title="🔐 TLS Fingerprint Intelligence">
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, marginBottom: 12 }}>
          <Stat label="Catalogued" value={t.fingerprints.total} />
          <Stat label="Known Bad Matches" value={t.fingerprints.known_bad} color={t.fingerprints.known_bad > 0 ? C.red : C.green} />
          <Stat label="New (1h)" value={t.fingerprints.new_last_hour} color={C.cyan} />
        </div>
        {t.fingerprints.recent_matches.length > 0 ? (
          <div>
            <div style={{ fontSize: 10, color: C.textDim, marginBottom: 6, textTransform: "uppercase", letterSpacing: 1 }}>Active Threat Matches</div>
            {t.fingerprints.recent_matches.map((m, i) => (
              <div key={i} style={{ padding: "8px 10px", background: C.redDim, borderRadius: 6, border: `1px solid ${C.red}33`, marginBottom: 6 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                  <SeverityBadge severity="critical">{m.family}</SeverityBadge>
                  <ConfidenceBadge tier={m.confidence >= 0.95 ? "near_certain" : m.confidence >= 0.8 ? "high" : m.confidence >= 0.6 ? "probable" : "emerging"} confidence={m.confidence} />
                </div>
                <div style={{ fontSize: 10, color: C.textSoft, fontFamily: MONO }}>
                  {m.source} → {m.dest}
                </div>
                <div style={{ fontSize: 9, color: C.textDim, fontFamily: MONO, marginTop: 2 }}>
                  JA3: {m.ja3.slice(0, 24)}…
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ textAlign: "center", padding: 20, color: C.green, fontSize: 11 }}>
            ✓ No malicious fingerprints detected
          </div>
        )}
      </Panel>

      {/* DNS Intelligence */}
      <Panel title="🌐 DNS Transaction Intelligence">
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 12 }}>
          <Stat label="Sources Profiled" value={t.dns.sources_profiled} />
          <Stat label="Queries/min" value={t.dns.queries_per_min.toLocaleString()} />
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 6 }}>
          <div style={{ padding: "10px", background: t.dns.dga_detected > 0 ? C.redDim : C.greenDim, borderRadius: 6, textAlign: "center" }}>
            <div style={{ fontSize: 18, fontWeight: 700, color: t.dns.dga_detected > 0 ? C.red : C.green, fontFamily: MONO }}>{t.dns.dga_detected}</div>
            <div style={{ fontSize: 9, color: C.textSoft }}>DGA Domains</div>
          </div>
          <div style={{ padding: "10px", background: t.dns.tunneling_alerts > 0 ? C.amberDim : C.greenDim, borderRadius: 6, textAlign: "center" }}>
            <div style={{ fontSize: 18, fontWeight: 700, color: t.dns.tunneling_alerts > 0 ? C.amber : C.green, fontFamily: MONO }}>{t.dns.tunneling_alerts}</div>
            <div style={{ fontSize: 9, color: C.textSoft }}>Tunneling</div>
          </div>
          <div style={{ padding: "10px", background: t.dns.exfil_indicators > 0 ? C.redDim : C.greenDim, borderRadius: 6, textAlign: "center" }}>
            <div style={{ fontSize: 18, fontWeight: 700, color: t.dns.exfil_indicators > 0 ? C.red : C.green, fontFamily: MONO }}>{t.dns.exfil_indicators}</div>
            <div style={{ fontSize: 9, color: C.textSoft }}>Exfil Indicators</div>
          </div>
        </div>
      </Panel>
    </div>
  );
}

function TelemetryTemporalPanel({ t }) {
  const beaconColors = { periodic_exact: C.red, periodic_jittered: C.amber, adaptive: C.purple, slow_drip: C.cyan };
  return (
    <div>
      <Panel title="⏱ Beacon Detection — Communication Cadence Analysis">
        {t.beacons.length > 0 ? (
          <div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))", gap: 10 }}>
              {t.beacons.map((b, i) => (
                <div key={i} style={{ padding: "10px 12px", background: C.surface, borderRadius: 6, border: `1px solid ${beaconColors[b.classification] || C.border}44` }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                    <Badge color={beaconColors[b.classification] || C.textDim}>{b.classification.replace(/_/g, " ")}</Badge>
                    <ConfidenceBadge tier={b.confidence >= 0.95 ? "near_certain" : b.confidence >= 0.8 ? "high" : b.confidence >= 0.6 ? "probable" : "emerging"} confidence={b.confidence} />
                  </div>
                  <div style={{ fontSize: 11, fontFamily: MONO, color: C.text, marginBottom: 4 }}>
                    {b.source} → {b.destination}
                  </div>
                  <div style={{ display: "flex", gap: 16, fontSize: 10, color: C.textSoft }}>
                    <span>Interval: <span style={{ color: C.cyan, fontFamily: MONO }}>{b.mean_interval}s</span></span>
                    <span>Jitter: <span style={{ color: C.amber, fontFamily: MONO }}>{b.jitter}</span></span>
                    <span>Samples: <span style={{ fontFamily: MONO }}>{b.samples}</span></span>
                  </div>
                  <div style={{ marginTop: 6 }}>
                    <ProgressBar value={b.confidence} max={1} color={beaconColors[b.classification] || C.cyan} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div style={{ textAlign: "center", padding: 30, color: C.green, fontSize: 11 }}>
            ✓ No beaconing patterns detected — communications appear organic
          </div>
        )}
      </Panel>
    </div>
  );
}

function TelemetryKernelPanel({ t }) {
  const k = t.kernel;
  const kernelMetrics = [
    { label: "Syscall Profiles", value: k.syscall_profiles, color: C.text },
    { label: "Injection Alerts", value: k.injection_alerts, color: k.injection_alerts > 0 ? C.red : C.green },
    { label: "Credential Access", value: k.credential_alerts, color: k.credential_alerts > 0 ? C.red : C.green },
    { label: "Ransomware Patterns", value: k.ransomware_patterns, color: k.ransomware_patterns > 0 ? C.red : C.green },
    { label: "File I/O Assets", value: k.file_io_assets, color: C.text },
    { label: "Memory Anomalies", value: k.memory_anomalies, color: k.memory_anomalies > 0 ? C.amber : C.green },
    { label: "Privilege Transitions", value: k.privilege_transitions, color: k.privilege_transitions > 10 ? C.amber : C.text },
  ];
  return (
    <div>
      <Panel title="🧬 Kernel & Endpoint Telemetry">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 16 }}>
          {kernelMetrics.map((m, i) => (
            <div key={i} style={{ padding: "12px", background: C.surface, borderRadius: 6, textAlign: "center" }}>
              <div style={{ fontSize: 22, fontWeight: 700, color: m.color, fontFamily: MONO }}>{m.value}</div>
              <div style={{ fontSize: 9, color: C.textSoft, marginTop: 4 }}>{m.label}</div>
            </div>
          ))}
        </div>
        {k.injection_alerts > 0 && (
          <div style={{ padding: "10px 12px", background: C.redDim, borderRadius: 6, border: `1px solid ${C.red}33`, marginBottom: 8 }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: C.red }}>⚠ Active injection syscall patterns detected</div>
            <div style={{ fontSize: 10, color: C.textSoft, marginTop: 4 }}>
              {k.injection_alerts} process(es) showing NtWriteVirtualMemory / CreateRemoteThread patterns — recommend immediate memory forensics
            </div>
          </div>
        )}
        {k.ransomware_patterns > 0 && (
          <div style={{ padding: "10px 12px", background: C.redDim, borderRadius: 6, border: `1px solid ${C.red}33` }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: C.red }}>🔴 RANSOMWARE FILE I/O PATTERN DETECTED</div>
            <div style={{ fontSize: 10, color: C.textSoft, marginTop: 4 }}>
              Rapid read→write→rename across multiple files — ISOLATE AFFECTED ASSETS IMMEDIATELY
            </div>
          </div>
        )}
      </Panel>
    </div>
  );
}

function TelemetryGraphPanel({ t }) {
  const g = t.graph;
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
      <Panel title="🔗 Cross-Asset Communication Graph">
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, marginBottom: 12 }}>
          <Stat label="Nodes" value={g.total_nodes} />
          <Stat label="Edges" value={g.total_edges} />
          <Stat label="Lateral Movements" value={g.lateral_movements} color={g.lateral_movements > 0 ? C.red : C.green} />
        </div>
        {/* Simplified graph visualization */}
        <div style={{ height: 160, background: C.surface, borderRadius: 6, padding: 12, position: "relative", overflow: "hidden" }}>
          {Array.from({ length: Math.min(g.total_nodes, 30) }, (_, i) => {
            const angle = (i / Math.min(g.total_nodes, 30)) * Math.PI * 2;
            const r = 55 + (i % 3) * 15;
            const x = 50 + Math.cos(angle) * r * 0.7;
            const y = 50 + Math.sin(angle) * r * 0.85;
            const isRisky = g.high_risk_assets.some(a => i < g.high_risk_assets.length);
            return (
              <div key={i} style={{
                position: "absolute", left: `${x}%`, top: `${y}%`,
                width: isRisky && i < g.high_risk_assets.length ? 8 : 4,
                height: isRisky && i < g.high_risk_assets.length ? 8 : 4,
                borderRadius: "50%",
                background: i < g.high_risk_assets.length ? C.red : C.cyan,
                opacity: i < g.high_risk_assets.length ? 1 : 0.4,
                boxShadow: i < g.high_risk_assets.length ? `0 0 8px ${C.red}` : "none",
                transform: "translate(-50%, -50%)",
              }} />
            );
          })}
          <div style={{ position: "absolute", bottom: 6, right: 8, fontSize: 8, color: C.textDim, fontFamily: MONO }}>
            {g.total_nodes} nodes / {g.total_edges} connections
          </div>
        </div>
      </Panel>

      <Panel title="⚡ High-Risk Assets — Blast Radius">
        {g.high_risk_assets.length > 0 ? (
          g.high_risk_assets.map((a, i) => (
            <div key={i} style={{ padding: "10px 12px", background: C.surface, borderRadius: 6, marginBottom: 6, border: `1px solid ${a.risk > 0.8 ? C.red : C.amber}33` }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                <span style={{ fontSize: 11, fontFamily: MONO, color: C.text }}>{a.asset}</span>
                <span style={{
                  fontSize: 10, fontFamily: MONO, fontWeight: 700,
                  color: a.risk > 0.8 ? C.red : a.risk > 0.6 ? C.amber : C.green,
                }}>RISK: {a.risk}</span>
              </div>
              <ProgressBar value={a.risk} max={1} color={a.risk > 0.8 ? C.red : C.amber} />
              <div style={{ display: "flex", gap: 12, marginTop: 4, fontSize: 9, color: C.textSoft }}>
                <span>Direct: {a.direct_targets}</span>
                <span>Blast Radius: <span style={{ color: C.amber }}>{a.blast_radius}</span> assets</span>
              </div>
            </div>
          ))
        ) : (
          <div style={{ textAlign: "center", padding: 30, color: C.green, fontSize: 11 }}>
            ✓ No high-risk assets detected
          </div>
        )}
      </Panel>
    </div>
  );
}

function TelemetryFeedbackPanel({ t }) {
  const f = t.feedback;
  const layerNames = Object.keys(f.layer_accuracy);
  const barData = layerNames.map(name => ({
    name: name.replace(/_/g, " "),
    accuracy: +(f.layer_accuracy[name].accuracy * 100).toFixed(0),
    fp_rate: +(f.layer_accuracy[name].fp_rate * 100).toFixed(0),
    total: f.layer_accuracy[name].total,
  }));

  return (
    <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 12 }}>
      <Panel title="🧠 Layer Accuracy — Adaptive Feedback Loop">
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={barData} barGap={2}>
            <XAxis dataKey="name" tick={{ fill: C.textDim, fontSize: 9 }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fill: C.textDim, fontSize: 9 }} axisLine={false} tickLine={false} domain={[0, 100]} />
            <Tooltip contentStyle={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 6, fontSize: 10 }} />
            <Bar dataKey="accuracy" fill={C.green} radius={[3, 3, 0, 0]} name="Accuracy %" />
            <Bar dataKey="fp_rate" fill={C.red} radius={[3, 3, 0, 0]} name="FP Rate %" />
          </BarChart>
        </ResponsiveContainer>
        <div style={{ display: "flex", gap: 16, justifyContent: "center", marginTop: 8 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 9, color: C.textSoft }}>
            <div style={{ width: 8, height: 8, borderRadius: 2, background: C.green }} /> Accuracy %
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 9, color: C.textSoft }}>
            <div style={{ width: 8, height: 8, borderRadius: 2, background: C.red }} /> False Positive %
          </div>
        </div>
      </Panel>

      <Panel title="⚙ Calibration Status">
        <div style={{ display: "grid", gap: 10 }}>
          <Stat label="Feedback Entries" value={f.total_entries} />
          <Stat label="Threshold Adjustments" value={f.active_adjustments} color={f.active_adjustments > 0 ? C.amber : C.green} />
          <Stat label="Suppression Rules" value={f.suppression_rules} color={f.suppression_rules > 0 ? C.amber : C.text} />
          <Stat label="Tuned Signal Weights" value={f.tuned_weights} color={C.cyan} />
          <div style={{ padding: "8px 10px", background: C.surface, borderRadius: 6, textAlign: "center", marginTop: 4 }}>
            <div style={{ fontSize: 9, color: C.textDim, marginBottom: 4 }}>SYSTEM LEARNING</div>
            <div style={{ fontSize: 10, color: C.green }}>
              {f.total_entries > 100 ? "Mature — high confidence calibration" :
               f.total_entries > 30 ? "Developing — improving accuracy" :
               "Early stage — building baselines"}
            </div>
          </div>
        </div>
      </Panel>
    </div>
  );
}

function TelemetryHealthPanel({ t }) {
  const healthColor = { healthy: C.green, degraded: C.amber, stale: C.amber, offline: C.red };
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
      <Panel title="💊 Sensor Collection Health">
        <div style={{ display: "grid", gap: 6 }}>
          {t.sensors.map((s, i) => (
            <div key={i} style={{ padding: "8px 12px", background: C.surface, borderRadius: 6, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <div style={{ fontSize: 11, fontWeight: 600, color: C.text, textTransform: "capitalize" }}>
                  {s.type} <Badge color={healthColor[s.health] || C.textDim}>{s.health}</Badge>
                </div>
                <div style={{ fontSize: 9, color: C.textSoft, marginTop: 2 }}>
                  {s.count} sensors · {s.events_per_min} events/min · {s.avg_latency_ms}ms latency
                </div>
              </div>
              <div style={{ textAlign: "right" }}>
                <div style={{ fontSize: 14, fontWeight: 700, fontFamily: MONO, color: s.coverage_pct > 90 ? C.green : s.coverage_pct > 70 ? C.amber : C.red }}>
                  {s.coverage_pct}%
                </div>
                <div style={{ fontSize: 8, color: C.textDim }}>coverage</div>
              </div>
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="🗺 Coverage & Blind Spots">
        <div style={{ padding: "12px", background: t.overall_health === "healthy" ? C.greenDim : C.amberDim, borderRadius: 6, marginBottom: 12, textAlign: "center" }}>
          <div style={{ fontSize: 20, fontWeight: 700, fontFamily: MONO, color: t.overall_health === "healthy" ? C.green : C.amber }}>
            {t.overall_health === "healthy" ? "FULL COVERAGE" : "GAPS DETECTED"}
          </div>
          <div style={{ fontSize: 10, color: C.textSoft, marginTop: 4 }}>
            {t.blind_spots === 0 ? "All asset types have sensor coverage" : `${t.blind_spots} blind spot(s) identified — review sensor deployment`}
          </div>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
          {t.sensors.map((s, i) => (
            <div key={i} style={{ padding: "8px", background: C.surface, borderRadius: 6, textAlign: "center" }}>
              <ProgressBar value={s.coverage_pct} max={100} color={s.coverage_pct > 90 ? C.green : C.amber} />
              <div style={{ fontSize: 9, color: C.textSoft, marginTop: 4, textTransform: "capitalize" }}>{s.type}</div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

// ─── OVERVIEW TAB ─────────────────────────────────────────────────────────

function OverviewTab({ mesh, predictions, incidents, timeSeries, landscape }) {
  const topPreds = predictions.slice(0, 3);
  const criticalIncidents = incidents.filter(i => i.severity === "CRITICAL").length;
  const highPreds = predictions.filter(p => p.confidence > 0.7).length;

  // Threat posture score: 0-100 (lower is better)
  const postureScore = Math.round(
    100 - (
      mesh.threat_posture.active_attack_chains * 15 +
      criticalIncidents * 10 +
      highPreds * 8
    )
  );
  const postureColor = postureScore >= 80 ? C.green : postureScore >= 50 ? C.amber : C.red;
  const postureLabel = postureScore >= 80 ? "SECURE" : postureScore >= 50 ? "ELEVATED" : "CRITICAL";

  return (
    <div style={{ display: "grid", gap: 16 }}>
      {/* Hero: Threat Posture */}
      <div style={{
        display: "grid", gridTemplateColumns: "260px 1fr 300px", gap: 16,
      }}>
        <Panel title="Threat Posture" icon="◉" accent={postureColor} glow>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
            <div style={{ position: "relative", width: 120, height: 120 }}>
              <svg width={120} height={120} viewBox="0 0 120 120">
                <circle cx={60} cy={60} r={52} fill="none" stroke={`${postureColor}15`} strokeWidth={8} />
                <circle cx={60} cy={60} r={52} fill="none" stroke={postureColor} strokeWidth={8}
                  strokeDasharray={`${(postureScore / 100) * 327} 327`}
                  strokeLinecap="round" transform="rotate(-90 60 60)"
                  style={{ transition: "stroke-dasharray 1.2s ease" }} />
              </svg>
              <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
                <div style={{ fontSize: 32, fontWeight: 800, fontFamily: MONO, color: postureColor, lineHeight: 1 }}>{postureScore}</div>
                <div style={{ fontSize: 9, fontWeight: 700, color: postureColor, letterSpacing: 1.5 }}>{postureLabel}</div>
              </div>
            </div>
            <div style={{ display: "flex", gap: 16, marginTop: 4 }}>
              <Stat label="Attack Chains" value={mesh.threat_posture.active_attack_chains} color={mesh.threat_posture.active_attack_chains > 0 ? C.red : C.green} small />
              <Stat label="Predictions" value={highPreds} color={highPreds > 0 ? C.amber : C.green} sub="HIGH+" small />
            </div>
          </div>
        </Panel>

        <Panel title="Event Timeline — 24h" icon="📊" accent={C.accent}>
          <ResponsiveContainer width="100%" height={160}>
            <AreaChart data={timeSeries} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
              <defs>
                <linearGradient id="evtGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={C.accent} stopOpacity={0.15} />
                  <stop offset="100%" stopColor={C.accent} stopOpacity={0} />
                </linearGradient>
                <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={C.red} stopOpacity={0.2} />
                  <stop offset="100%" stopColor={C.red} stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="time" tick={{ fill: C.textDim, fontSize: 9, fontFamily: MONO }} axisLine={false} tickLine={false} interval={3} />
              <YAxis tick={{ fill: C.textDim, fontSize: 9, fontFamily: MONO }} axisLine={false} tickLine={false} width={40} />
              <Tooltip contentStyle={{ background: C.panel, border: `1px solid ${C.borderLit}`, borderRadius: 6, fontFamily: MONO, fontSize: 11, color: C.text }} />
              <Area type="monotone" dataKey="events" stroke={C.accent} fill="url(#evtGrad)" strokeWidth={1.5} />
              <Area type="monotone" dataKey="threats" stroke={C.red} fill="url(#threatGrad)" strokeWidth={1.5} />
              <Line type="monotone" dataKey="predictions" stroke={C.purple} strokeWidth={1.5} strokeDasharray="4 4" dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </Panel>

        <Panel title="Mesh Health" icon="🕷" accent={C.green}>
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <Stat label="Nodes Active" value={`${mesh.topology.active_nodes}/${mesh.topology.total_nodes}`} color={C.green} small />
              <Stat label="Circuits" value={`${mesh.topology.healthy_circuits}/${mesh.topology.total_circuits}`} color={C.green} small />
              <Stat label="Heals" value={mesh.statistics.mesh_heals} color={C.cyan} small />
            </div>
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                <span style={{ fontSize: 10, color: C.textSoft }}>Mesh Integrity</span>
                <span style={{ fontSize: 10, color: C.green, fontFamily: MONO }}>{Math.round(mesh.topology.active_nodes / mesh.topology.total_nodes * 100)}%</span>
              </div>
              <ProgressBar value={mesh.topology.active_nodes} max={mesh.topology.total_nodes} color={C.green} />
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, fontSize: 11 }}>
              <div style={{ padding: "6px 8px", background: C.redDim, borderRadius: 4, display: "flex", justifyContent: "space-between" }}>
                <span style={{ color: C.textSoft }}>IPs Blocked</span>
                <span style={{ color: C.red, fontFamily: MONO, fontWeight: 600 }}>{mesh.threat_posture.ips_blocked}</span>
              </div>
              <div style={{ padding: "6px 8px", background: C.amberDim, borderRadius: 4, display: "flex", justifyContent: "space-between" }}>
                <span style={{ color: C.textSoft }}>IOCs Active</span>
                <span style={{ color: C.amber, fontFamily: MONO, fontWeight: 600 }}>{mesh.threat_posture.iocs_active}</span>
              </div>
            </div>
            <div style={{ fontSize: 10, color: C.textDim }}>
              Events Ingested: <span style={{ color: C.text, fontFamily: MONO }}>{mesh.statistics.events_ingested.toLocaleString()}</span>
            </div>
          </div>
        </Panel>
      </div>

      {/* Top Predictions + Active Incidents */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <Panel title="Top Threat Predictions" icon="🔮" accent={C.purple} glow={topPreds.length > 0}>
          {topPreds.length === 0 ? (
            <div style={{ textAlign: "center", padding: 20, color: C.green }}>
              <div style={{ fontSize: 24, marginBottom: 4 }}>✓</div>
              <div style={{ fontSize: 12 }}>No high-confidence predictions</div>
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {topPreds.map(p => (
                <div key={p.prediction_id} style={{
                  padding: "10px 12px", background: C.surface, borderRadius: 6,
                  border: `1px solid ${p.confidence > 0.8 ? C.red + "30" : C.border}`,
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 8 }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: C.text, marginBottom: 4, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{p.title}</div>
                      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                        <ConfidenceBadge tier={p.confidence_tier} confidence={p.confidence} />
                        <HorizonBadge horizon={p.threat_horizon} />
                        <Badge color={C.textSoft}>{p.category.replace(/_/g, " ")}</Badge>
                      </div>
                    </div>
                    <div style={{ fontSize: 18, fontWeight: 800, fontFamily: MONO, color: p.risk_score >= 8 ? C.red : p.risk_score >= 5 ? C.amber : C.accentBright }}>{p.risk_score.toFixed(1)}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="Active Incidents" icon="🚨" accent={C.red} glow={criticalIncidents > 0}>
          {incidents.length === 0 ? (
            <div style={{ textAlign: "center", padding: 20, color: C.green }}>
              <div style={{ fontSize: 24, marginBottom: 4 }}>✓</div>
              <div style={{ fontSize: 12 }}>No active incidents</div>
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {incidents.slice(0, 4).map(inc => (
                <div key={inc.incident_id} style={{
                  padding: "10px 12px", background: C.surface, borderRadius: 6,
                  border: `1px solid ${inc.severity === "CRITICAL" ? C.red + "30" : C.border}`,
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 8 }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: C.text, marginBottom: 4, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{inc.title}</div>
                      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                        <SeverityBadge severity={inc.severity} />
                        <Badge color={C.cyan}>{inc.status}</Badge>
                        <Badge color={C.textSoft}>{inc.incident_id}</Badge>
                      </div>
                    </div>
                    <div style={{ textAlign: "right" }}>
                      <div style={{ fontSize: 10, color: C.textDim }}>{inc.affected_assets} assets</div>
                      {inc.actions_pending > 0 && <div style={{ fontSize: 10, color: C.amber }}>{inc.actions_pending} pending</div>}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      {/* Threat Landscape Radar */}
      <Panel title="Strategic Threat Landscape" icon="🌐" accent={C.cyan}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          <ResponsiveContainer width="100%" height={220}>
            <RadarChart cx="50%" cy="50%" outerRadius="70%" data={landscape}>
              <PolarGrid stroke={C.border} />
              <PolarAngleAxis dataKey="vector" tick={{ fill: C.textSoft, fontSize: 9 }} />
              <PolarRadiusAxis tick={false} domain={[0, 100]} axisLine={false} />
              <Radar name="Risk" dataKey="risk" stroke={C.red} fill={C.red} fillOpacity={0.12} strokeWidth={2} />
            </RadarChart>
          </ResponsiveContainer>
          <div style={{ display: "flex", flexDirection: "column", gap: 6, justifyContent: "center" }}>
            {landscape.map(l => (
              <div key={l.vector} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <div style={{ width: 80, fontSize: 10, color: C.textSoft, textAlign: "right" }}>{l.vector}</div>
                <div style={{ flex: 1 }}><ProgressBar value={l.risk} color={l.risk > 80 ? C.red : l.risk > 60 ? C.amber : C.accentBright} height={6} /></div>
                <div style={{ width: 28, fontSize: 10, fontFamily: MONO, color: l.risk > 80 ? C.red : l.risk > 60 ? C.amber : C.text }}>{Math.round(l.risk)}</div>
                <Badge color={l.trend === "accelerating" || l.trend === "escalating" ? C.red : l.trend === "emerging" || l.trend === "expanding" ? C.amber : C.textDim} style={{ fontSize: 8 }}>
                  {l.trend === "accelerating" ? "▲▲" : l.trend === "escalating" ? "▲" : l.trend === "emerging" || l.trend === "expanding" ? "↗" : "─"}
                </Badge>
              </div>
            ))}
          </div>
        </div>
      </Panel>
    </div>
  );
}

// ─── PREDICTOR TAB ─────────────────────────────────────────────────────────

function PredictorTab({ predictions, layerActivity }) {
  return (
    <div style={{ display: "grid", gap: 16 }}>
      {/* Prediction Engine Status */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <Panel title="Prediction Layer Activity" icon="⚡" accent={C.purple}>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {layerActivity.map(l => (
              <div key={l.layer}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <span style={{ fontSize: 11, color: C.text }}>{l.layer}</span>
                  <div style={{ display: "flex", gap: 8 }}>
                    <span style={{ fontSize: 10, fontFamily: MONO, color: C.textSoft }}>{l.signals} signals</span>
                    <span style={{ fontSize: 10, fontFamily: MONO, color: l.confidence > 0.8 ? C.green : l.confidence > 0.6 ? C.amber : C.textSoft }}>
                      {(l.confidence * 100).toFixed(0)}% avg conf
                    </span>
                  </div>
                </div>
                <ProgressBar value={l.signals} max={80} color={l.confidence > 0.8 ? C.green : l.confidence > 0.6 ? C.accent : C.textDim} height={5} />
              </div>
            ))}
          </div>
          <div style={{ marginTop: 12, padding: "8px 10px", background: C.surface, borderRadius: 6, fontSize: 10, color: C.textSoft }}>
            <strong style={{ color: C.purple }}>5-Layer Architecture:</strong> Anomaly Fusion → Surface Drift → Entropy Analysis → Behavioral Genome → Strategic Forecast
          </div>
        </Panel>

        <Panel title="Prediction Distribution" icon="📊" accent={C.purple}>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={[
              { tier: "Near Certain", count: predictions.filter(p => p.confidence_tier === "near_certain").length, color: C.red },
              { tier: "High", count: predictions.filter(p => p.confidence_tier === "high").length, color: C.amber },
              { tier: "Probable", count: predictions.filter(p => p.confidence_tier === "probable").length, color: C.accentBright },
              { tier: "Emerging", count: predictions.filter(p => p.confidence_tier === "emerging").length, color: C.cyan },
              { tier: "Speculative", count: predictions.filter(p => p.confidence_tier === "speculative").length, color: C.textDim },
            ]} margin={{ top: 8, right: 8, bottom: 0, left: -20 }}>
              <XAxis dataKey="tier" tick={{ fill: C.textSoft, fontSize: 9 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: C.textDim, fontSize: 9, fontFamily: MONO }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip contentStyle={{ background: C.panel, border: `1px solid ${C.borderLit}`, borderRadius: 6, fontFamily: MONO, fontSize: 11, color: C.text }} />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {[C.red, C.amber, C.accentBright, C.cyan, C.textDim].map((c, i) => <Cell key={i} fill={c} fillOpacity={0.8} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Panel>
      </div>

      {/* All Predictions */}
      <Panel title={`Active Predictions (${predictions.length})`} icon="🔮" accent={C.purple} glow>
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {predictions.map(p => (
            <div key={p.prediction_id} style={{
              padding: "12px 14px", background: C.surface, borderRadius: 6,
              border: `1px solid ${p.confidence > 0.8 ? C.red + "30" : p.confidence > 0.6 ? C.amber + "20" : C.border}`,
              boxShadow: p.confidence > 0.8 ? `0 0 15px ${C.red}08` : "none",
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 6 }}>{p.title}</div>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 6 }}>
                    <ConfidenceBadge tier={p.confidence_tier} confidence={p.confidence} />
                    <HorizonBadge horizon={p.threat_horizon} />
                    <Badge color={C.purple}>{p.category.replace(/_/g, " ")}</Badge>
                    <Badge color={C.textSoft}>{p.contributing_signals} signals</Badge>
                  </div>
                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                    {p.predicted_techniques.map(t => (
                      <span key={t} style={{ fontSize: 9, fontFamily: MONO, color: C.cyan, background: C.cyanDim, padding: "1px 5px", borderRadius: 3 }}>{t}</span>
                    ))}
                    {p.affected_assets.slice(0, 2).map(a => (
                      <span key={a} style={{ fontSize: 9, fontFamily: MONO, color: C.textDim, background: `${C.textDim}15`, padding: "1px 5px", borderRadius: 3 }}>{a}</span>
                    ))}
                  </div>
                </div>
                <div style={{ textAlign: "right", flexShrink: 0 }}>
                  <div style={{ fontSize: 24, fontWeight: 800, fontFamily: MONO, color: p.risk_score >= 8 ? C.red : p.risk_score >= 5 ? C.amber : C.accentBright, lineHeight: 1 }}>
                    {p.risk_score.toFixed(1)}
                  </div>
                  <div style={{ fontSize: 9, color: C.textDim, marginTop: 2 }}>RISK SCORE</div>
                  <div style={{ fontSize: 9, fontFamily: MONO, color: C.textDim, marginTop: 4 }}>{p.prediction_id}</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

// ─── MESH TAB ─────────────────────────────────────────────────────────────

function MeshTab({ mesh }) {
  const nodeTypes = [
    { type: "Hub Nodes", icon: "◆", count: 4, color: C.accent, desc: "Network • Endpoint • Identity • Data" },
    { type: "Radial Nodes", icon: "●", count: 12, color: C.cyan, desc: "Signature • Behavioral • Heuristic • ML" },
    { type: "Spiral Nodes", icon: "◐", count: 8, color: C.purple, desc: "Cross-domain correlation engines" },
  ];

  const circuits = [
    "Ingestion Pipeline", "Detection Pipeline", "Correlation Pipeline",
    "Response Pipeline", "Intelligence Pipeline", "Audit Pipeline",
  ];

  return (
    <div style={{ display: "grid", gap: 16 }}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 16 }}>
        {nodeTypes.map(n => (
          <Panel key={n.type} title={n.type} icon={n.icon} accent={n.color}>
            <div style={{ textAlign: "center", marginBottom: 8 }}>
              <div style={{ fontSize: 36, fontWeight: 800, fontFamily: MONO, color: n.color }}>{n.count}</div>
              <div style={{ fontSize: 10, color: C.textSoft }}>{n.desc}</div>
            </div>
            <ProgressBar value={n.count} max={n.count} color={n.color} height={3} />
          </Panel>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <Panel title="Tamerian Circuits" icon="⚡" accent={C.green}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
            {circuits.map(c => (
              <div key={c} style={{ padding: "8px 10px", background: C.surface, borderRadius: 6, display: "flex", alignItems: "center", gap: 8 }}>
                <PulseDot color={C.green} size={6} />
                <span style={{ fontSize: 11, color: C.text }}>{c}</span>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 12, padding: 8, background: C.greenGlow, borderRadius: 6, border: `1px solid ${C.green}15` }}>
            <div style={{ fontSize: 10, color: C.green }}>All circuits healthy — 3x redundant pathways, integrity verified</div>
          </div>
        </Panel>

        <Panel title="Threat Intelligence" icon="🔒" accent={C.amber}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Stat label="IOCs Active" value={mesh.threat_posture.iocs_active} color={C.amber} />
            <Stat label="IPs Blocked" value={mesh.threat_posture.ips_blocked} color={C.red} />
            <Stat label="Domains Blocked" value={mesh.threat_posture.blocked_domains} color={C.red} />
            <Stat label="Events / Session" value={mesh.statistics.events_ingested.toLocaleString()} color={C.accent} />
          </div>
        </Panel>
      </div>

      <Panel title="Detection Signatures" icon="📝" accent={C.accent}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 6 }}>
          {["SIG-NET: Port Scan", "SIG-NET: C2 Domain", "SIG-NET: DNS Tunnel", "SIG-NET: Beaconing",
            "SIG-END: Suspicious Proc", "SIG-END: Ransomware", "SIG-END: Cred Dump", "SIG-END: Persistence",
            "SIG-IDN: Brute Force", "SIG-IDN: Impossible Travel", "SIG-IDN: Priv Escalation", "SIG-DAT: Data Anomaly"
          ].map(sig => (
            <div key={sig} style={{ padding: "6px 8px", background: C.surface, borderRadius: 4, fontSize: 10, fontFamily: MONO, color: C.textSoft, display: "flex", alignItems: "center", gap: 4 }}>
              <span style={{ color: C.green }}>●</span> {sig}
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

// ─── INCIDENTS TAB ─────────────────────────────────────────────────────────

function IncidentsTab({ incidents }) {
  const [selectedId, setSelectedId] = useState(null);
  const [panel, setPanel] = useState(null); // "investigate" | "approve" | "timeline"
  const [actionStatuses, setActionStatuses] = useState({}); // { "ACT-xxx": "approved"|"rejected" }
  const [analystNotes, setAnalystNotes] = useState({});
  const [statusOverrides, setStatusOverrides] = useState({});
  const [severityOverrides, setSeverityOverrides] = useState({});
  const [toasts, setToasts] = useState([]);

  const selected = incidents.find(i => i.incident_id === selectedId);

  const addToast = (msg, color = C.green) => {
    const id = Date.now();
    setToasts(prev => [...prev, { id, msg, color }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 3500);
  };

  const handleApprove = (actId) => {
    setActionStatuses(prev => ({ ...prev, [actId]: "approved" }));
    addToast(`✓ Action ${actId} approved — executing`, C.green);
  };
  const handleReject = (actId) => {
    setActionStatuses(prev => ({ ...prev, [actId]: "rejected" }));
    addToast(`✗ Action ${actId} rejected`, C.amber);
  };
  const handleApproveAll = (actions) => {
    const updates = {};
    actions.forEach(a => { if (!actionStatuses[a.id]) updates[a.id] = "approved"; });
    setActionStatuses(prev => ({ ...prev, ...updates }));
    addToast(`✓ ${Object.keys(updates).length} actions batch-approved — executing`, C.green);
  };
  const handleEscalate = (incId) => {
    setSeverityOverrides(prev => ({ ...prev, [incId]: "CRITICAL" }));
    addToast(`▲ ${incId} escalated to CRITICAL`, C.red);
  };
  const handleStatusChange = (incId, newStatus) => {
    setStatusOverrides(prev => ({ ...prev, [incId]: newStatus }));
    addToast(`◈ ${incId} status → ${newStatus}`, C.cyan);
  };

  const getEffectiveSeverity = (inc) => severityOverrides[inc.incident_id] || inc.severity;
  const getEffectiveStatus = (inc) => statusOverrides[inc.incident_id] || inc.status;
  const getPendingCount = (inc) => inc.pending_actions.filter(a => !actionStatuses[a.id]).length;

  const riskColor = { low: C.green, medium: C.amber, high: C.red };
  const typeColor = { detection: C.red, analysis: C.cyan, containment: C.amber, evidence: C.purple, escalation: C.magenta, enrichment: C.accentBright };
  const typeIcon = { detection: "⚠", analysis: "🔍", containment: "🛡", evidence: "📦", escalation: "▲", enrichment: "🧠" };

  // ── BACK TO LIST ──
  const backBtn = (
    <button onClick={() => { setSelectedId(null); setPanel(null); }} style={{
      padding: "6px 14px", background: "transparent", color: C.textSoft,
      border: `1px solid ${C.border}`, borderRadius: 5, fontSize: 11, fontWeight: 600,
      cursor: "pointer", fontFamily: FONT, display: "flex", alignItems: "center", gap: 5,
    }}>
      ← Back to Incidents
    </button>
  );

  return (
    <div style={{ display: "grid", gap: 16, position: "relative" }}>
      {/* Toast notifications */}
      <div style={{ position: "fixed", top: 16, right: 16, zIndex: 9999, display: "flex", flexDirection: "column", gap: 6 }}>
        {toasts.map(t => (
          <div key={t.id} style={{
            padding: "8px 14px", background: C.panel, border: `1px solid ${t.color}50`,
            borderRadius: 6, fontSize: 11, fontWeight: 600, color: t.color,
            fontFamily: MONO, boxShadow: `0 4px 20px ${t.color}15`,
            animation: "qcPulse 0.4s ease",
          }}>{t.msg}</div>
        ))}
      </div>

      {/* ═══════ KPI BANNER ═══════ */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12 }}>
        <Panel accent={C.red}><Stat label="Critical" value={incidents.filter(i => getEffectiveSeverity(i) === "CRITICAL").length} color={C.red} /></Panel>
        <Panel accent={C.amber}><Stat label="High" value={incidents.filter(i => getEffectiveSeverity(i) === "HIGH").length} color={C.amber} /></Panel>
        <Panel accent={C.accent}><Stat label="Total Active" value={incidents.length} color={C.accent} /></Panel>
        <Panel accent={C.purple}><Stat label="Pending Actions" value={incidents.reduce((a, i) => a + getPendingCount(i), 0)} color={C.purple} /></Panel>
        <Panel accent={C.green}><Stat label="Avg Containment" value={`${Math.round(incidents.reduce((a, i) => a + (i.containment_time_min || 0), 0) / Math.max(1, incidents.length))}m`} color={C.green} /></Panel>
      </div>

      {/* ═══════ INVESTIGATION DETAIL VIEW ═══════ */}
      {selected && panel === "investigate" && (
        <div style={{ display: "grid", gap: 12 }}>
          {backBtn}
          <Panel title={`🔬 Investigation — ${selected.incident_id}`} accent={C.accent} glow>
            <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16 }}>
              {/* Left col — details */}
              <div style={{ display: "grid", gap: 12 }}>
                <div>
                  <div style={{ fontSize: 16, fontWeight: 700, color: C.text, marginBottom: 8 }}>{selected.title}</div>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 8 }}>
                    <SeverityBadge severity={getEffectiveSeverity(selected)} />
                    <Badge color={C.cyan}>{getEffectiveStatus(selected)}</Badge>
                    <Badge color={C.textSoft}>{selected.category}</Badge>
                    <Badge color={C.textSoft}>{selected.playbook}</Badge>
                  </div>
                  <div style={{ fontSize: 10, color: C.textDim, fontFamily: MONO }}>
                    Lead: {selected.lead_analyst} · Created: {new Date(selected.created_at).toLocaleString()} · Assets: {selected.affected_assets}
                  </div>
                </div>
                {/* Status control */}
                <div style={{ padding: "10px 12px", background: C.surface, borderRadius: 6 }}>
                  <div style={{ fontSize: 10, color: C.textDim, marginBottom: 6, textTransform: "uppercase", letterSpacing: 1 }}>Status Control</div>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                    {["triaged","investigating","containing","eradicating","recovering","resolved"].map(s => (
                      <button key={s} onClick={() => handleStatusChange(selected.incident_id, s)} style={{
                        padding: "4px 10px", borderRadius: 4, fontSize: 10, fontWeight: 600, cursor: "pointer",
                        border: `1px solid ${getEffectiveStatus(selected) === s ? C.cyan : C.border}`,
                        background: getEffectiveStatus(selected) === s ? C.cyanDim : "transparent",
                        color: getEffectiveStatus(selected) === s ? C.cyan : C.textSoft,
                      }}>{s}</button>
                    ))}
                    {getEffectiveSeverity(selected) !== "CRITICAL" && (
                      <button onClick={() => handleEscalate(selected.incident_id)} style={{
                        padding: "4px 10px", borderRadius: 4, fontSize: 10, fontWeight: 700, cursor: "pointer",
                        border: `1px solid ${C.red}60`, background: C.redDim, color: C.red,
                      }}>▲ Escalate to CRITICAL</button>
                    )}
                  </div>
                </div>
                {/* MITRE ATT&CK */}
                <div style={{ padding: "10px 12px", background: C.surface, borderRadius: 6 }}>
                  <div style={{ fontSize: 10, color: C.textDim, marginBottom: 6, textTransform: "uppercase", letterSpacing: 1 }}>MITRE ATT&CK Techniques</div>
                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                    {selected.mitre_techniques.map((t, i) => (
                      <span key={i} style={{ padding: "3px 8px", background: C.purpleDim, borderRadius: 4, fontSize: 10, fontFamily: MONO, color: C.purple, border: `1px solid ${C.purple}30` }}>{t}</span>
                    ))}
                  </div>
                </div>
                {/* Evidence */}
                <div style={{ padding: "10px 12px", background: C.surface, borderRadius: 6 }}>
                  <div style={{ fontSize: 10, color: C.textDim, marginBottom: 6, textTransform: "uppercase", letterSpacing: 1 }}>Collected Evidence ({selected.evidence.length})</div>
                  {selected.evidence.map((e, i) => (
                    <div key={e.id} style={{ padding: "6px 8px", background: C.panel, borderRadius: 4, marginBottom: 4, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <div>
                        <div style={{ fontSize: 11, color: C.text, fontWeight: 500 }}>{e.desc}</div>
                        <div style={{ fontSize: 9, fontFamily: MONO, color: C.textDim }}>
                          {e.id} · {e.type} · {e.size_mb}MB · CoC: {e.chain_of_custody}
                        </div>
                      </div>
                      <Badge color={C.green}>secured</Badge>
                    </div>
                  ))}
                </div>
                {/* Analyst Notes */}
                <div style={{ padding: "10px 12px", background: C.surface, borderRadius: 6 }}>
                  <div style={{ fontSize: 10, color: C.textDim, marginBottom: 6, textTransform: "uppercase", letterSpacing: 1 }}>Analyst Notes</div>
                  <textarea
                    value={analystNotes[selected.incident_id] || ""}
                    onChange={e => setAnalystNotes(prev => ({ ...prev, [selected.incident_id]: e.target.value }))}
                    placeholder="Add investigation notes, findings, next steps…"
                    style={{
                      width: "100%", minHeight: 70, padding: "8px 10px", background: C.panel,
                      border: `1px solid ${C.border}`, borderRadius: 4, color: C.text,
                      fontFamily: MONO, fontSize: 11, resize: "vertical", outline: "none",
                    }}
                  />
                  <button onClick={() => addToast(`📝 Notes saved for ${selected.incident_id}`, C.green)} style={{
                    marginTop: 6, padding: "5px 14px", background: C.accent, color: "#fff",
                    border: "none", borderRadius: 4, fontSize: 10, fontWeight: 600, cursor: "pointer",
                  }}>Save Notes</button>
                </div>
              </div>
              {/* Right col — IOCs + quick actions */}
              <div style={{ display: "grid", gap: 12, alignContent: "start" }}>
                <div style={{ padding: "10px 12px", background: C.surface, borderRadius: 6 }}>
                  <div style={{ fontSize: 10, color: C.textDim, marginBottom: 6, textTransform: "uppercase", letterSpacing: 1 }}>IOC Indicators ({selected.iocs.length})</div>
                  {selected.iocs.map((ioc, i) => (
                    <div key={i} style={{ padding: "5px 8px", background: C.panel, borderRadius: 4, marginBottom: 3 }}>
                      <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                        <Badge color={C.red} style={{ fontSize: 8 }}>{ioc.type}</Badge>
                        <span style={{ fontSize: 10, fontFamily: MONO, color: C.text, wordBreak: "break-all" }}>{ioc.value.length > 40 ? ioc.value.slice(0,40)+"…" : ioc.value}</span>
                      </div>
                      <div style={{ fontSize: 8, color: C.textDim, fontFamily: MONO, marginTop: 2 }}>
                        via {ioc.source} · {new Date(ioc.first_seen).toLocaleTimeString()}
                      </div>
                    </div>
                  ))}
                </div>
                <div style={{ padding: "10px 12px", background: C.surface, borderRadius: 6 }}>
                  <div style={{ fontSize: 10, color: C.textDim, marginBottom: 6, textTransform: "uppercase", letterSpacing: 1 }}>Quick Actions</div>
                  <div style={{ display: "grid", gap: 4 }}>
                    <button onClick={() => { setPanel("approve"); }} style={{ padding: "6px 10px", background: C.amberDim, border: `1px solid ${C.amber}40`, borderRadius: 4, fontSize: 10, fontWeight: 600, color: C.amber, cursor: "pointer", textAlign: "left" }}>
                      🛡 Review Pending Actions ({getPendingCount(selected)})
                    </button>
                    <button onClick={() => { setPanel("timeline"); }} style={{ padding: "6px 10px", background: C.cyanDim, border: `1px solid ${C.cyan}40`, borderRadius: 4, fontSize: 10, fontWeight: 600, color: C.cyan, cursor: "pointer", textAlign: "left" }}>
                      📜 View Full Timeline ({selected.timeline.length} events)
                    </button>
                    <button onClick={() => handleEscalate(selected.incident_id)} style={{ padding: "6px 10px", background: C.redDim, border: `1px solid ${C.red}40`, borderRadius: 4, fontSize: 10, fontWeight: 600, color: C.red, cursor: "pointer", textAlign: "left" }}>
                      ▲ Escalate Severity
                    </button>
                    <button onClick={() => { handleStatusChange(selected.incident_id, "resolved"); addToast(`✓ ${selected.incident_id} marked resolved`, C.green); }} style={{ padding: "6px 10px", background: C.greenDim, border: `1px solid ${C.green}40`, borderRadius: 4, fontSize: 10, fontWeight: 600, color: C.green, cursor: "pointer", textAlign: "left" }}>
                      ✓ Mark Resolved
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </Panel>
        </div>
      )}

      {/* ═══════ ACTION APPROVAL VIEW ═══════ */}
      {selected && panel === "approve" && (
        <div style={{ display: "grid", gap: 12 }}>
          {backBtn}
          <Panel title={`🛡 Action Approval — ${selected.incident_id}`} accent={C.amber} glow>
            <div style={{ marginBottom: 12, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: C.text }}>{selected.title}</div>
                <div style={{ fontSize: 10, color: C.textSoft }}>{getPendingCount(selected)} of {selected.pending_actions.length} actions awaiting approval</div>
              </div>
              {getPendingCount(selected) > 0 && (
                <button onClick={() => handleApproveAll(selected.pending_actions)} style={{
                  padding: "6px 16px", background: C.green, color: "#fff", border: "none",
                  borderRadius: 5, fontSize: 11, fontWeight: 700, cursor: "pointer",
                }}>✓ Approve All Remaining</button>
              )}
            </div>

            <div style={{ display: "grid", gap: 6 }}>
              {selected.pending_actions.map(act => {
                const st = actionStatuses[act.id];
                return (
                  <div key={act.id} style={{
                    padding: "12px 14px", background: C.surface, borderRadius: 6,
                    border: `1px solid ${st === "approved" ? C.green + "40" : st === "rejected" ? C.red + "40" : C.border}`,
                    opacity: st ? 0.7 : 1, transition: "all 0.3s ease",
                  }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 12, fontWeight: 600, color: C.text, marginBottom: 4 }}>{act.action}</div>
                        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                          <Badge color={C.cyan}>{act.type}</Badge>
                          <Badge color={riskColor[act.risk]}>{act.risk} risk</Badge>
                          <span style={{ fontSize: 9, color: C.textDim, fontFamily: MONO }}>
                            {act.id} · by {act.requested_by} · {new Date(act.requested_at).toLocaleTimeString()}
                          </span>
                        </div>
                      </div>
                      <div style={{ display: "flex", gap: 6, marginLeft: 12 }}>
                        {st === "approved" ? (
                          <Badge color={C.green}>✓ APPROVED — EXECUTING</Badge>
                        ) : st === "rejected" ? (
                          <Badge color={C.red}>✗ REJECTED</Badge>
                        ) : (
                          <>
                            <button onClick={() => handleApprove(act.id)} style={{
                              padding: "5px 14px", background: C.green, color: "#fff", border: "none",
                              borderRadius: 4, fontSize: 10, fontWeight: 700, cursor: "pointer",
                            }}>✓ Approve</button>
                            <button onClick={() => handleReject(act.id)} style={{
                              padding: "5px 14px", background: "transparent", color: C.red,
                              border: `1px solid ${C.red}50`, borderRadius: 4, fontSize: 10, fontWeight: 600, cursor: "pointer",
                            }}>✗ Reject</button>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </Panel>
          <div style={{ display: "flex", gap: 8 }}>
            <button onClick={() => setPanel("investigate")} style={{ padding: "6px 14px", background: C.accent, color: "#fff", border: "none", borderRadius: 5, fontSize: 11, fontWeight: 600, cursor: "pointer" }}>🔬 Back to Investigation</button>
            <button onClick={() => setPanel("timeline")} style={{ padding: "6px 14px", background: "transparent", color: C.cyan, border: `1px solid ${C.cyan}40`, borderRadius: 5, fontSize: 11, fontWeight: 600, cursor: "pointer" }}>📜 View Timeline</button>
          </div>
        </div>
      )}

      {/* ═══════ TIMELINE VIEW ═══════ */}
      {selected && panel === "timeline" && (
        <div style={{ display: "grid", gap: 12 }}>
          {backBtn}
          <Panel title={`📜 Incident Timeline — ${selected.incident_id}`} accent={C.cyan} glow>
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: C.text }}>{selected.title}</div>
              <div style={{ fontSize: 10, color: C.textSoft }}>{selected.timeline.length} events · {new Date(selected.created_at).toLocaleString()} → present</div>
            </div>
            <div style={{ position: "relative", paddingLeft: 28 }}>
              {/* Timeline line */}
              <div style={{ position: "absolute", left: 10, top: 4, bottom: 4, width: 2, background: `linear-gradient(180deg, ${C.cyan}, ${C.border})`, borderRadius: 1 }} />
              {selected.timeline.map((evt, i) => (
                <div key={i} style={{ position: "relative", marginBottom: 12, paddingBottom: 4 }}>
                  {/* Timeline dot */}
                  <div style={{
                    position: "absolute", left: -22, top: 4, width: 10, height: 10,
                    borderRadius: "50%", background: typeColor[evt.type] || C.cyan,
                    border: `2px solid ${C.panel}`, boxShadow: `0 0 6px ${typeColor[evt.type] || C.cyan}50`,
                  }} />
                  <div style={{ padding: "8px 12px", background: C.surface, borderRadius: 6, border: `1px solid ${C.border}` }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 4 }}>
                      <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                        <span style={{ fontSize: 12 }}>{typeIcon[evt.type] || "●"}</span>
                        <Badge color={typeColor[evt.type] || C.textDim}>{evt.type}</Badge>
                        <span style={{ fontSize: 9, color: C.textDim, fontFamily: MONO }}>{evt.actor}</span>
                      </div>
                      <span style={{ fontSize: 9, color: C.textDim, fontFamily: MONO }}>{new Date(evt.time).toLocaleTimeString()}</span>
                    </div>
                    <div style={{ fontSize: 11, color: C.text, lineHeight: 1.5 }}>{evt.event}</div>
                  </div>
                </div>
              ))}
            </div>
          </Panel>
          <div style={{ display: "flex", gap: 8 }}>
            <button onClick={() => setPanel("investigate")} style={{ padding: "6px 14px", background: C.accent, color: "#fff", border: "none", borderRadius: 5, fontSize: 11, fontWeight: 600, cursor: "pointer" }}>🔬 Back to Investigation</button>
            <button onClick={() => setPanel("approve")} style={{ padding: "6px 14px", background: "transparent", color: C.amber, border: `1px solid ${C.amber}40`, borderRadius: 5, fontSize: 11, fontWeight: 600, cursor: "pointer" }}>🛡 Review Actions</button>
          </div>
        </div>
      )}

      {/* ═══════ INCIDENT LIST (default) ═══════ */}
      {!selected && (
        <>
          <Panel title="Active Incidents" icon="🚨" accent={C.red}>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {incidents.map(inc => (
                <div key={inc.incident_id} style={{
                  padding: 14, background: C.surface, borderRadius: 8,
                  border: `1px solid ${getEffectiveSeverity(inc) === "CRITICAL" ? C.red + "30" : C.border}`,
                  boxShadow: getEffectiveSeverity(inc) === "CRITICAL" ? `0 0 20px ${C.red}06` : "none",
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                    <div>
                      <div style={{ fontSize: 14, fontWeight: 600, color: C.text, marginBottom: 6 }}>{inc.title}</div>
                      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                        <SeverityBadge severity={getEffectiveSeverity(inc)} />
                        <Badge color={C.cyan}>{getEffectiveStatus(inc)}</Badge>
                        <Badge color={C.textSoft}>{inc.category}</Badge>
                        <Badge color={C.textSoft}>{inc.incident_id}</Badge>
                        {analystNotes[inc.incident_id] && <Badge color={C.green}>📝 notes</Badge>}
                      </div>
                    </div>
                    <div style={{ textAlign: "right" }}>
                      <div style={{ fontSize: 10, color: C.textSoft }}>{inc.affected_assets} assets · {inc.evidence.length} evidence</div>
                      <div style={{ fontSize: 10, color: C.textDim, fontFamily: MONO }}>{inc.lead_analyst}</div>
                      {getPendingCount(inc) > 0 && (
                        <Badge color={C.amber} style={{ marginTop: 4 }}>{getPendingCount(inc)} actions pending</Badge>
                      )}
                    </div>
                  </div>
                  <div style={{ marginTop: 8, display: "flex", gap: 8 }}>
                    <button onClick={() => { setSelectedId(inc.incident_id); setPanel("investigate"); }} style={{
                      padding: "5px 14px", background: C.accent, color: "#fff", border: "none",
                      borderRadius: 4, fontSize: 10, fontWeight: 600, cursor: "pointer",
                      transition: "all 0.2s", boxShadow: `0 0 10px ${C.accent}30`,
                    }}>🔬 Investigate</button>
                    <button onClick={() => { setSelectedId(inc.incident_id); setPanel("approve"); }} style={{
                      padding: "5px 14px", background: "transparent", color: C.amber,
                      border: `1px solid ${C.amber}40`, borderRadius: 4, fontSize: 10, fontWeight: 600, cursor: "pointer",
                      transition: "all 0.2s",
                    }}>🛡 Approve Actions{getPendingCount(inc) > 0 ? ` (${getPendingCount(inc)})` : ""}</button>
                    <button onClick={() => { setSelectedId(inc.incident_id); setPanel("timeline"); }} style={{
                      padding: "5px 14px", background: "transparent", color: C.cyan,
                      border: `1px solid ${C.cyan}40`, borderRadius: 4, fontSize: 10, fontWeight: 600, cursor: "pointer",
                      transition: "all 0.2s",
                    }}>📜 Timeline ({inc.timeline.length})</button>
                  </div>
                </div>
              ))}
            </div>
          </Panel>

          <Panel title="Response Playbooks" icon="📋" accent={C.green}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8 }}>
              {["Ransomware Response", "APT Campaign Response", "Data Breach Response", "Unauthorized Access", "Phishing Response", "Insider Threat"].map(pb => (
                <div key={pb} style={{ padding: "8px 10px", background: C.surface, borderRadius: 6, display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{ color: C.green, fontSize: 10 }}>▶</span>
                  <span style={{ fontSize: 11, color: C.text }}>{pb}</span>
                </div>
              ))}
            </div>
          </Panel>
        </>
      )}
    </div>
  );
}

// ─── VULN TAB ─────────────────────────────────────────────────────────────

function VulnsTab({ onAvatarStateChange }) {
  const [apiKey, setApiKey] = useState(() => localStorage.getItem("qc_api_key") || "");
  const [ack, setAck] = useState(false);

  const [target, setTarget] = useState("192.168.1.0/24");
  const [scanType, setScanType] = useState("full"); // full|quick|compliance|web_app
  const [webUrl, setWebUrl] = useState("https://example.com");

  const [submitting, setSubmitting] = useState(false);
  const [scanId, setScanId] = useState(null);
  const [scanStatus, setScanStatus] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [remediation, setRemediation] = useState(null);
  const [error, setError] = useState("");

  // ── One-Click Remediate State
  const [oneClickRunning, setOneClickRunning] = useState(false);
  const [oneClickPhase, setOneClickPhase] = useState("");
  const [oneClickLog, setOneClickLog] = useState([]);
  const [oneClickResult, setOneClickResult] = useState(null);
  const ocLog = (msg, color) => setOneClickLog(prev => [...prev, { msg, color: color || "#8a9dbd", ts: new Date().toLocaleTimeString() }]);

  const headers = useMemo(() => {
    const h = { "Content-Type": "application/json" };
    if (apiKey && apiKey.trim()) h["X-QC-API-Key"] = apiKey.trim();
    return h;
  }, [apiKey]);

  const apiFetch = useCallback(async (path, init = {}) => {
    const res = await fetch(`${QC_API}${path}`, { ...init, headers: { ...(init.headers || {}), ...headers } });
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { json = null; }
    if (!res.ok) {
      const msg = json?.error || json?.message || `${res.status} ${res.statusText}`;
      throw new Error(msg);
    }
    if (text && json === null) {
      const snippet = String(text).slice(0, 220).replace(/\s+/g, " ");
      throw new Error(`Non-JSON response from backend (${res.status}). Snippet: ${snippet}`);
    }
    return json;
  }, [headers]);

  const normalizeStatus = useCallback((payload) => {
    // Celery path:
    //   { scan_id, state, ready, result? }
    // Local job store:
    //   { scan_id, status, result? }
    if (!payload) return { state: "unknown", ready: false, result: null };

    if (payload.result) {
      return { state: payload.state || payload.status || "completed", ready: true, result: payload.result };
    }

    const state = payload.state || payload.status || "unknown";
    const ready = payload.ready === true || state === "completed" || state === "SUCCESS";
    const result = payload.result || payload?.data?.result || null;
    return { state, ready, result };
  }, []);

  const downloadText = useCallback((filename, content) => {
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 500);
  }, []);

  const remediationToScript = useCallback((plan, format) => {
    const actions = plan?.priority_actions || [];
    if (!actions.length) return "# No remediation actions available.\n";

    if (format === "powershell") {
      const lines = [
        "# QueenCalifia — Remediation Guidance (PowerShell)",
        "# Review carefully before applying changes.",
        "",
      ];
      for (const a of actions) {
        lines.push(`# [P${a.priority}] ${a.title} (${a.cve_id || a.vuln_id}) — Severity: ${a.severity} CVSS: ${a.cvss_score}`);
        lines.push(`# Asset: ${a.affected_asset || "n/a"}`);
        lines.push(`# Guidance: ${a.remediation || "n/a"}`);
        lines.push("");
      }
      return lines.join("\n");
    }

    if (format === "ansible") {
      const lines = [
        "# QueenCalifia — Remediation Guidance (Ansible YAML scaffold)",
        "# NOTE: This is a scaffold; you must adapt tasks to your environment.",
        "---",
        "- name: QC remediation (review + adapt)",
        "  hosts: all",
        "  become: true",
        "  tasks:",
      ];
      for (const a of actions) {
        lines.push(`    - name: "[P${a.priority}] ${a.title} (${a.cve_id || a.vuln_id})"`);
        lines.push("      debug:");
        lines.push(`        msg: "${String(a.remediation || "n/a").replaceAll('"', '\"')}"`);
      }
      lines.push("");
      return lines.join("\n");
    }

    // default: bash
    const lines = [
      "#!/usr/bin/env bash",
      "# QueenCalifia — Remediation Guidance (Bash)",
      "# Review carefully before applying changes.",
      "set -euo pipefail",
      "",
    ];
    for (const a of actions) {
      lines.push(`# [P${a.priority}] ${a.title} (${a.cve_id || a.vuln_id}) — Severity: ${a.severity} CVSS: ${a.cvss_score}`);
      lines.push(`# Asset: ${a.affected_asset || "n/a"}`);
      lines.push(`# Guidance: ${a.remediation || "n/a"}`);
      lines.push("");
    }
    return lines.join("\n");
  }, []);

  // If the real vuln backend is not reachable on production, we fall back to a deterministic simulation
  // so the UI experience (tabs/buttons/avatar states/animations) still works end-to-end.
  const simulateSeed = useCallback((s) => {
    const str = String(s || "");
    let h = 0;
    for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) % 100000;
    return h;
  }, []);

  const simulateScan = useCallback((opts) => {
    const target = String(opts?.target || "");
    const scanType = String(opts?.scanType || "full");
    const webUrl = String(opts?.webUrl || "https://example.com");
    const seed = simulateSeed(`${target}|${scanType}|${webUrl}`);

    const critical_count = seed % 2 === 0 ? 1 : 0;
    const high_count = (seed % 3) + 1; // 1..3
    const medium_count = (seed % 5) + 1; // 1..5
    const low_count = (seed % 4); // 0..3
    const info_count = 0;

    const assets_discovered = 10 + (seed % 40);
    const vulnerabilities_found = critical_count + high_count + medium_count + low_count + info_count;
    const risk_score = Math.round(((critical_count * 9 + high_count * 6 + medium_count * 3 + low_count) / Math.max(1, vulnerabilities_found)) * 100) / 100;

    const sevOrder = [
      { key: "CRITICAL", count: critical_count, color: C.red },
      { key: "HIGH", count: high_count, color: C.amber },
      { key: "MEDIUM", count: medium_count, color: C.textSoft },
      { key: "LOW", count: low_count, color: C.green },
    ];

    const findingPool = [];
    let idx = 0;
    for (const block of sevOrder) {
      for (let i = 0; i < block.count; i++) {
        const j = idx++;
        findingPool.push({
          title: `${block.key} — ${target || "target"} :: Oracle Path Drift ${j}`,
          severity: block.key,
          description: `Simulated finding for UI continuity (severity ${block.key}).`,
          remediation: `Apply patch guidance for ${block.key} (${j}).`,
          cve_id: `CVE-${2020 + (seed % 6)}-${1000 + j}`,
          vuln_id: `VULN-${seed % 9000}-${j}`,
          affected_service: scanType === "web_app" ? "web_app" : "network_service",
          affected_asset: scanType === "web_app" ? webUrl : target,
          cvss_score: block.key === "CRITICAL" ? 9.8 : block.key === "HIGH" ? 8.2 : block.key === "MEDIUM" ? 5.6 : 3.1,
          exploitability: block.key === "CRITICAL" || block.key === "HIGH" ? "active" : "theoretical",
        });
      }
    }

    // Cap findings so the UI stays fast.
    const findings = findingPool.slice(0, 10);

    if (scanType === "web_app") {
      return {
        target_url: webUrl,
        scan_type: "web_app",
        critical_count,
        high_count,
        medium_count,
        low_count,
        risk_score,
        summary: { critical: critical_count, high: high_count, medium: medium_count, low: low_count, info: info_count },
        findings,
      };
    }

    const scan_id = `sim-${Date.now()}-${seed.toString(16).slice(0, 6)}`;
    return {
      scan_id,
      target,
      scan_type: scanType,
      completed_at: new Date().toISOString(),
      critical_count,
      high_count,
      medium_count,
      low_count,
      assets_discovered,
      vulnerabilities_found,
      risk_score,
      summary: { critical: critical_count, high: high_count, medium: medium_count, low: low_count, info: info_count },
      findings,
    };
  }, [C.red, C.amber, C.textSoft, C.green, simulateSeed]);

  const simulateRemediationPlan = useCallback((scanOrCounts, planForTarget) => {
    const scan = scanOrCounts || {};
    const critical = scan.summary?.critical ?? scan.critical_count ?? 0;
    const high = scan.summary?.high ?? scan.high_count ?? 0;
    const medium = scan.summary?.medium ?? scan.medium_count ?? 0;
    const low = scan.summary?.low ?? scan.low_count ?? 0;
    const total = critical + high + medium + low;

    const actions = [];
    const mk = (priority, sevKey) => {
      const baseTitle = sevKey === "CRITICAL" ? "Critical Exploit Chain Shutdown" :
        sevKey === "HIGH" ? "High-Risk Vector Hardening" :
          sevKey === "MEDIUM" ? "Medium-Risk Control Tightening" : "Low-Risk Noise Reduction";
      const j = actions.length;
      const affected_asset = scan?.target || planForTarget || "127.0.0.1";
      return {
        priority: priority,
        title: `${baseTitle} (#${j + 1})`,
        severity: sevKey,
        cve_id: scan?.findings?.[j]?.cve_id || `CVE-${2025}-${1000 + j}`,
        vuln_id: scan?.findings?.[j]?.vuln_id || `VULN-${10000 + j}`,
        cvss_score: sevKey === "CRITICAL" ? 9.9 : sevKey === "HIGH" ? 8.4 : sevKey === "MEDIUM" ? 5.9 : 2.8,
        affected_asset,
        remediation: `Simulated remediation guidance for ${sevKey} against ${affected_asset}.`,
        affected_asset_root: affected_asset,
      };
    };

    // Prioritize critical → high → medium → low (stable priorities).
    let prio = 1;
    for (let i = 0; i < critical; i++) actions.push(mk(prio++, "CRITICAL"));
    for (let i = 0; i < high; i++) actions.push(mk(prio++, "HIGH"));
    for (let i = 0; i < medium; i++) actions.push(mk(prio++, "MEDIUM"));
    for (let i = 0; i < low; i++) actions.push(mk(prio++, "LOW"));

    const plan_id = `plan-${Date.now()}`;
    return {
      plan_id,
      total_vulnerabilities: total,
      summary: { critical, high, medium, low, info: 0 },
      priority_actions: actions.slice(0, 24),
    };
  }, []);

  const simulateOneClickResult = useCallback((plan) => {
    const total = plan?.total_vulnerabilities ?? plan?.priority_actions?.length ?? 0;
    return {
      total,
      actions_executed: (plan?.priority_actions || []).slice(0, 8).map((a) => `Applied: ${a.title}`),
    };
  }, []);

  const isLikelyAuthFailure = useCallback((err) => {
    const msg = String(err?.message || err || "").toLowerCase();
    // Keep this narrowly scoped so we only skip simulation when the backend is reachable
    // but explicitly denying us (missing/invalid API key, etc).
    return msg.includes("unauthorized") || msg.includes("forbidden") || msg.includes(" 401") || msg.includes(" 403");
  }, []);

  const fetchRemediation = useCallback(async () => {
    try {
      const r = await apiFetch("/api/vulns/remediation");
      setRemediation(r?.data || null);
    } catch (e) {
      const msg = String(e?.message || e || "");
      if (isLikelyAuthFailure(msg)) {
        setError(msg);
        return;
      }
      setError(msg || "Unable to load remediation plan.");
      setRemediation(null);
    }
  }, [apiFetch]);

  const computedAvatarState = useMemo(() => {
    const phase = String(oneClickPhase || "").toLowerCase();
    const isRemediating = oneClickRunning || phase === "remediating";
    const isScanning =
      oneClickRunning ||
      (scanStatus && !scanStatus.ready && ["pending", "queued", "running", "in_progress", "active", "scanning"].includes(String(scanStatus.state || scanStatus.status || "").toLowerCase()));

    const criticalCount =
      (scanResult?.critical_count ?? scanResult?.summary?.critical ?? 0) || 0;

    if (isRemediating) return "staff_raised";
    if (criticalCount > 0) return "ascended";
    if (isScanning) return "hex_shield";
    if (scanStatus?.ready) return "active";
    return "idle";
  }, [oneClickRunning, oneClickPhase, scanStatus, scanResult]);

  useEffect(() => {
    if (onAvatarStateChange) onAvatarStateChange(computedAvatarState);
  }, [computedAvatarState, onAvatarStateChange]);

  const oneClickRemediate = async () => {
    setOneClickRunning(true);
    setOneClickPhase("scanning");
    setOneClickLog([]);
    setOneClickResult(null);
    setError("");
    ocLog("⚡ Starting one-click remediation of 127.0.0.1...", "#60a5fa");
    onAvatarStateChange?.("hex_shield");
    try {
      ocLog("🔍 Launching full scan of localhost...");
      const workflowResp = await fetch(`${QC_API}/api/v1/one-click/scan-and-fix`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(apiKey ? { "X-QC-API-Key": apiKey } : {}) },
        body: JSON.stringify({
          target: "127.0.0.1",
          scan_type: "full",
          auto_approve: true,
          acknowledge_authorized: true,
        }),
      });
      const workflowText = await workflowResp.text();
      let workflowJson = null;
      try { workflowJson = workflowText ? JSON.parse(workflowText) : null; } catch {
        throw new Error(`Non-JSON one-click response (${workflowResp.status}). Snippet: ${String(workflowText).slice(0, 220)}`);
      }
      if (!workflowResp.ok) throw new Error(workflowJson?.error || workflowJson?.message || `HTTP ${workflowResp.status}`);
      const result = workflowJson?.data || workflowJson;
      const scan = result?.phases?.scan || {};
      const normalizedScan = {
        scan_id: scan.scan_id || result?.operation_id || null,
        target: result?.target || "127.0.0.1",
        scan_type: "full",
        critical_count: scan.critical || 0,
        high_count: scan.high || 0,
        medium_count: scan.medium || 0,
        low_count: scan.low || 0,
        assets_discovered: scan.hosts_alive || 0,
        vulnerabilities_found: scan.total_findings || 0,
        risk_score: scan.overall_risk || 0,
        quantum_risk: scan.quantum_risk || null,
        summary: {
          critical: scan.critical || 0,
          high: scan.high || 0,
          medium: scan.medium || 0,
          low: scan.low || 0,
        },
      };
      if (normalizedScan.scan_id) {
        setScanId(normalizedScan.scan_id);
        ocLog("✓ Scan queued — ID: " + normalizedScan.scan_id, "#10b981");
      }
      setScanStatus({ state: "completed", ready: true, result: normalizedScan });
      setScanResult(normalizedScan);
      ocLog("  ↳ Scan status: completed");
      ocLog("✓ Scan complete!", "#10b981");

      setOneClickPhase("remediating");
      onAvatarStateChange?.("staff_raised");
      ocLog("🛠️ Executing auto-remediation...", "#f59e0b");
      setOneClickResult(result);
      try {
        await fetchRemediation();
      } catch {}
      setOneClickPhase("done");
      ocLog("✅ All done — one-click workflow completed.", "#10b981");
      onAvatarStateChange?.((scan.critical || 0) > 0 ? "ascended" : "active");
    } catch (e) {
      const msg = String(e?.message || e || "");
      setOneClickPhase("error");
      setError(msg);
      ocLog("❌ " + msg, "#ef4444");
      onAvatarStateChange?.("idle");
    } finally {
      setOneClickRunning(false);
    }
  };

  const launchScan = useCallback(async () => {
    setError("");
    setRemediation(null);
    setScanResult(null);
    setScanStatus(null);

    if (!ack) {
      setError("You must confirm you are authorized to scan this target.");
      return;
    }

    setSubmitting(true);
    onAvatarStateChange?.("hex_shield");
    try {
      if (scanType === "web_app") {
        const r = await apiFetch("/api/vulns/webapp", {
          method: "POST",
          body: JSON.stringify({ url: webUrl, acknowledge_authorized: true }),
        });
        setScanResult(r?.data || null);
        // webapp scans have their own findings; still show remediation guidance
        await fetchRemediation();
        return;
      }

      const r = await apiFetch("/api/vulns/scan", {
        method: "POST",
        body: JSON.stringify({
          target,
          scan_type: scanType,
          mode: "async",
          acknowledge_authorized: true,
        }),
      });
      const id = r?.data?.scan_id || r?.data?.scanId || null;
      if (!id) throw new Error("scan_id missing from response");
      setScanId(id);
      setScanStatus({ state: r?.data?.status || "queued", ready: false });
    } catch (e) {
      const msg = String(e?.message || e || "");
      setError(msg);
      setScanId(null);
      setScanStatus(null);
      setScanResult(null);
      setRemediation(null);
      onAvatarStateChange?.("idle");
    } finally {
      setSubmitting(false);
    }
  }, [ack, apiFetch, fetchRemediation, onAvatarStateChange, scanType, target, webUrl]);

  useEffect(() => {
    localStorage.setItem("qc_api_key", apiKey || "");
  }, [apiKey]);

  useEffect(() => {
    if (!scanId) return;
    // Skip polling when we are in UI simulation mode.
    if (String(scanId).startsWith("sim-")) return;
    let cancelled = false;
    let notFoundStreak = 0;
    const tick = async () => {
      try {
        const r = await apiFetch(`/api/vulns/scan/${encodeURIComponent(scanId)}`, { method: "GET" });
        const s = normalizeStatus(r?.data || null);
        if (cancelled) return;
        notFoundStreak = 0;
        setError("");
        setScanStatus(s);
        if (s.ready) {
          setScanResult(s.result || null);
          const critical = (s.result?.critical_count ?? s.result?.summary?.critical ?? 0) || 0;
          onAvatarStateChange?.(critical > 0 ? "ascended" : "active");
          await fetchRemediation();
          return;
        }
      } catch (e) {
        const msg = String(e?.message || e || "");
        const transientMissing = /scan not found/i.test(msg);
        if (!cancelled && transientMissing) {
          notFoundStreak += 1;
          setScanStatus((prev) => prev || { state: "queued", ready: false, result: null });
          if (notFoundStreak >= 4) {
            setError("Scan status is synchronizing across the backend. Holding the scan session and retrying...");
          }
        } else if (!cancelled) {
          setError(msg);
          onAvatarStateChange?.("idle");
        }
      }
      if (!cancelled) setTimeout(tick, notFoundStreak > 0 ? 1500 : 2000);
    };
    tick();
    return () => { cancelled = true; };
  }, [apiFetch, fetchRemediation, normalizeStatus, onAvatarStateChange, scanId]);

  const [scriptFmt, setScriptFmt] = useState("bash"); // bash|powershell|ansible

  return (
    <div style={{ display: "grid", gap: 16 }}>
      {/* ── ONE-CLICK REMEDIATE BANNER */}
      <div style={{ padding: "16px 20px", background: "linear-gradient(135deg, rgba(37,99,235,0.15) 0%, rgba(16,185,129,0.10) 100%)", border: "1px solid rgba(37,99,235,0.35)", borderRadius: 10, marginBottom: 16 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
          <div>
            <div style={{ fontSize: 15, fontWeight: 700, color: "#d4dff0", letterSpacing: 0.3 }}>⚡ One-Click Remediate</div>
            <div style={{ fontSize: 11, color: "#8a9dbd", marginTop: 3 }}>Scans 127.0.0.1 and auto-applies all fixes — no prompts</div>
          </div>
          <button
            onClick={oneClickRemediate}
            disabled={oneClickRunning}
            style={{ padding: "12px 28px", background: oneClickRunning ? "#1a2d50" : "linear-gradient(135deg, #2563eb, #10b981)", color: "#fff", border: "none", borderRadius: 8, fontSize: 13, fontWeight: 700, cursor: oneClickRunning ? "wait" : "pointer", boxShadow: oneClickRunning ? "none" : "0 0 20px rgba(37,99,235,0.4)", whiteSpace: "nowrap" }}
          >
            {oneClickRunning ? (oneClickPhase === "scanning" ? "🔍 Scanning..." : oneClickPhase === "remediating" ? "🛠️ Remediating..." : "⏳ Working...") : "⚡ REMEDIATE ALL"}
          </button>
        </div>
        {oneClickLog.length > 0 && (
          <div style={{ marginTop: 12, padding: "10px 14px", background: "rgba(6,10,20,0.7)", borderRadius: 6, fontFamily: "'JetBrains Mono', monospace", fontSize: 10, maxHeight: 160, overflowY: "auto", display: "flex", flexDirection: "column", gap: 3 }}>
            {oneClickLog.map((l, i) => (
              <div key={i} style={{ color: l.color }}>
                <span style={{ color: "#4a6080", marginRight: 8 }}>{l.ts}</span>{l.msg}
              </div>
            ))}
            {oneClickPhase === "done" && oneClickResult && (
              <div style={{ marginTop: 8, color: "#10b981", fontWeight: 600 }}>
                ✅ Actions applied: {JSON.stringify(
                  oneClickResult?.actions_executed
                  || oneClickResult?.phases?.execution?.actions?.map((a) => a.title || a.action_id)
                  || oneClickResult?.phases?.execution?.total_actions
                  || oneClickResult?.total
                  || "see plan below"
                )}
              </div>
            )}
          </div>
        )}
      </div>
      <Panel title="Vulnerability Scanner (Authorized Use Only)" icon="🔍" accent={C.accent}>
        <div style={{ display: "grid", gap: 10 }}>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <input
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="API key (X-QC-API-Key) — leave blank if QC_NO_AUTH=1"
              style={{ flex: 1, minWidth: 320, padding: "8px 12px", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, fontFamily: MONO, fontSize: 12, outline: "none" }}
              type="password"
              autoComplete="off"
            />
            <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11, color: C.textDim, userSelect: "none" }}>
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
              I am authorized to scan this target
            </label>
          </div>

          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            {scanType !== "web_app" ? (
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="Target IP/CIDR..."
                style={{ flex: 1, minWidth: 260, padding: "8px 12px", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, fontFamily: MONO, fontSize: 12, outline: "none" }}
              />
            ) : (
              <input
                value={webUrl}
                onChange={(e) => setWebUrl(e.target.value)}
                placeholder="https://target.example"
                style={{ flex: 1, minWidth: 260, padding: "8px 12px", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, fontFamily: MONO, fontSize: 12, outline: "none" }}
              />
            )}

            <select
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
              style={{ padding: "8px 12px", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, fontFamily: MONO, fontSize: 12 }}
            >
              <option value="full">Full Scan</option>
              <option value="quick">Quick Scan</option>
              <option value="compliance">Compliance</option>
              <option value="web_app">Web App</option>
            </select>

            <button
              onClick={launchScan}
              disabled={submitting}
              style={{ padding: "8px 20px", background: submitting ? C.textDim : C.accent, color: "#fff", border: "none", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: submitting ? "wait" : "pointer", whiteSpace: "nowrap" }}
            >
              {submitting ? "Submitting..." : "Launch Scan"}
            </button>

            <button
              onClick={() => { setScanId(null); setScanStatus(null); setScanResult(null); setRemediation(null); setError(""); }}
              style={{ padding: "8px 16px", background: C.surface, color: C.text, border: `1px solid ${C.border}`, borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: "pointer", whiteSpace: "nowrap" }}
            >
              Reset
            </button>
          </div>

          <div style={{ fontSize: 10, color: C.textDim }}>
            Guardrails: backend denies public targets by default; allowlist is set server-side via <span style={{ fontFamily: MONO }}>QC_SCAN_ALLOWLIST</span>. Scanning networks you don't own or aren't explicitly authorized to test is not supported.
          </div>

          {!!error && (
            <div style={{ padding: "8px 10px", background: C.surface, border: `1px solid ${C.red}`, borderRadius: 6, color: C.red, fontSize: 11 }}>
              {error}
            </div>
          )}

          {scanId && (
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <Badge color={C.accent}>scan_id: <span style={{ fontFamily: MONO }}>{scanId}</span></Badge>
              <Badge color={C.textDim}>state: <span style={{ fontFamily: MONO }}>{scanStatus?.state || "unknown"}</span></Badge>
              {!!scanStatus?.ready && <Badge color={C.green}>READY</Badge>}
            </div>
          )}
        </div>
      </Panel>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <Panel title="Latest Scan Result" icon="📈" accent={C.accent}>
          {!scanResult ? (
            <div style={{ fontSize: 12, color: C.textDim }}>
              Run a scan to populate results.
            </div>
          ) : (
            <div style={{ display: "grid", gap: 10 }}>
              {"scan_id" in scanResult ? (
                <>
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                    <Badge color={C.accent}>Target: <span style={{ fontFamily: MONO }}>{scanResult.target}</span></Badge>
                    <Badge color={C.textDim}>Type: <span style={{ fontFamily: MONO }}>{scanResult.scan_type}</span></Badge>
                    <Badge color={C.red}>Critical: {scanResult.critical_count}</Badge>
                    <Badge color={C.amber}>High: {scanResult.high_count}</Badge>
                    <Badge color={C.textDim}>Medium: {scanResult.medium_count}</Badge>
                    <Badge color={C.textDim}>Low: {scanResult.low_count}</Badge>
                  </div>
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                    <Badge color={C.textDim}>Assets: {scanResult.assets_discovered}</Badge>
                    <Badge color={C.textDim}>Findings: {scanResult.vulnerabilities_found}</Badge>
                    <Badge color={C.green}>Risk score: {scanResult.risk_score}</Badge>
                  </div>
                  <div style={{ fontSize: 11, color: C.textDim }}>
                    This UI shows aggregated counts. Use the Remediation Plan panel for prioritized actions and guidance.
                  </div>
                </>
              ) : (
                <>
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                    <Badge color={C.accent}>Web App Scan</Badge>
                    <Badge color={C.textDim}><span style={{ fontFamily: MONO }}>{scanResult.target_url || "n/a"}</span></Badge>
                  </div>
                  <div style={{ fontSize: 11, color: C.textDim }}>
                    Findings: {(scanResult.findings || []).length}
                  </div>
                  <div style={{ display: "grid", gap: 6 }}>
                    {(scanResult.findings || []).slice(0, 6).map((f, idx) => (
                      <div key={idx} style={{ padding: "8px 10px", background: C.surface, borderRadius: 6 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                          <div style={{ fontSize: 11, color: C.text }}>{f.title || f.category || "Finding"}</div>
                          <Badge color={String(f.severity || "").toUpperCase() === "HIGH" ? C.red : C.amber}>{f.severity || "INFO"}</Badge>
                        </div>
                        <div style={{ fontSize: 10, color: C.textDim, marginTop: 4 }}>{f.description || f.details || ""}</div>
                        {!!f.remediation && <div style={{ fontSize: 10, color: C.textDim, marginTop: 4 }}>Fix: {f.remediation}</div>}
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>
          )}
        </Panel>

        <Panel title="Remediation Plan (One-Click Export)" icon="🛠️" accent={C.green}>
          {!remediation ? (
            <div style={{ display: "grid", gap: 10 }}>
              <div style={{ fontSize: 12, color: C.textDim }}>
                No plan loaded yet.
              </div>
              <button
                onClick={fetchRemediation}
                style={{ padding: "8px 16px", background: C.surface, color: C.text, border: `1px solid ${C.border}`, borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: "pointer", width: "fit-content" }}
              >
                Load current plan
              </button>
            </div>
          ) : (
            <div style={{ display: "grid", gap: 10 }}>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <Badge color={C.green}>Plan: <span style={{ fontFamily: MONO }}>{remediation.plan_id}</span></Badge>
                <Badge color={C.textDim}>Total: {remediation.total_vulnerabilities}</Badge>
                <Badge color={C.red}>Critical: {remediation.summary?.critical || 0}</Badge>
                <Badge color={C.amber}>High: {remediation.summary?.high || 0}</Badge>
              </div>

              <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                <select
                  value={scriptFmt}
                  onChange={(e) => setScriptFmt(e.target.value)}
                  style={{ padding: "8px 12px", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, fontFamily: MONO, fontSize: 12 }}
                >
                  <option value="bash">Bash</option>
                  <option value="powershell">PowerShell</option>
                  <option value="ansible">Ansible YAML</option>
                </select>

                <button
                  onClick={() => downloadText(`qc_remediation_${remediation.plan_id}.${scriptFmt === "powershell" ? "ps1" : scriptFmt === "ansible" ? "yml" : "sh"}`, remediationToScript(remediation, scriptFmt))}
                  style={{ padding: "8px 16px", background: C.green, color: "#fff", border: "none", borderRadius: 6, fontSize: 12, fontWeight: 700, cursor: "pointer" }}
                >
                  Export Script
                </button>

                <button
                  onClick={async () => {
                    try {
                      const content = remediationToScript(remediation, scriptFmt);
                      await navigator.clipboard.writeText(content);
                    } catch (e) {
                      setError("Clipboard unavailable. Use Export Script instead.");
                    }
                  }}
                  style={{ padding: "8px 16px", background: C.surface, color: C.text, border: `1px solid ${C.border}`, borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: "pointer" }}
                >
                  Copy
                </button>
              </div>

              <div style={{ display: "grid", gap: 6 }}>
                {(remediation.priority_actions || []).slice(0, 10).map((a) => (
                  <div key={a.vuln_id} style={{ padding: "8px 10px", background: C.surface, borderRadius: 6 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "center" }}>
                      <div style={{ fontSize: 11, color: C.text }}>
                        <span style={{ color: C.textDim, fontFamily: MONO }}>P{a.priority}</span>{" "}
                        {a.title}
                      </div>
                      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                        <Badge color={a.severity === "CRITICAL" ? C.red : a.severity === "HIGH" ? C.amber : C.textDim}>{a.severity}</Badge>
                        <Badge color={C.textDim}>{a.cve_id || a.vuln_id}</Badge>
                      </div>
                    </div>
                    {!!a.affected_asset && (
                      <div style={{ marginTop: 4, fontSize: 10, color: C.textDim }}>
                        Asset: <span style={{ fontFamily: MONO }}>{a.affected_asset}</span>
                      </div>
                    )}
                    {!!a.remediation && (
                      <div style={{ marginTop: 4, fontSize: 10, color: C.textDim }}>
                        Fix: {a.remediation}
                      </div>
                    )}
                  </div>
                ))}
              </div>

              <div style={{ fontSize: 10, color: C.textDim }}>
                Exported scripts are guidance scaffolds—review before applying.
              </div>
            </div>
          )}
        </Panel>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <Panel title="CVE Knowledge Base" icon="📚" accent={C.amber}>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {[
              { cve: "CVE-2024-3400", title: "PAN-OS Command Injection", cvss: 10.0, status: "weaponized" },
              { cve: "CVE-2024-1709", title: "ScreenConnect Auth Bypass", cvss: 10.0, status: "weaponized" },
              { cve: "CVE-2024-21887", title: "Ivanti Connect Secure", cvss: 9.1, status: "weaponized" },
              { cve: "CVE-2024-23897", title: "Jenkins Arbitrary File Read", cvss: 9.8, status: "functional" },
              { cve: "CVE-2023-44228", title: "Log4Shell", cvss: 10.0, status: "weaponized" },
            ].map((v) => (
              <div key={v.cve} style={{ padding: "8px 10px", background: C.surface, borderRadius: 6, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div>
                  <span style={{ fontSize: 11, fontFamily: MONO, color: C.red, marginRight: 8 }}>{v.cve}</span>
                  <span style={{ fontSize: 11, color: C.text }}>{v.title}</span>
                </div>
                <div style={{ display: "flex", gap: 6 }}>
                  <Badge color={v.cvss >= 9 ? C.red : C.amber}>CVSS {v.cvss}</Badge>
                  <Badge color={v.status === "weaponized" ? C.red : C.amber}>{v.status}</Badge>
                </div>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Compliance Frameworks" icon="✓" accent={C.green}>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {["CIS Benchmarks", "NIST SP 800-53", "NIST CSF", "DISA STIG", "PCI DSS", "HIPAA", "SOC 2"].map((fw) => (
              <div key={fw} style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 12, color: C.text }}>{fw}</span>
                <Badge color={C.green}>LOADED</Badge>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}



// ─── DEVOPS TAB ────────────────────────────────────────────────────────────

const DEVOPS_WORKFLOWS = [
  { id: "bootstrap", label: "Bootstrap K8s", icon: "⎈", color: C.accent, desc: "Provision cluster, ingress, cert-manager, ArgoCD" },
  { id: "protect", label: "Protect Branches", icon: "🛡", color: C.green, desc: "Apply branch protection rules with auto-discover" },
  { id: "dns", label: "DNS Sanity Check", icon: "🌐", color: C.cyan, desc: "Verify DNS propagation and record sanity" },
  { id: "deploy", label: "Deploy to VM", icon: "🚀", color: C.purple, desc: "Docker compose deploy with TLS and monitoring" },
  { id: "promote", label: "Promote to Prod", icon: "📦", color: C.amber, desc: "Promote staging to production via PR" },
  { id: "helm", label: "Release Helm Chart", icon: "⚓", color: C.magenta, desc: "Package and publish Helm chart" },
];

// ─── QC OS v4.2.1 — API Layer (shared by all QC tabs) ────────────────────

const QC_API = "https://queencalifia-cyberai.onrender.com";
const qcH = (ak,apiKey) => { const h = {"Content-Type":"application/json"}; if (apiKey) h["X-QC-API-Key"]=apiKey; if (ak) h["X-QC-Admin-Key"]=ak; return h; };
const qcGet = async (p,ak,apiKey) => { const r=await fetch(`${QC_API}${p}`,{headers:qcH(ak,apiKey)}); const d=await r.json().catch(()=>({})); if(!r.ok) throw new Error(d.error||`HTTP ${r.status}`); return d; };
const qcPost = async (p,b,ak,apiKey) => { const r=await fetch(`${QC_API}${p}`,{method:"POST",headers:qcH(ak,apiKey),body:JSON.stringify(b||{})}); const d=await r.json().catch(()=>({})); if(!r.ok) throw new Error(d.error||`HTTP ${r.status}`); return d; };

const QC_MODES = {cyber:{label:"Cyber Guardian",color:C.green},research:{label:"Research Companion",color:C.amber},lab:{label:"Quant Lab",color:C.purple}};
const SAMPLE_HOLDINGS = [
  {symbol:"BTC-USD",asset_type:"crypto",units:0.25,latest_price:65000},
  {symbol:"ETH-USD",asset_type:"crypto",units:2,latest_price:3500},
  {symbol:"AAPL",asset_type:"stock",units:10,latest_price:220},
];
const SAMPLE_QUANT = {risk_aversion:0.5,candidates:[
  {symbol:"BTC-USD",expected_return:0.18,risk:0.32},
  {symbol:"ETH-USD",expected_return:0.15,risk:0.28},
  {symbol:"AAPL",expected_return:0.08,risk:0.14},
]};
const FORECAST_TYPES = ["regime_detection","telemetry_forecast","scenario","signal_ensemble","risk_budget"];

// ─── QC CONSOLE TAB (Queen Califia conversational brain) ─────────────────

function QCConsoleTab() {
  const [mode,setMode] = useState("cyber");
  const [messages,setMsgs] = useState([]);
  const [input,setInput] = useState("");
  const [busy,setBusy] = useState(false);
  const [err,setErr] = useState("");
  const [memories,setMems] = useState([]);
  const [config,setConfig] = useState(null);
  const [sessionId] = useState(()=>"ses-"+Math.random().toString(36).slice(2,10));
  const [userId] = useState(()=>"usr-"+Math.random().toString(36).slice(2,10));
  const streamRef = useRef(null);

  useEffect(()=>{
    (async()=>{
      try{
        const c=await qcGet("/api/config");
        setConfig(c);
        setMsgs([{id:"w",role:"assistant",text:c.welcome_message}]);
      }catch(e){setErr(e.message);setMsgs([{id:"e",role:"assistant",text:"Backend unreachable. Render may be cold-starting — retry in 30s."}]);}
    })();
  },[]);

  useEffect(()=>{streamRef.current?.scrollTo({top:streamRef.current.scrollHeight,behavior:"smooth"});},[messages]);

  const send = async()=>{
    const t=input.trim();if(!t||busy)return;
    setErr("");setBusy(true);
    setMsgs(m=>[...m,{id:"u-"+Date.now(),role:"user",text:t}]);setInput("");
    try{
      const d=await qcPost("/api/chat/",{message:t,session_id:sessionId,user_id:userId,mode});
      if(d.memories_added?.length) setMems(p=>[...d.memories_added,...p].slice(0,12));
      setMsgs(m=>[...m,{id:"a-"+Date.now(),role:"assistant",text:d.reply}]);
    }catch(e){setErr(e.message);setMsgs(m=>[...m,{id:"e-"+Date.now(),role:"assistant",text:`Error: ${e.message}`}]);}
    finally{setBusy(false);}
  };

  const modeInfo = QC_MODES[mode];
  const qcAvatarState = mode === "cyber" ? "active" : mode === "research" ? "ascended" : "energy_spiral";

  return (
    <div style={{display:"grid",gap:16}}>
      {/* Mode Switcher */}
      <Panel
        title="Queen Califia — Conversational Intelligence"
        icon="💬"
        accent={modeInfo.color}
        glow
        headerRight={
          <QueenCalifiaAvatar
            state={qcAvatarState}
            size={120}
            showLabel={false}
            showStatus={false}
            style={{ transform: "scale(0.62)", transformOrigin: "right center" }}
          />
        }
      >
        <div style={{display:"flex",gap:6,marginBottom:12}}>
          {Object.entries(QC_MODES).map(([k,v])=>(
            <button key={k} onClick={()=>setMode(k)} style={{
              padding:"8px 16px",borderRadius:6,border:`1px solid ${mode===k?v.color+"50":C.border}`,
              background:mode===k?`${v.color}12`:"transparent",color:mode===k?v.color:C.textSoft,
              fontSize:11,fontWeight:600,cursor:"pointer",fontFamily:FONT,
            }}>{v.label}</button>
          ))}
          <div style={{marginLeft:"auto",display:"flex",alignItems:"center",gap:6}}>
            <PulseDot color={busy?C.amber:C.green} size={6}/>
            <span style={{fontSize:10,fontFamily:MONO,color:busy?C.amber:C.green}}>{busy?"Thinking…":"Ready"}</span>
          </div>
        </div>

        {/* Chat stream */}
        <div ref={streamRef} style={{maxHeight:360,overflowY:"auto",display:"flex",flexDirection:"column",gap:8,marginBottom:12,padding:"8px 0"}}>
          {messages.map(msg=>(
            <div key={msg.id} style={{
              maxWidth:"85%",padding:"10px 14px",borderRadius:8,
              alignSelf:msg.role==="user"?"flex-end":"flex-start",
              background:msg.role==="user"?`${C.accent}15`:C.surface,
              border:`1px solid ${msg.role==="user"?C.accent+"20":C.border}`,
            }}>
              <div style={{fontSize:9,color:C.textDim,textTransform:"uppercase",letterSpacing:0.8,marginBottom:4,fontFamily:MONO}}>
                {msg.role==="assistant"?(config?.name||"Queen Califia"):"You"}
              </div>
              <div style={{fontSize:12,color:C.text,lineHeight:1.6,whiteSpace:"pre-wrap"}}>{msg.text}</div>
            </div>
          ))}
          {busy&&<div style={{alignSelf:"flex-start",padding:"10px 14px",background:C.surface,borderRadius:8,border:`1px solid ${C.border}`}}>
            <span style={{fontSize:12,color:C.textDim,animation:"qcPulse 1.2s ease-in-out infinite"}}>● ● ●</span>
          </div>}
        </div>

        {/* Input */}
        <div style={{display:"flex",gap:8}}>
          <textarea value={input} onChange={e=>setInput(e.target.value)}
            onKeyDown={e=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();send();}}}
            placeholder={mode==="cyber"?"Ask about threats, vulnerabilities, architecture…":mode==="research"?"Query market data, economic indicators…":"Design experiments, run scenarios…"}
            rows={2} disabled={busy}
            style={{flex:1,padding:"10px 12px",background:C.surface,border:`1px solid ${C.border}`,borderRadius:6,color:C.text,fontFamily:FONT,fontSize:12,resize:"none",outline:"none",lineHeight:1.5}}
          />
          <button onClick={send} disabled={busy||!input.trim()} style={{
            width:42,height:42,borderRadius:8,border:"none",
            background:busy||!input.trim()?C.textDim:`linear-gradient(135deg,${modeInfo.color},${C.accent})`,
            color:"#fff",fontSize:16,fontWeight:700,cursor:busy?"wait":"pointer",
            display:"flex",alignItems:"center",justifyContent:"center",
          }}>→</button>
        </div>
        {err&&<div style={{marginTop:6,fontSize:10,color:C.red,fontFamily:MONO}}>{err}</div>}
      </Panel>

      {/* Memory sidebar */}
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
        <Panel title="Active Memories" icon="🧠" accent={C.purple}>
          {memories.length===0?<span style={{fontSize:11,color:C.textDim}}>No memories yet. Tell QC your name, goals, or portfolio.</span>
          :memories.map((m,i)=>(
            <div key={i} style={{display:"flex",gap:8,padding:"4px 0",borderBottom:`1px solid ${C.border}`,fontSize:11}}>
              <span style={{fontFamily:MONO,fontSize:10,color:C.purple,minWidth:60}}>{m.key}</span>
              <span style={{color:C.text}}>{m.value}</span>
            </div>
          ))}
        </Panel>
        <Panel title="Engine Status" icon="⚡" accent={C.green}>
          <div style={{display:"flex",flexDirection:"column",gap:4}}>
            <div style={{display:"flex",justifyContent:"space-between",fontSize:11}}><span style={{color:C.textSoft}}>Backend</span><code style={{fontFamily:MONO,fontSize:10,color:config?C.green:C.red}}>{config?"CONNECTED":"OFFLINE"}</code></div>
            <div style={{display:"flex",justifyContent:"space-between",fontSize:11}}><span style={{color:C.textSoft}}>Mode</span><code style={{fontFamily:MONO,fontSize:10,color:modeInfo.color}}>{modeInfo.label}</code></div>
            <div style={{display:"flex",justifyContent:"space-between",fontSize:11}}><span style={{color:C.textSoft}}>Session</span><code style={{fontFamily:MONO,fontSize:10,color:C.textDim}}>{sessionId.slice(0,12)}</code></div>
            <div style={{display:"flex",justifyContent:"space-between",fontSize:11}}><span style={{color:C.textSoft}}>Persona</span><code style={{fontFamily:MONO,fontSize:10,color:C.textSoft}}>{config?.persona?.slice(0,50)||"—"}</code></div>
            {config?.capabilities&&<div style={{marginTop:4,display:"flex",gap:4,flexWrap:"wrap"}}>
              {config.capabilities.map(c=><Badge key={c} color={C.cyan}>{c}</Badge>)}
            </div>}
          </div>
        </Panel>
      </div>
    </div>
  );
}

// ─── RESEARCH & QUANT TAB (Market Intel + Forecast + Portfolio + Quant) ──

function ResearchLabTab() {
  const [sub,setSub] = useState("market");
  const [err,setErr] = useState("");
  const [busy,setBusy] = useState(false);
  const [adminKey,setAdminKey] = useState("");
  const DEFAULT_MARKET_SYMBOLS = { crypto: "BTC-USD", forex: "USD/EUR", stock: "AAPL", macro: "FEDFUNDS" };

  // Market
  const [assetType,setAssetType] = useState("crypto");
  const [symbol,setSymbol] = useState("BTC-USD");
  const [snapshot,setSnapshot] = useState(null);
  const [sources,setSources] = useState([]);

  // Forecast
  const [fcType,setFcType] = useState("telemetry_forecast");
  const [fcResult,setFcResult] = useState(null);

  // Portfolio
  const [holdingsText,setHoldingsText] = useState(JSON.stringify(SAMPLE_HOLDINGS,null,2));
  const [portfolioResult,setPortfolioResult] = useState(null);

  // Quant
  const [quantText,setQuantText] = useState(JSON.stringify(SAMPLE_QUANT,null,2));
  const [quantResult,setQuantResult] = useState(null);

  useEffect(()=>{(async()=>{try{const d=await qcGet("/api/market/sources");setSources(d.sources||[]);}catch{}})();},[]);
  useEffect(()=>{setSymbol(DEFAULT_MARKET_SYMBOLS[assetType] || "BTC-USD");},[assetType]);

  const loadSnap = async()=>{
    setErr("");setSnapshot(null);setBusy(true);
    try{setSnapshot(await qcGet(`/api/market/snapshot?asset_type=${assetType}&symbol=${symbol}`));}
    catch(e){setErr(e.message);}finally{setBusy(false);}
  };

  const runForecast = async()=>{
    setErr("");setFcResult(null);setBusy(true);
    try{
      const input = fcType==="telemetry_forecast"&&snapshot
        ?{asset_type:snapshot.asset_type,symbol:snapshot.symbol,horizon:"short"}
        :fcType==="risk_budget"?{holdings:{"BTC-USD":16250,"ETH-USD":7000,"AAPL":2200},max_drawdown:0.15}
        :{};
      setFcResult(await qcPost("/api/forecast/run",{user_id:"analyst",run_type:fcType,input}));
    }catch(e){setErr(e.message);}finally{setBusy(false);}
  };

  const analyzePortfolio = async()=>{
    setErr("");setPortfolioResult(null);setBusy(true);
    try{const h=JSON.parse(holdingsText);setPortfolioResult(await qcPost("/api/forecast/portfolio/analyze",{holdings:h}));}
    catch(e){setErr(e.message);}finally{setBusy(false);}
  };

  const runQuant = async()=>{
    setErr("");setQuantResult(null);setBusy(true);
    try{setQuantResult(await qcPost("/api/forecast/quant/run",JSON.parse(quantText),adminKey));}
    catch(e){setErr(e.message);}finally{setBusy(false);}
  };

  const inp = {width:"100%",padding:"8px 10px",background:C.surface,border:`1px solid ${C.border}`,borderRadius:6,color:C.text,fontFamily:MONO,fontSize:11,outline:"none",boxSizing:"border-box"};
  const sbtn = (on,clr=C.accent)=>({padding:"5px 12px",borderRadius:5,border:`1px solid ${on?clr+"50":C.border}`,background:on?`${clr}12`:"transparent",color:on?clr:C.textSoft,fontSize:10,fontWeight:600,cursor:"pointer",fontFamily:FONT});
  const abtn = (clr=C.accent,dis)=>({padding:"6px 14px",borderRadius:6,border:"none",background:dis?C.textDim:clr,color:"#fff",fontSize:11,fontWeight:600,cursor:dis?"not-allowed":"pointer",fontFamily:FONT,opacity:dis?0.4:1});
  const jsonPre = (data)=>(<pre style={{margin:0,padding:"10px 12px",background:C.void,borderRadius:6,border:`1px solid ${C.border}`,fontFamily:MONO,fontSize:10,color:C.textSoft,maxHeight:250,overflow:"auto",whiteSpace:"pre-wrap",wordBreak:"break-word"}}>{JSON.stringify(data,null,2)}</pre>);

  const SUBS = [{id:"market",label:"Market Intel",icon:"🌐"},{id:"forecast",label:"Forecast Lab",icon:"🔬"},{id:"portfolio",label:"Portfolio Lab",icon:"💼"},{id:"quant",label:"Quant Lab",icon:"⚛"}];

  return (
    <div style={{display:"grid",gap:16}}>
      <Panel title="Research & Quant — Live Data Engines" icon="📊" accent={C.amber} glow>
        <div style={{display:"flex",gap:2,flexWrap:"wrap",marginBottom:8}}>
          {SUBS.map(s=>(
            <button key={s.id} onClick={()=>setSub(s.id)} style={{
              padding:"7px 14px",background:sub===s.id?`${C.amber}12`:"transparent",
              border:`1px solid ${sub===s.id?C.amber+"40":"transparent"}`,borderRadius:6,
              color:sub===s.id?C.amber:C.textSoft,fontSize:11,fontWeight:600,cursor:"pointer",
              fontFamily:FONT,display:"flex",alignItems:"center",gap:5,
            }}><span style={{fontSize:12}}>{s.icon}</span>{s.label}</button>
          ))}
          {sub==="quant"&&<div style={{marginLeft:"auto",display:"flex",gap:6,alignItems:"center"}}>
            <span style={{fontSize:10,color:C.textSoft}}>Admin</span>
            <input type="password" value={adminKey} onChange={e=>setAdminKey(e.target.value)} placeholder="X-QC-Admin-Key (optional if QC_NO_AUTH=1)" style={{...inp,width:240}}/>
          </div>}
        </div>
        {err&&<div style={{padding:"6px 10px",borderRadius:6,background:C.redDim,border:`1px solid ${C.red}30`,color:C.red,fontSize:11,fontFamily:MONO}}>{err}</div>}
      </Panel>

      {/* ── Market Intel ── */}
      {sub==="market"&&(
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
          <Panel title="Market Snapshot" icon="🌐" accent={C.cyan}>
            <div style={{display:"flex",gap:6,marginBottom:10,flexWrap:"wrap",alignItems:"center"}}>
              <select value={assetType} onChange={e=>setAssetType(e.target.value)} style={{...inp,width:100,flex:"none"}}>
                <option value="crypto">Crypto</option><option value="forex">Forex</option>
                <option value="stock">Stock</option><option value="macro">Macro</option>
              </select>
              <input value={symbol} onChange={e=>setSymbol(e.target.value.toUpperCase())} placeholder="BTC-USD" style={{...inp,flex:1,minWidth:100}}/>
              <button onClick={loadSnap} disabled={busy} style={abtn(C.cyan,busy)}>Load</button>
            </div>
            {snapshot&&jsonPre(snapshot)}
          </Panel>
          <Panel title="Trusted Sources" icon="🔒" accent={C.green}>
            {sources.length===0?<span style={{fontSize:11,color:C.textDim}}>Loading…</span>
            :sources.map(s=>(
              <div key={s.id} style={{display:"flex",alignItems:"center",gap:8,padding:"5px 0",borderBottom:`1px solid ${C.border}`,fontSize:11}}>
                <PulseDot color={s.enabled?C.green:C.textDim} size={5}/>
                <span style={{flex:1,color:C.text}}>{s.name}</span>
                <span style={{fontFamily:MONO,fontSize:10,color:C.textSoft}}>{(s.confidence_score*100).toFixed(0)}%</span>
              </div>
            ))}
          </Panel>
        </div>
      )}

      {/* ── Forecast Lab ── */}
      {sub==="forecast"&&(
        <Panel title="Forecast Lab" icon="🔬" accent={C.accentBright}>
          <div style={{display:"flex",gap:6,marginBottom:10,flexWrap:"wrap",alignItems:"center"}}>
            <select value={fcType} onChange={e=>setFcType(e.target.value)} style={{...inp,width:200,flex:"none"}}>
              {FORECAST_TYPES.map(t=><option key={t} value={t}>{t.replace(/_/g," ")}</option>)}
            </select>
            <button onClick={runForecast} disabled={busy} style={abtn(C.accentBright,busy)}>Run Forecast</button>
            {!snapshot&&fcType==="telemetry_forecast"&&<span style={{fontSize:10,color:C.amber}}>Load a market snapshot first for telemetry forecast</span>}
          </div>
          <div style={{fontSize:10,color:C.textSoft,marginBottom:8}}>
            Dispatches to regime detection, telemetry forecast, scenario analysis, signal ensemble, or risk budget engine.
          </div>
          {fcResult&&jsonPre(fcResult)}
        </Panel>
      )}

      {/* ── Portfolio Lab ── */}
      {sub==="portfolio"&&(
        <Panel title="Portfolio Lab" icon="💼" accent={C.green}>
          <div style={{fontSize:10,color:C.textSoft,marginBottom:8}}>
            Paste holdings JSON → get PnL, allocation, concentration risk, cost-basis analysis. Uses live cached market prices.
          </div>
          <textarea value={holdingsText} onChange={e=>setHoldingsText(e.target.value)} rows={8}
            style={{...inp,fontFamily:MONO,fontSize:10,resize:"vertical",lineHeight:1.5,marginBottom:8}}/>
          <button onClick={analyzePortfolio} disabled={busy} style={abtn(C.green,busy)}>Analyze Portfolio</button>
          {portfolioResult&&(
            <div style={{marginTop:12}}>
              <div style={{display:"flex",gap:12,flexWrap:"wrap",marginBottom:12}}>
                <Stat label="Portfolio Value" value={`$${portfolioResult.portfolio_value?.toLocaleString()}`} color={C.green} small/>
                <Stat label="Top Holding" value={portfolioResult.top_holding?.symbol||"—"} color={C.amber} small/>
                <Stat label="Conc. Risk" value={portfolioResult.flags?.concentration_risk?"YES":"NO"} color={portfolioResult.flags?.concentration_risk?C.red:C.green} small/>
              </div>
              {portfolioResult.holdings&&(
                <div style={{display:"flex",flexDirection:"column",gap:2}}>
                  {portfolioResult.holdings.map(h=>(
                    <div key={h.symbol} style={{display:"flex",justifyContent:"space-between",padding:"5px 8px",background:C.surface,borderRadius:4,fontSize:11}}>
                      <span style={{color:C.text,fontFamily:MONO}}>{h.symbol}</span>
                      <span style={{color:C.textSoft}}>{h.units} @ ${h.latest_price}</span>
                      <span style={{color:C.textSoft}}>${h.market_value?.toLocaleString()}</span>
                      <span style={{fontFamily:MONO,color:h.weight>=0.35?C.red:C.green}}>{(h.weight*100).toFixed(1)}%</span>
                      {h.pnl!=null&&<span style={{fontFamily:MONO,color:h.pnl>=0?C.green:C.red}}>{h.pnl>=0?"+":""}${h.pnl.toLocaleString()}</span>}
                    </div>
                  ))}
                </div>
              )}
              {portfolioResult.allocation_by_asset_type&&(
                <div style={{marginTop:8,display:"flex",gap:8}}>
                  {Object.entries(portfolioResult.allocation_by_asset_type).map(([k,v])=>(
                    <Badge key={k} color={C.cyan}>{k}: {(v*100).toFixed(1)}%</Badge>
                  ))}
                </div>
              )}
            </div>
          )}
        </Panel>
      )}

      {/* ── Quant Lab ── */}
      {sub==="quant"&&(
        <Panel title="Quant Lab — Admin Research Optimizer" icon="⚛" accent={C.magenta} glow>
          <div style={{fontSize:10,color:C.textSoft,marginBottom:8}}>
            Classical mean-variance fallback or Qiskit QAOA-inspired quantum optimization. Admin key required. Paper trading only.
          </div>
          <textarea value={quantText} onChange={e=>setQuantText(e.target.value)} rows={8}
            style={{...inp,fontFamily:MONO,fontSize:10,resize:"vertical",lineHeight:1.5,marginBottom:8}}/>
          <button onClick={runQuant} disabled={busy} style={abtn(C.magenta,busy)}>Run Optimizer</button>
          {quantResult&&(
            <div style={{marginTop:12}}>
              <div style={{display:"flex",gap:12,flexWrap:"wrap",marginBottom:12}}>
                <Stat label="Engine" value={quantResult.engine_mode||"—"} color={C.cyan} small/>
                <Stat label="Quantum" value={quantResult.quantum_ready?"YES":"NO"} color={quantResult.quantum_ready?C.purple:C.textDim} small/>
                <Stat label="Expected Return" value={`${((quantResult.portfolio_expected_return||0)*100).toFixed(2)}%`} color={C.green} small/>
                <Stat label="Risk Score" value={((quantResult.portfolio_risk_score||0)*100).toFixed(2)+"%"} color={C.amber} small/>
              </div>
              {quantResult.allocation&&(
                <div style={{display:"flex",flexDirection:"column",gap:2}}>
                  {quantResult.allocation.map(a=>(
                    <div key={a.symbol} style={{display:"flex",justifyContent:"space-between",padding:"5px 8px",background:C.surface,borderRadius:4,fontSize:11}}>
                      <span style={{fontFamily:MONO,color:C.text}}>{a.symbol}</span>
                      <span style={{color:C.textSoft}}>ER: {(a.expected_return*100).toFixed(1)}%</span>
                      <span style={{color:C.amber}}>Risk: {(a.risk*100).toFixed(1)}%</span>
                      <ProgressBar value={a.weight*100} max={100} color={C.accentBright} height={4}/>
                      <span style={{fontFamily:MONO,color:C.accentBright,minWidth:50,textAlign:"right"}}>{(a.weight*100).toFixed(1)}%</span>
                    </div>
                  ))}
                </div>
              )}
              <div style={{marginTop:8,fontSize:10,color:C.textDim,fontFamily:MONO}}>{quantResult.note}</div>
            </div>
          )}
        </Panel>
      )}
    </div>
  );
}

// ─── IDENTITY CORE TAB (QC OS v4.2.1 — wired to live backend) ───────────

const ID_LANES = ["personal","cyber","market","persona"];
const ID_QUEUE_TABS = ["proposals","reflections","rules","notes"];
const ID_SEVS = ["info","low","medium","high","critical"];
const ID_SEV_CLR = {info:C.textSoft,low:C.green,medium:C.amber,high:"#ff9100",critical:C.red};
const ID_PROVIDERS = ["local_symbolic_core","ollama","vllm_local","auto"];

const IdBadge = ({children,color=C.accent}) => <Badge color={color}>{children}</Badge>;

function IdentityTab() {
  const [adminKey,setAdminKey] = useState("");
  const [sub,setSub] = useState("state");
  const [err,setErr] = useState("");
  const [busy,setBusy] = useState(false);
  const [ps,setPs] = useState(null); // persona state
  const [qt,setQt] = useState("proposals"); // queue tab
  const [ql,setQl] = useState(""); // queue lane
  const [qi,setQi] = useState([]); // queue items
  const [prov,setProv] = useState(null);
  const [oHealth,setOHealth] = useState(null);
  const [oModels,setOModels] = useState([]);
  const [pullN,setPullN] = useState("");
  const [pullM,setPullM] = useState("");
  const [lr,setLr] = useState(null); // learning result
  const [missions,setMissions] = useState([]);
  const [selM,setSelM] = useState(null);
  const [mName,setMName] = useState("");
  const [mObj,setMObj] = useState("");
  const [fSev,setFSev] = useState("medium");
  const [fSum,setFSum] = useState("");

  const loadPs = useCallback(async()=>{try{setPs(await qcGet("/api/identity/state"));}catch(e){setErr(e.message);}}, []);
  const loadQ = useCallback(async()=>{
    setErr("");setQi([]);
    try {
      const path = qt==="proposals"?`/api/identity/memory/pending${ql?`?lane=${ql}`:""}`
        :qt==="reflections"?"/api/identity/reflections/pending"
        :qt==="rules"?"/api/identity/rules/pending":"/api/identity/self-notes/pending";
      setQi((await qcGet(path)).items||[]);
    } catch(e){setErr(e.message);}
  },[qt,ql]);
  const loadProv = useCallback(async()=>{try{setProv(await qcGet("/api/identity/provider-status"));}catch{}}, []);
  const loadMissions = useCallback(async()=>{try{setMissions((await qcGet("/api/identity/missions")).items||[]);}catch(e){setErr(e.message);}}, []);

  useEffect(()=>{loadPs();loadProv();loadMissions();},[loadPs,loadProv,loadMissions]);
  useEffect(()=>{loadQ();},[loadQ]);

  const actQ = async(action,id)=>{
    setBusy(true);setErr("");
    try{
      const pfx=qt==="proposals"?"/api/identity/memory":qt==="reflections"?"/api/identity/reflections":qt==="rules"?"/api/identity/rules":"/api/identity/self-notes";
      await qcPost(`${pfx}/${id}/${action}`,{},adminKey);await loadQ();await loadPs();
    }catch(e){setErr(e.message);}finally{setBusy(false);}
  };
  const switchProv = async(p)=>{setBusy(true);try{await qcPost("/api/identity/provider-status",{provider:p},adminKey);await loadProv();}catch(e){setErr(e.message);}finally{setBusy(false);}};
  const checkOllama = async()=>{try{const[h,m]=await Promise.all([qcGet("/api/identity/ollama/health"),qcGet("/api/identity/ollama/models")]);setOHealth(h);setOModels(m.models||[]);}catch(e){setErr(e.message);}};
  const doPull = async()=>{if(!pullN.trim())return;setBusy(true);setPullM("Pulling…");try{const d=await qcPost("/api/identity/ollama/pull",{model:pullN.trim()},adminKey);setPullM(d.ok?`✓ ${d.model}`:`✗ ${d.error}`);if(d.ok){setPullN("");checkOllama();}}catch(e){setPullM("");setErr(e.message);}finally{setBusy(false);}};
  const doLearn = async()=>{setBusy(true);setLr(null);try{setLr(await qcPost("/api/identity/learning/cycle/run",{},adminKey)); await loadPs(); await loadQ();}catch(e){setErr(e.message);}finally{setBusy(false);}};
  const createM = async()=>{if(!mName.trim()||!mObj.trim()){setErr("Name & objective required");return;}setBusy(true);try{const d=await qcPost("/api/identity/missions",{name:mName.trim(),objective:mObj.trim()},adminKey);setMName("");setMObj("");await loadMissions();try{setSelM(await qcGet(`/api/identity/missions/${d.id}`));}catch{}}catch(e){setErr(e.message);}finally{setBusy(false);}};
  const loadMD = async(id)=>{try{setSelM(await qcGet(`/api/identity/missions/${id}`));}catch(e){setErr(e.message);}};
  const addFind = async()=>{if(!selM||!fSum.trim())return;setBusy(true);try{await qcPost(`/api/identity/missions/${selM.id}/findings`,{severity:fSev,summary:fSum.trim()},adminKey);setFSum("");await loadMD(selM.id);await loadMissions();}catch(e){setErr(e.message);}finally{setBusy(false);}};
  const genRem = async()=>{if(!selM)return;setBusy(true);try{await qcPost(`/api/identity/missions/${selM.id}/remediation/generate`,{},adminKey);await loadMD(selM.id);}catch(e){setErr(e.message);}finally{setBusy(false);}};
  const appRem = async()=>{if(!selM)return;setBusy(true);try{await qcPost(`/api/identity/missions/${selM.id}/remediation/apply`,{},adminKey);await loadMD(selM.id);await loadMissions();}catch(e){setErr(e.message);}finally{setBusy(false);}};

  const inp = {width:"100%",padding:"8px 10px",background:C.surface,border:`1px solid ${C.border}`,borderRadius:6,color:C.text,fontFamily:MONO,fontSize:11,outline:"none",boxSizing:"border-box"};
  const sbtn = (on,clr=C.accent)=>({padding:"5px 12px",borderRadius:5,border:`1px solid ${on?clr+"50":C.border}`,background:on?`${clr}12`:"transparent",color:on?clr:C.textSoft,fontSize:10,fontWeight:600,cursor:"pointer",fontFamily:FONT});
  const abtn = (clr=C.accent,dis)=>({padding:"6px 14px",borderRadius:6,border:"none",background:dis?C.textDim:clr,color:"#fff",fontSize:11,fontWeight:600,cursor:dis?"not-allowed":"pointer",fontFamily:FONT,opacity:dis?0.4:1});

  const SUBS = [{id:"state",label:"Persona",icon:"♛"},{id:"queue",label:"Approvals",icon:"📋"},{id:"missions",label:"Missions",icon:"🎯"},{id:"model",label:"Models",icon:"⚙"},{id:"learning",label:"Learning",icon:"🧬"}];

  return (
    <div style={{display:"grid",gap:16}}>
      {/* Admin key + sub-nav */}
      <Panel title="Identity Core — QC OS v4.2.1" icon="♛" accent={C.purple} glow>
        <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:12}}>
          <span style={{fontSize:10,color:C.textSoft,whiteSpace:"nowrap"}}>Admin Key</span>
          <input type="password" value={adminKey} onChange={e=>setAdminKey(e.target.value)} placeholder="X-QC-Admin-Key (optional if QC_NO_AUTH=1)" style={{...inp,flex:1,maxWidth:320}} />
          <PulseDot color={adminKey?C.green:C.cyan} size={6}/>
        </div>
        <div style={{display:"flex",gap:2,flexWrap:"wrap"}}>
          {SUBS.map(s=>(
            <button key={s.id} onClick={()=>setSub(s.id)} style={{
              padding:"7px 14px",background:sub===s.id?`${C.purple}12`:"transparent",
              border:`1px solid ${sub===s.id?C.purple+"40":"transparent"}`,borderRadius:6,
              color:sub===s.id?C.purple:C.textSoft,fontSize:11,fontWeight:600,cursor:"pointer",
              fontFamily:FONT,display:"flex",alignItems:"center",gap:5,
            }}><span style={{fontSize:12}}>{s.icon}</span>{s.label}</button>
          ))}
        </div>
        {err&&<div style={{marginTop:8,padding:"6px 10px",borderRadius:6,background:C.redDim,border:`1px solid ${C.red}30`,color:C.red,fontSize:11,fontFamily:MONO}}>{err}</div>}
      </Panel>

      {/* ── Persona State ── */}
      {sub==="state"&&ps&&(
        <Panel title="Persona State" icon="👁" accent={C.purple}>
          <div style={{display:"flex",gap:12,flexWrap:"wrap",marginBottom:12}}>
            <Stat label="Pending" value={ps.pending_items} color={ps.pending_items>0?C.amber:C.green} small/>
            <Stat label="Rules" value={ps.approved_rules_count} color={C.accentBright} small/>
            <Stat label="Notes" value={ps.approved_notes_count} color={C.cyan} small/>
            {ID_LANES.map(l=><Stat key={l} label={l} value={ps.memory_lanes?.[l]??0} color={C.textSoft} small/>)}
          </div>
          <div style={{fontSize:11,color:C.textSoft,lineHeight:1.6,padding:"8px 0",borderTop:`1px solid ${C.border}`}}>{ps.identity_summary}</div>
          {ps.latest_approved_note&&<div style={{marginTop:8,padding:"8px 10px",background:C.surface,borderRadius:6,fontSize:10,color:C.textSoft,fontFamily:MONO,lineHeight:1.5}}><span style={{color:C.purple,fontWeight:600}}>Latest Note: </span>{ps.latest_approved_note.note_text}</div>}
        </Panel>
      )}

      {/* ── Approval Queue ── */}
      {sub==="queue"&&(
        <Panel title="Approval Queue" icon="📋" accent={C.accentBright}>
          <div style={{display:"flex",gap:4,marginBottom:8}}>
            {ID_QUEUE_TABS.map(t=><button key={t} onClick={()=>setQt(t)} style={sbtn(qt===t,C.accentBright)}>{t}</button>)}
          </div>
          {qt==="proposals"&&<div style={{display:"flex",gap:4,marginBottom:8}}>
            <button onClick={()=>setQl("")} style={sbtn(ql==="",C.cyan)}>All</button>
            {ID_LANES.map(l=><button key={l} onClick={()=>setQl(l)} style={sbtn(ql===l,C.cyan)}>{l}</button>)}
          </div>}
          <div style={{display:"flex",flexDirection:"column",gap:6,maxHeight:320,overflowY:"auto"}}>
            {qi.length===0&&<span style={{fontSize:11,color:C.textDim}}>No pending items.</span>}
            {qi.map(it=>(
              <div key={it.id} style={{padding:"10px 12px",background:C.surface,borderRadius:6,border:`1px solid ${C.border}`}}>
                <div style={{display:"flex",alignItems:"center",gap:6,marginBottom:4}}>
                  <span style={{fontFamily:MONO,fontSize:10,color:C.textDim}}>#{it.id}</span>
                  {it.lane&&<IdBadge color={{personal:C.accentBright,cyber:C.green,market:C.amber,persona:C.purple}[it.lane]}>{it.lane}</IdBadge>}
                  {it.kind&&<IdBadge color={C.textSoft}>{it.kind}</IdBadge>}
                  {it.score!=null&&<span style={{marginLeft:"auto",fontFamily:MONO,fontSize:10,color:C.purple}}>{(it.score*100).toFixed(0)}%</span>}
                </div>
                <div style={{fontSize:11,color:C.text,lineHeight:1.5,marginBottom:6}}>{it.content||it.rule_text||it.note_text||""}</div>
                <div style={{display:"flex",gap:6}}>
                  <button disabled={busy} onClick={()=>actQ("approve",it.id)} style={abtn(C.green,busy)}>Approve</button>
                  <button disabled={busy} onClick={()=>actQ("reject",it.id)} style={abtn(C.red,busy)}>Reject</button>
                </div>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* ── Cyber Missions ── */}
      {sub==="missions"&&(
        <div style={{display:"grid",gridTemplateColumns:"260px 1fr",gap:16}}>
          <Panel title="Missions" icon="🎯" accent={C.accent}>
            <div style={{display:"flex",flexDirection:"column",gap:4,marginBottom:8}}>
              <input value={mName} onChange={e=>setMName(e.target.value)} placeholder="Mission name" style={inp}/>
              <input value={mObj} onChange={e=>setMObj(e.target.value)} placeholder="Objective" style={inp}/>
              <button disabled={busy} onClick={createM} style={abtn(C.accent,busy)}>+ Create</button>
            </div>
            <div style={{display:"flex",flexDirection:"column",gap:2,maxHeight:260,overflowY:"auto"}}>
              {missions.length===0&&<span style={{fontSize:11,color:C.textDim}}>No missions.</span>}
              {missions.map(m=>(
                <button key={m.id} onClick={()=>loadMD(m.id)} style={{
                  padding:"7px 8px",background:selM?.id===m.id?`${C.accent}12`:"transparent",
                  border:`1px solid ${selM?.id===m.id?C.accent+"40":"transparent"}`,borderRadius:6,
                  color:C.text,fontSize:11,cursor:"pointer",textAlign:"left",display:"flex",alignItems:"center",gap:6,width:"100%",fontFamily:FONT,
                }}><PulseDot color={m.status==="open"?C.accent:m.status==="in_progress"?C.amber:C.green} size={6}/>
                  <span style={{flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{m.name}</span>
                  <span style={{fontFamily:MONO,fontSize:9,color:C.textDim}}>{m.findings_count}F</span>
                </button>
              ))}
            </div>
          </Panel>
          <Panel title={selM?selM.name:"Select a mission"} icon="📄" accent={C.accent}>
            {!selM?<span style={{fontSize:11,color:C.textDim}}>Select or create a mission.</span>:(
              <div style={{display:"flex",flexDirection:"column",gap:10}}>
                <div style={{display:"flex",alignItems:"center",gap:8}}>
                  <Badge color={selM.status==="open"?C.accent:selM.status==="in_progress"?C.amber:C.green}>{selM.status}</Badge>
                  <span style={{fontSize:11,color:C.textSoft}}>{selM.objective}</span>
                </div>
                <div style={{borderTop:`1px solid ${C.border}`,paddingTop:8}}>
                  <div style={{fontSize:10,color:C.textSoft,letterSpacing:0.8,textTransform:"uppercase",marginBottom:6}}>Findings ({selM.findings?.length||0})</div>
                  {(selM.findings||[]).map(f=>(
                    <div key={f.id} style={{display:"flex",gap:8,padding:"4px 0",fontSize:11}}>
                      <span style={{fontFamily:MONO,fontSize:10,fontWeight:700,color:ID_SEV_CLR[f.severity],minWidth:52,textTransform:"uppercase"}}>{f.severity}</span>
                      <span style={{color:C.text}}>{f.summary}</span>
                    </div>
                  ))}
                  <div style={{display:"flex",gap:6,marginTop:6}}>
                    <select value={fSev} onChange={e=>setFSev(e.target.value)} style={{...inp,width:90,flex:"none"}}>
                      {ID_SEVS.map(s=><option key={s} value={s}>{s}</option>)}
                    </select>
                    <input value={fSum} onChange={e=>setFSum(e.target.value)} placeholder="Finding summary" style={{...inp,flex:1}}/>
                    <button disabled={busy} onClick={addFind} style={abtn(C.accent,busy)}>+ Add</button>
                  </div>
                </div>
                <div style={{borderTop:`1px solid ${C.border}`,paddingTop:8}}>
                  <div style={{fontSize:10,color:C.textSoft,letterSpacing:0.8,textTransform:"uppercase",marginBottom:6}}>Remediation</div>
                  <div style={{display:"flex",gap:6}}>
                    <button disabled={busy||!(selM.findings?.length)} onClick={genRem} style={abtn(C.accent,busy||!(selM.findings?.length))}>Generate Package</button>
                    <button disabled={busy} onClick={appRem} style={abtn(C.green,busy)}>Apply Latest</button>
                  </div>
                  {(selM.remediation_packages||[]).map(pkg=>{
                    let parsed;try{parsed=JSON.parse(pkg.package_json);}catch{parsed=null;}
                    return (<div key={pkg.id} style={{marginTop:8,padding:"8px 10px",background:pkg.applied?C.greenGlow:C.surface,border:`1px solid ${pkg.applied?C.green+"20":C.border}`,borderRadius:6}}>
                      <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}>
                        <span style={{fontFamily:MONO,fontSize:10,color:C.textDim}}>PKG-{pkg.id}</span>
                        <Badge color={pkg.applied?C.green:C.amber}>{pkg.applied?"Applied":"Pending"}</Badge>
                      </div>
                      {parsed?.steps?.map((st,i)=>(<div key={i} style={{display:"flex",gap:6,fontSize:10,padding:"2px 0"}}>
                        <span style={{fontFamily:MONO,fontWeight:700,color:ID_SEV_CLR[st.severity],minWidth:20}}>P{st.priority}</span>
                        <span style={{color:C.text,lineHeight:1.4}}>{st.action}</span>
                      </div>))}
                    </div>);
                  })}
                </div>
              </div>
            )}
          </Panel>
        </div>
      )}

      {/* ── Model Manager ── */}
      {sub==="model"&&(
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
          <Panel title="Provider" icon="⚙" accent={C.cyan}>
            {prov?.current&&<div style={{display:"flex",flexDirection:"column",gap:4,marginBottom:10}}>
              <div style={{display:"flex",justifyContent:"space-between",fontSize:11}}><span style={{color:C.textSoft}}>Active</span><code style={{fontFamily:MONO,fontSize:11,color:C.text}}>{prov.current.provider}</code></div>
              <div style={{display:"flex",justifyContent:"space-between",fontSize:11}}><span style={{color:C.textSoft}}>Ollama</span><PulseDot color={prov.ollama_reachable?C.green:C.textDim} size={6}/></div>
              <div style={{display:"flex",justifyContent:"space-between",fontSize:11}}><span style={{color:C.textSoft}}>vLLM</span><PulseDot color={prov.vllm_reachable?C.green:C.textDim} size={6}/></div>
            </div>}
            <div style={{display:"flex",gap:4,flexWrap:"wrap"}}>
              {ID_PROVIDERS.map(p=><button key={p} disabled={busy||prov?.current?.provider===p} onClick={()=>switchProv(p)} style={sbtn(prov?.current?.provider===p,C.cyan)}>{p.replace(/_/g," ")}</button>)}
            </div>
          </Panel>
          <Panel title="Ollama" icon="🧠" accent={C.cyan}>
            <div style={{display:"flex",gap:6,marginBottom:8}}>
              <button onClick={checkOllama} style={sbtn(false,C.cyan)}>Refresh</button>
              {oHealth&&<Badge color={oHealth.reachable?C.green:C.red}>{oHealth.reachable?"Healthy":oHealth.status}</Badge>}
            </div>
            {oModels.map(m=><div key={m.name} style={{display:"flex",justifyContent:"space-between",padding:"4px 0",borderBottom:`1px solid ${C.border}`}}>
              <span style={{fontFamily:MONO,fontSize:11,color:C.text}}>{m.name}</span>
              <span style={{fontFamily:MONO,fontSize:10,color:C.textDim}}>{m.size?`${(m.size/1e9).toFixed(1)}GB`:"—"}</span>
            </div>)}
            <div style={{display:"flex",gap:6,marginTop:8}}>
              <input value={pullN} onChange={e=>setPullN(e.target.value)} placeholder="e.g. mistral:7b" style={{...inp,flex:1}}/>
              <button disabled={busy||!pullN.trim()} onClick={doPull} style={abtn(C.cyan,busy||!pullN.trim())}>Pull</button>
            </div>
            {pullM&&<span style={{fontSize:10,fontFamily:MONO,color:C.purple,marginTop:4,display:"block"}}>{pullM}</span>}
          </Panel>
        </div>
      )}

      {/* ── Learning Dock ── */}
      {sub==="learning"&&(
        <Panel title="Learning Dock — Biomimetic Cycle" icon="🧬" accent={C.magenta} glow>
          <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:12}}>
            <button disabled={busy} onClick={doLearn} style={abtn(C.magenta,busy)}>{busy?"Running…":"Run Cycle"}</button>
            <span style={{fontSize:10,color:C.textDim}}>Sense → Interpret → Propose</span>
          </div>
          {lr&&(
            <div style={{display:"flex",flexDirection:"column",gap:8}}>
              <div style={{display:"flex",justifyContent:"space-between",fontSize:11}}><span style={{color:C.textSoft}}>Run</span><code style={{fontFamily:MONO,fontSize:11,color:C.text}}>{lr.run_at}</code></div>
              <div style={{fontSize:10,color:C.textSoft,letterSpacing:0.8,textTransform:"uppercase",marginTop:4}}>Sensed</div>
              <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                <Stat label="Turns" value={lr.sensed?.conversation_turns??0} color={C.text} small/>
                <Stat label="Market" value={lr.sensed?.market_snapshots??0} color={C.amber} small/>
                <Stat label="Forecast" value={lr.sensed?.forecast_runs??0} color={C.accentBright} small/>
                <Stat label="Events" value={lr.sensed?.audit_events??0} color={C.cyan} small/>
              </div>
              <div style={{fontSize:10,color:C.textSoft,letterSpacing:0.8,textTransform:"uppercase",marginTop:4}}>Generated</div>
              <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                <Stat label="Proposals" value={lr.generated?.proposals??0} color={C.accentBright} small/>
                <Stat label="Reflect" value={lr.generated?.reflections??0} color={C.purple} small/>
                <Stat label="Rules" value={lr.generated?.rules??0} color={C.cyan} small/>
                <Stat label="Notes" value={lr.generated?.self_notes??0} color={C.magenta} small/>
              </div>
            </div>
          )}
          {!lr&&!err&&<span style={{fontSize:11,color:C.textDim}}>Trigger a cycle to sense, interpret, and propose.</span>}
        </Panel>
      )}
    </div>
  );
}

function DevOpsTab() {
  const [selected, setSelected] = useState(null);
  const [running, setRunning] = useState(null);

  return (
    <div style={{ display: "grid", gap: 16 }}>
      <Panel title="One-Click Operations" icon="⚡" accent={C.accent}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>
          {DEVOPS_WORKFLOWS.map(w => (
            <button
              key={w.id}
              onClick={() => setSelected(selected === w.id ? null : w.id)}
              style={{
                padding: 14, background: selected === w.id ? `${w.color}12` : C.surface,
                border: `1px solid ${selected === w.id ? w.color + "40" : C.border}`,
                borderRadius: 8, cursor: "pointer", textAlign: "left",
                transition: "all 0.2s ease",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                <span style={{ fontSize: 18 }}>{w.icon}</span>
                <span style={{ fontSize: 13, fontWeight: 600, color: C.text }}>{w.label}</span>
              </div>
              <div style={{ fontSize: 10, color: C.textSoft, lineHeight: 1.4 }}>{w.desc}</div>
              {running === w.id && <ProgressBar value={65} color={w.color} height={3} bg={`${w.color}10`} style={{ marginTop: 8 }} />}
            </button>
          ))}
        </div>
      </Panel>

      {selected && (
        <Panel title={`Configure: ${DEVOPS_WORKFLOWS.find(w => w.id === selected)?.label}`} icon="⚙" accent={DEVOPS_WORKFLOWS.find(w => w.id === selected)?.color}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div>
              <label style={{ fontSize: 10, color: C.textSoft, display: "block", marginBottom: 4 }}>Target Environment</label>
              <select style={{ width: "100%", padding: "8px 10px", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, fontFamily: MONO, fontSize: 11 }}>
                <option>staging</option>
                <option>production</option>
              </select>
            </div>
            <div>
              <label style={{ fontSize: 10, color: C.textSoft, display: "block", marginBottom: 4 }}>Branch</label>
              <input defaultValue="main" style={{ width: "100%", padding: "8px 10px", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, fontFamily: MONO, fontSize: 11, boxSizing: "border-box" }} />
            </div>
          </div>
          <div style={{ marginTop: 12, display: "flex", gap: 8 }}>
            <button
              onClick={() => { setRunning(selected); setTimeout(() => setRunning(null), 5000); }}
              disabled={running === selected}
              style={{ padding: "8px 20px", background: running === selected ? C.textDim : C.accent, color: "#fff", border: "none", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: running ? "wait" : "pointer" }}
            >
              {running === selected ? "Running..." : "Execute"}
            </button>
            <button onClick={() => setSelected(null)} style={{ padding: "8px 16px", background: "transparent", color: C.textSoft, border: `1px solid ${C.border}`, borderRadius: 6, fontSize: 12, cursor: "pointer" }}>
              Cancel
            </button>
          </div>
        </Panel>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <Panel title="CI/CD Workflows" icon="🔄" accent={C.green}>
          {["ci.yml", "deploy-vm.yml", "promote-production.yml", "release-helm.yml", "bootstrap-k8s.yml", "protect-branches.yml", "deps-refresh.yml", "weekly-platform-upgrades.yml"].map(wf => (
            <div key={wf} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 0", borderBottom: `1px solid ${C.border}` }}>
              <span style={{ fontSize: 11, fontFamily: MONO, color: C.text }}>{wf}</span>
              <PulseDot color={C.green} size={6} />
            </div>
          ))}
        </Panel>

        <Panel title="Infrastructure" icon="🏗" accent={C.cyan}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
            {[
              { label: "K8s Cluster", status: "Active" },
              { label: "ArgoCD", status: "Synced" },
              { label: "Cert-Manager", status: "Ready" },
              { label: "Ingress", status: "Active" },
              { label: "Redis", status: "Connected" },
              { label: "Prometheus", status: "Scraping" },
              { label: "Grafana", status: "Ready" },
              { label: "OTEL Collector", status: "Active" },
            ].map(s => (
              <div key={s.label} style={{ padding: "6px 8px", background: C.surface, borderRadius: 4, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 10, color: C.textSoft }}>{s.label}</span>
                <span style={{ fontSize: 9, fontFamily: MONO, color: C.green }}>{s.status}</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}

// ─── MAIN DASHBOARD ────────────────────────────────────────────────────────

// ─── GUIDED WIZARD (3-step: target → scan → export) ─────────────────────────

function GuidedWizard({ onExit, onAvatarStateChange }) {
  const [step, setStep] = useState(1); // 1=target, 2=scanning, 3=results
  const [target, setTarget] = useState("192.168.1.0/24");
  const [scanType, setScanType] = useState("full");
  const [apiKey, setApiKey] = useState("");
  const [ack, setAck] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!onAvatarStateChange) return;
    const critical =
      result?.phases?.scan?.critical ??
      result?.critical_count ??
      result?.summary?.critical ??
      0;

    if (scanning) onAvatarStateChange("hex_shield");
    else if (step >= 3 && result) onAvatarStateChange(critical > 0 ? "ascended" : "active");
    else onAvatarStateChange("idle");

    return () => onAvatarStateChange("idle");
  }, [onAvatarStateChange, scanning, step, result]);

  const presets = [
    { label: "Home Network", value: "192.168.1.0/24", desc: "Most home routers" },
    { label: "Office Range", value: "10.0.0.0/24", desc: "Common enterprise" },
    { label: "This Machine", value: "127.0.0.1", desc: "Localhost only" },
    { label: "Custom", value: "", desc: "Enter your target" },
  ];

  const runScan = async () => {
    if (!ack) { setError("You must confirm you are authorized to scan this target."); return; }
    setScanning(true); setError(""); setStep(2); setProgress(0);

    // Simulate progress while waiting for API
    const progressInterval = setInterval(() => {
      setProgress(p => Math.min(p + Math.random() * 8, 92));
    }, 600);

    try {
      const headers = { "Content-Type": "application/json" };
      if (apiKey.trim()) headers["X-QC-API-Key"] = apiKey.trim();

      const res = await fetch(`${QC_API}/api/v1/one-click/scan-and-fix`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          target,
          scan_type: scanType,
          auto_approve: false,
          acknowledge_authorized: true,
        }),
      });
      const text = await res.text();
      let data = null;
      try { data = text ? JSON.parse(text) : null; } catch {
        throw new Error(`Non-JSON scan-and-fix response (${res.status}). Snippet: ${String(text).slice(0, 220)}`);
      }
      if (!res.ok) throw new Error(data?.error || data?.message || `HTTP ${res.status}`);
      clearInterval(progressInterval);
      setProgress(100);
      setResult(data);
      setTimeout(() => setStep(3), 500);
    } catch (e) {
      clearInterval(progressInterval);
      const msg = String(e?.message || e || "");
      setError(msg);
      setStep(1);
    } finally {
      setScanning(false);
    }
  };

  const exportReport = (format) => {
    if (!result) return;
    const content = format === "json"
      ? JSON.stringify(result, null, 2)
      : [
          "# QueenCalifia CyberAI — Scan Report",
          `# Target: ${result.target}`,
          `# Date: ${result.completed_at}`,
          `# Risk: ${result.risk_level}`,
          `# Recommendation: ${result.recommendation}`,
          "",
          `## Scan Summary`,
          `Hosts alive: ${result.phases?.scan?.hosts_alive || 0}`,
          `Total findings: ${result.phases?.scan?.total_findings || 0}`,
          `Critical: ${result.phases?.scan?.critical || 0}`,
          `High: ${result.phases?.scan?.high || 0}`,
          `Overall risk: ${result.phases?.scan?.overall_risk || 0}/10`,
          `Quantum risk: ${result.phases?.scan?.quantum_risk || "N/A"}`,
          "",
          `## Learning`,
          `New baselines: ${result.phases?.learning?.new_baselines || 0}`,
          `Patterns learned: ${result.phases?.learning?.new_patterns || 0}`,
          "",
          `## Remediation`,
          `Actions: ${result.phases?.remediation?.total_actions || 0}`,
          "",
          `## Evolution`,
          `New rules: ${result.phases?.evolution?.new_detection_rules || 0}`,
        ].join("\n");

    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `qc_report_${result.operation_id}.${format === "json" ? "json" : "md"}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 500);
  };

  const stepStyle = (s) => ({
    width: 32, height: 32, borderRadius: "50%",
    display: "flex", alignItems: "center", justifyContent: "center",
    fontSize: 14, fontWeight: 700,
    background: step >= s ? C.accent : C.surface,
    color: step >= s ? "#fff" : C.textDim,
    border: `2px solid ${step >= s ? C.accent : C.border}`,
    transition: "all 0.3s ease",
  });

  const connectorStyle = (s) => ({
    flex: 1, height: 2,
    background: step > s ? C.accent : C.border,
    transition: "all 0.3s ease",
  });

  return (
    <div style={{ minHeight: "100vh", background: C.bg, color: C.text, fontFamily: FONT, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: 24 }}>
      <style>{`
        @keyframes qcPulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
        * { box-sizing: border-box; }
      `}</style>

      {/* Back button */}
      <button onClick={onExit} style={{
        position: "absolute", top: 16, left: 16, padding: "8px 16px",
        background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6,
        color: C.textDim, fontSize: 12, cursor: "pointer", fontFamily: FONT,
      }}>← Dashboard</button>

      <div style={{ width: "100%", maxWidth: 640 }}>
        {/* Logo */}
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <div style={{ fontSize: 40, marginBottom: 8 }}>🛡</div>
          <div style={{ fontSize: 20, fontWeight: 700 }}>QUEEN CALIFIA <span style={{ color: C.accent }}>QUICK SCAN</span></div>
          <div style={{ fontSize: 12, color: C.textDim, marginTop: 4 }}>Scan your network in 3 easy steps</div>
        </div>

        {/* Progress steps */}
        <div style={{ display: "flex", alignItems: "center", gap: 0, marginBottom: 40, padding: "0 40px" }}>
          <div style={stepStyle(1)}>1</div>
          <div style={connectorStyle(1)} />
          <div style={stepStyle(2)}>2</div>
          <div style={connectorStyle(2)} />
          <div style={stepStyle(3)}>3</div>
        </div>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 32, marginTop: -32, padding: "0 20px" }}>
          <span style={{ fontSize: 10, color: step >= 1 ? C.text : C.textDim, fontWeight: 600, width: 80, textAlign: "center" }}>Pick Target</span>
          <span style={{ fontSize: 10, color: step >= 2 ? C.text : C.textDim, fontWeight: 600, width: 80, textAlign: "center" }}>Scan</span>
          <span style={{ fontSize: 10, color: step >= 3 ? C.text : C.textDim, fontWeight: 600, width: 80, textAlign: "center" }}>Results</span>
        </div>

        {/* Step 1: Pick Target */}
        {step === 1 && (
          <div style={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 12, padding: 24 }}>
            <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 16 }}>Step 1: Choose Your Target</div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 16 }}>
              {presets.map(p => (
                <button key={p.label} onClick={() => { if (p.value) setTarget(p.value); }}
                  style={{
                    padding: "12px 14px", background: target === p.value ? `${C.accent}15` : C.surface,
                    border: `1px solid ${target === p.value ? C.accent : C.border}`, borderRadius: 8,
                    cursor: "pointer", textAlign: "left", fontFamily: FONT,
                  }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: C.text }}>{p.label}</div>
                  <div style={{ fontSize: 10, color: C.textDim, fontFamily: MONO, marginTop: 2 }}>{p.value || "you type it"}</div>
                </button>
              ))}
            </div>

            <div style={{ marginBottom: 12 }}>
              <label style={{ fontSize: 11, fontWeight: 600, color: C.textDim, marginBottom: 4, display: "block" }}>Target (IP, CIDR, or hostname)</label>
              <input type="text" value={target} onChange={e => setTarget(e.target.value)}
                style={{ width: "100%", padding: "10px 12px", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, fontFamily: MONO, fontSize: 13, outline: "none" }}
                placeholder="e.g. 192.168.1.0/24" />
            </div>

            <div style={{ marginBottom: 12 }}>
              <label style={{ fontSize: 11, fontWeight: 600, color: C.textDim, marginBottom: 4, display: "block" }}>Scan Mode</label>
              <div style={{ display: "flex", gap: 8 }}>
                {["quick", "full", "stealth"].map(m => (
                  <button key={m} onClick={() => setScanType(m)} style={{
                    flex: 1, padding: "8px", background: scanType === m ? `${C.accent}15` : C.surface,
                    border: `1px solid ${scanType === m ? C.accent : C.border}`, borderRadius: 6,
                    fontSize: 11, fontWeight: 600, cursor: "pointer", color: scanType === m ? C.accent : C.textDim, fontFamily: FONT,
                  }}>{m === "quick" ? "⚡ Quick" : m === "full" ? "🔍 Full" : "🥷 Stealth"}</button>
                ))}
              </div>
            </div>

            <div style={{ marginBottom: 12 }}>
              <label style={{ fontSize: 11, fontWeight: 600, color: C.textDim, marginBottom: 4, display: "block" }}>API Key (optional if running locally)</label>
              <input type="password" value={apiKey} onChange={e => setApiKey(e.target.value)}
                style={{ width: "100%", padding: "10px 12px", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, fontFamily: MONO, fontSize: 12, outline: "none" }}
                placeholder="Leave blank for local development" />
            </div>

            {/* Authorization checkbox */}
            <div style={{ display: "flex", alignItems: "flex-start", gap: 10, padding: 12, background: `${C.amber}08`, border: `1px solid ${C.amber}30`, borderRadius: 8, marginBottom: 16 }}>
              <input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} style={{ marginTop: 2, accentColor: C.accent }} />
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: C.amber }}>⚠ Authorization Required</div>
                <div style={{ fontSize: 11, color: C.textDim, marginTop: 2 }}>
                  I confirm I am authorized to scan this target. Unauthorized scanning is illegal. This tool is for white-hat, contracted security assessments only.
                </div>
              </div>
            </div>

            {error && <div style={{ padding: 10, background: `${C.red}10`, border: `1px solid ${C.red}30`, borderRadius: 6, fontSize: 11, color: C.red, marginBottom: 12 }}>{error}</div>}

            <button onClick={runScan} disabled={!target || !ack} style={{
              width: "100%", padding: "14px", background: !target || !ack ? C.surface : `linear-gradient(135deg, ${C.accent}, ${C.purple})`,
              border: "none", borderRadius: 8, color: "#fff", fontSize: 14, fontWeight: 700,
              cursor: !target || !ack ? "not-allowed" : "pointer", fontFamily: FONT, opacity: !target || !ack ? 0.5 : 1,
            }}>🚀 Start Scan</button>
          </div>
        )}

        {/* Step 2: Scanning */}
        {step === 2 && (
          <div style={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 12, padding: 32, textAlign: "center" }}>
            <div style={{ fontSize: 48, marginBottom: 16, animation: "qcPulse 2s ease-in-out infinite" }}>🔍</div>
            <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 8 }}>Scanning {target}</div>
            <div style={{ fontSize: 12, color: C.textDim, marginBottom: 24 }}>
              Queen Califia is scanning → learning → predicting → planning fixes → evolving
            </div>
            <div style={{ width: "100%", height: 8, background: C.surface, borderRadius: 4, overflow: "hidden", marginBottom: 8 }}>
              <div style={{ height: "100%", width: `${progress}%`, background: `linear-gradient(90deg, ${C.accent}, ${C.purple})`, borderRadius: 4, transition: "width 0.5s ease" }} />
            </div>
            <div style={{ fontSize: 11, fontFamily: MONO, color: C.textDim }}>{progress.toFixed(0)}%</div>
          </div>
        )}

        {/* Step 3: Results */}
        {step === 3 && result && (
          <div style={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 12, padding: 24 }}>
            <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 16, display: "flex", alignItems: "center", gap: 8 }}>
              ✅ Scan Complete
              <span style={{
                padding: "4px 10px", borderRadius: 4, fontSize: 11, fontWeight: 700,
                background: result.risk_level === "CRITICAL" ? `${C.red}20` : result.risk_level === "HIGH" ? `${C.amber}20` : `${C.green}20`,
                color: result.risk_level === "CRITICAL" ? C.red : result.risk_level === "HIGH" ? C.amber : C.green,
              }}>{result.risk_level}</span>
            </div>

            {/* Summary cards */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, marginBottom: 16 }}>
              {[
                { label: "Hosts Found", value: result.phases?.scan?.hosts_alive || 0, color: C.cyan },
                { label: "Findings", value: result.phases?.scan?.total_findings || 0, color: result.phases?.scan?.critical > 0 ? C.red : C.amber },
                { label: "Risk Score", value: `${result.phases?.scan?.overall_risk || 0}/10`, color: (result.phases?.scan?.overall_risk || 0) >= 7 ? C.red : C.green },
              ].map(c => (
                <div key={c.label} style={{ padding: 12, background: C.surface, borderRadius: 8, textAlign: "center" }}>
                  <div style={{ fontSize: 24, fontWeight: 800, color: c.color, fontFamily: MONO }}>{c.value}</div>
                  <div style={{ fontSize: 10, color: C.textDim, marginTop: 2 }}>{c.label}</div>
                </div>
              ))}
            </div>

            {/* Severity breakdown */}
            {(result.phases?.scan?.critical > 0 || result.phases?.scan?.high > 0) && (
              <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
                {result.phases?.scan?.critical > 0 && <Badge color={C.red}>{result.phases.scan.critical} CRITICAL</Badge>}
                {result.phases?.scan?.high > 0 && <Badge color={C.amber}>{result.phases.scan.high} HIGH</Badge>}
              </div>
            )}

            {/* Intelligence gained */}
            <div style={{ padding: 12, background: C.surface, borderRadius: 8, marginBottom: 16 }}>
              <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8 }}>🧠 Intelligence Gained</div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 4, fontSize: 11, color: C.textDim }}>
                <span>Baselines learned: {result.phases?.learning?.new_baselines || 0}</span>
                <span>Patterns recognized: {result.phases?.learning?.new_patterns || 0}</span>
                <span>Rules evolved: {result.phases?.evolution?.new_detection_rules || 0}</span>
                <span>Remediation actions: {result.phases?.remediation?.total_actions || 0}</span>
              </div>
            </div>

            <div style={{ fontSize: 12, fontWeight: 600, color: C.accent, marginBottom: 16 }}>
              💡 {result.recommendation}
            </div>

            {/* Export buttons */}
            <div style={{ display: "flex", gap: 8 }}>
              <button onClick={() => exportReport("md")} style={{
                flex: 1, padding: "12px", background: `${C.green}15`, border: `1px solid ${C.green}50`, borderRadius: 8,
                color: C.green, fontSize: 12, fontWeight: 600, cursor: "pointer", fontFamily: FONT,
              }}>📄 Export Report</button>
              <button onClick={() => exportReport("json")} style={{
                flex: 1, padding: "12px", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8,
                color: C.textDim, fontSize: 12, fontWeight: 600, cursor: "pointer", fontFamily: FONT,
              }}>{ "{}"} Export JSON</button>
              <button onClick={() => { setStep(1); setResult(null); setAck(false); }} style={{
                flex: 1, padding: "12px", background: `${C.purple}15`, border: `1px solid ${C.purple}50`, borderRadius: 8,
                color: C.purple, fontSize: 12, fontWeight: 600, cursor: "pointer", fontFamily: FONT,
              }}>🔄 Scan Again</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function QueenCalifiaCommandDashboard() {
  const [activeTab, setActiveTab] = useState("overview");
  const [tick, setTick] = useState(0);
  const [expertMode, setExpertMode] = useState(() => {
    try { return window.sessionStorage?.getItem?.("qc_expert") === "1"; } catch { return false; }
  });
  const [wizardMode, setWizardMode] = useState(false);
  const [qcAvatarState, setQcAvatarState] = useState("idle");

  const toggleExpert = () => {
    const next = !expertMode;
    setExpertMode(next);
    try { window.sessionStorage?.setItem?.("qc_expert", next ? "1" : "0"); } catch {}
    // If leaving expert mode, switch to a basic tab
    if (!next && ["predictor","telemetry","mesh","qc","research","identity","devops"].includes(activeTab)) setActiveTab("overview");
  };

  // Refresh data every 15s
  useEffect(() => {
    const interval = setInterval(() => setTick(t => t + 1), 15000);
    return () => clearInterval(interval);
  }, []);

  const mesh = useMemo(() => generateMeshStatus(), [tick]);
  const predictions = useMemo(() => generatePredictions(), [tick]);
  const incidents = useMemo(() => generateIncidents(), [tick]);
  const timeSeries = useMemo(() => generateTimeSeriesData(), [tick]);
  const landscape = useMemo(() => generateThreatLandscape(), [tick]);
  const layerActivity = useMemo(() => generateLayerActivity(), [tick]);
  const telemetryData = useMemo(() => generateTelemetryData(), [tick]);

  const critCount = incidents.filter(i => i.severity === "CRITICAL").length;
  const highPreds = predictions.filter(p => p.confidence > 0.7).length;

  const BASIC_TABS = ["overview", "vulns", "incidents"];
  const visibleNav = expertMode ? NAV_ITEMS : NAV_ITEMS.filter(n => BASIC_TABS.includes(n.id));

  // ── Guided Wizard ──────────────────────────────────────────────
  if (wizardMode) return <GuidedWizard onExit={() => setWizardMode(false)} onAvatarStateChange={setQcAvatarState} />;

  return (
    <div style={{
      minHeight: "100vh", background: C.bg, color: C.text, fontFamily: FONT,
      padding: 0, margin: 0,
    }}>
      {/* Global keyframe animations */}
      <style>{`
        @keyframes qcPulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        @keyframes qcPulseRing { 0%, 100% { opacity: 0.4; transform: scale(1); } 50% { opacity: 0; transform: scale(1.8); } }
        @keyframes qcGlow { 0%, 100% { box-shadow: 0 0 8px ${C.accent}20; } 50% { box-shadow: 0 0 16px ${C.accent}30; } }
        @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: ${C.void}; }
        ::-webkit-scrollbar-thumb { background: ${C.borderLit}; border-radius: 3px; }
        * { box-sizing: border-box; }
      `}</style>

      {/* Header */}
      <header style={{
        display: "flex", justifyContent: "space-between", alignItems: "center",
        padding: "12px 24px", borderBottom: `1px solid ${C.border}`,
        background: `linear-gradient(180deg, ${C.panel} 0%, ${C.bg} 100%)`,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <QueenCalifiaAvatar
            state={qcAvatarState}
            size={36}
            showLabel={false}
            showStatus={false}
            style={{ cursor: "default" }}
          />
          <div>
            <div style={{ fontSize: 15, fontWeight: 700, color: C.text, letterSpacing: 0.3 }}>
              QUEEN CALIFIA <span style={{ color: C.accent }}>CYBERAI</span>
            </div>
            <div style={{ fontSize: 9, color: C.textDim, letterSpacing: 1.5, textTransform: "uppercase" }}>
              {expertMode ? "Defense-Grade Cybersecurity Intelligence Platform" : "Network Security Scanner"}
            </div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          {/* Wizard launcher */}
          <button onClick={() => setWizardMode(true)} style={{
            padding: "6px 14px", background: `linear-gradient(135deg, ${C.green}20, ${C.green}08)`,
            border: `1px solid ${C.green}50`, borderRadius: 6, cursor: "pointer",
            fontSize: 11, fontWeight: 600, color: C.green, fontFamily: FONT,
          }}>⚡ Quick Scan</button>

          {/* Expert toggle */}
          <button onClick={toggleExpert} title={expertMode ? "Switch to Simple Mode" : "Switch to Expert Mode"} style={{
            padding: "6px 14px",
            background: expertMode ? `${C.purple}15` : C.surface,
            border: `1px solid ${expertMode ? C.purple + "50" : C.border}`,
            borderRadius: 6, cursor: "pointer",
            fontSize: 11, fontWeight: 600, fontFamily: FONT,
            color: expertMode ? C.purple : C.textDim,
          }}>{expertMode ? "🔬 Expert" : "👤 Simple"}</button>

          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <PulseDot color={critCount > 0 ? C.red : C.green} />
            <span style={{ fontSize: 11, color: critCount > 0 ? C.red : C.green, fontFamily: MONO }}>
              {critCount > 0 ? `${critCount} CRITICAL` : "ALL CLEAR"}
            </span>
          </div>
          {expertMode && highPreds > 0 && (
            <Badge color={C.purple}>🔮 {highPreds} predictions</Badge>
          )}
          <span style={{ fontSize: 10, fontFamily: MONO, color: C.textDim }}>
            {new Date().toLocaleTimeString()}
          </span>
        </div>
      </header>

      {/* Navigation */}
      <nav style={{
        display: "flex", gap: 2, padding: "0 24px",
        borderBottom: `1px solid ${C.border}`, background: C.panel,
      }}>
        {visibleNav.map(item => (
          <button
            key={item.id}
            onClick={() => setActiveTab(item.id)}
            style={{
              padding: "10px 16px", background: "transparent",
              border: "none", borderBottom: `2px solid ${activeTab === item.id ? C.accent : "transparent"}`,
              color: activeTab === item.id ? C.text : C.textSoft,
              fontSize: 11, fontWeight: 600, cursor: "pointer",
              fontFamily: FONT, letterSpacing: 0.3,
              display: "flex", alignItems: "center", gap: 6,
              transition: "all 0.2s ease",
            }}
          >
            <span style={{ fontSize: 13 }}>{item.icon}</span>
            {item.label}
            {item.id === "predictor" && highPreds > 0 && (
              <span style={{ width: 16, height: 16, borderRadius: "50%", background: C.purple, color: "#fff", fontSize: 9, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center" }}>{highPreds}</span>
            )}
            {item.id === "telemetry" && telemetryData.beacons.length > 0 && (
              <span style={{ width: 16, height: 16, borderRadius: "50%", background: C.cyan, color: "#fff", fontSize: 9, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center" }}>{telemetryData.beacons.length}</span>
            )}
            {item.id === "incidents" && critCount > 0 && (
              <span style={{ width: 16, height: 16, borderRadius: "50%", background: C.red, color: "#fff", fontSize: 9, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center" }}>{critCount}</span>
            )}
          </button>
        ))}
      </nav>

      {/* Content */}
      <main style={{ padding: 24 }}>
        {activeTab === "overview" && <OverviewTab mesh={mesh} predictions={predictions} incidents={incidents} timeSeries={timeSeries} landscape={landscape} />}
        {activeTab === "predictor" && expertMode && <PredictorTab predictions={predictions} layerActivity={layerActivity} />}
        {activeTab === "telemetry" && expertMode && <TelemetryTab telemetry={telemetryData} />}
        {activeTab === "mesh" && expertMode && <MeshTab mesh={mesh} />}
        {activeTab === "incidents" && <IncidentsTab incidents={incidents} />}
        {activeTab === "vulns" && <VulnsTab onAvatarStateChange={setQcAvatarState} />}
        {activeTab === "qc" && expertMode && <QCConsoleTab />}
        {activeTab === "research" && expertMode && <ResearchLabTab />}
        {activeTab === "identity" && expertMode && <IdentityTab />}
        {activeTab === "devops" && expertMode && <DevOpsTab />}
      </main>

      {/* Footer */}
      <footer style={{
        padding: "8px 24px", borderTop: `1px solid ${C.border}`,
        display: "flex", justifyContent: "space-between", alignItems: "center",
        background: C.panel,
      }}>
        <div style={{ fontSize: 9, color: C.textDim, fontFamily: MONO }}>
          TAMERIAN MATERIALS / QUEENCALIFIA-CYBERAI v4.2.1 — {expertMode ? "ALL ENGINES ACTIVE" : "SCANNER MODE"}
        </div>
        <div style={{ display: "flex", gap: 12, fontSize: 9, color: C.textDim, fontFamily: MONO }}>
          <span>Mesh: <span style={{ color: C.green }}>ONLINE</span></span>
          {expertMode && <span>Predictor: <span style={{ color: C.purple }}>ACTIVE</span></span>}
          {expertMode && <span>Telemetry: <span style={{ color: C.cyan }}>6 STREAMS</span></span>}
          <span>Nodes: <span style={{ color: C.green }}>{mesh.topology.active_nodes}/{mesh.topology.total_nodes}</span></span>
        </div>
      </footer>
    </div>
  );
}
