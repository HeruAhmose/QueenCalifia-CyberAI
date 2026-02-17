import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { LineChart, Line, AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Cell, PieChart, Pie } from "recharts";

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

function VulnsTab() {
  const [scanning, setScanning] = useState(false);
  const scanTarget = useRef("192.168.1.0/24");

  return (
    <div style={{ display: "grid", gap: 16 }}>
      <Panel title="Vulnerability Scanner" icon="🔍" accent={C.accent}>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <input
            defaultValue={scanTarget.current}
            onChange={e => { scanTarget.current = e.target.value; }}
            placeholder="Target IP/CIDR..."
            style={{ flex: 1, padding: "8px 12px", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, fontFamily: MONO, fontSize: 12, outline: "none" }}
          />
          <select style={{ padding: "8px 12px", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, fontFamily: MONO, fontSize: 12 }}>
            <option>Full Scan</option>
            <option>Quick Scan</option>
            <option>Compliance</option>
            <option>Web App</option>
          </select>
          <button
            onClick={() => { setScanning(true); setTimeout(() => setScanning(false), 3000); }}
            disabled={scanning}
            style={{ padding: "8px 20px", background: scanning ? C.textDim : C.accent, color: "#fff", border: "none", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: scanning ? "wait" : "pointer", whiteSpace: "nowrap" }}
          >
            {scanning ? "Scanning..." : "Launch Scan"}
          </button>
        </div>
        <div style={{ marginTop: 8, fontSize: 10, color: C.textDim }}>
          Target policy: Private networks only (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Public targets denied by default.
        </div>
      </Panel>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <Panel title="CVE Knowledge Base" icon="📚" accent={C.amber}>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {[
              { cve: "CVE-2024-3400", title: "PAN-OS Command Injection", cvss: 10.0, status: "weaponized" },
              { cve: "CVE-2024-1709", title: "ScreenConnect Auth Bypass", cvss: 10.0, status: "weaponized" },
              { cve: "CVE-2024-21887", title: "Ivanti Connect Secure", cvss: 9.1, status: "weaponized" },
              { cve: "CVE-2024-23897", title: "Jenkins Arbitrary File Read", cvss: 9.8, status: "functional" },
              { cve: "CVE-2023-44228", title: "Log4Shell", cvss: 10.0, status: "weaponized" },
            ].map(v => (
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
            {["CIS Benchmarks", "NIST SP 800-53", "NIST CSF", "DISA STIG", "PCI DSS", "HIPAA", "SOC 2"].map(fw => (
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

export default function QueenCalifiaCommandDashboard() {
  const [activeTab, setActiveTab] = useState("overview");
  const [tick, setTick] = useState(0);

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
          <div style={{
            width: 36, height: 36, borderRadius: 8,
            background: `linear-gradient(135deg, ${C.accent} 0%, ${C.purple} 100%)`,
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 18, fontWeight: 800, color: "#fff",
            boxShadow: `0 0 20px ${C.accent}30`,
          }}>Q</div>
          <div>
            <div style={{ fontSize: 15, fontWeight: 700, color: C.text, letterSpacing: 0.3 }}>
              QUEEN CALIFIA <span style={{ color: C.accent }}>CYBERAI</span>
            </div>
            <div style={{ fontSize: 9, color: C.textDim, letterSpacing: 1.5, textTransform: "uppercase" }}>
              Defense-Grade Cybersecurity Intelligence Platform
            </div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <PulseDot color={critCount > 0 ? C.red : C.green} />
            <span style={{ fontSize: 11, color: critCount > 0 ? C.red : C.green, fontFamily: MONO }}>
              {critCount > 0 ? `${critCount} CRITICAL` : "ALL CLEAR"}
            </span>
          </div>
          {highPreds > 0 && (
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
        {NAV_ITEMS.map(item => (
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
        {activeTab === "predictor" && <PredictorTab predictions={predictions} layerActivity={layerActivity} />}
        {activeTab === "telemetry" && <TelemetryTab telemetry={telemetryData} />}
        {activeTab === "mesh" && <MeshTab mesh={mesh} />}
        {activeTab === "incidents" && <IncidentsTab incidents={incidents} />}
        {activeTab === "vulns" && <VulnsTab />}
        {activeTab === "devops" && <DevOpsTab />}
      </main>

      {/* Footer */}
      <footer style={{
        padding: "8px 24px", borderTop: `1px solid ${C.border}`,
        display: "flex", justifyContent: "space-between", alignItems: "center",
        background: C.panel,
      }}>
        <div style={{ fontSize: 9, color: C.textDim, fontFamily: MONO }}>
          TAMERIAN MATERIALS / QUEENCALIFIA-CYBERAI v3.1 — ZERO-DAY PREDICTION + ADVANCED TELEMETRY ACTIVE
        </div>
        <div style={{ display: "flex", gap: 12, fontSize: 9, color: C.textDim, fontFamily: MONO }}>
          <span>Mesh: <span style={{ color: C.green }}>ONLINE</span></span>
          <span>Predictor: <span style={{ color: C.purple }}>ACTIVE</span></span>
          <span>Telemetry: <span style={{ color: C.cyan }}>6 STREAMS</span></span>
          <span>Nodes: <span style={{ color: C.green }}>{mesh.topology.active_nodes}/{mesh.topology.total_nodes}</span></span>
        </div>
      </footer>
    </div>
  );
}
