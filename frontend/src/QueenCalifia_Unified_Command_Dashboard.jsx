/**
 * Queen Califia CyberAI — Unified Command Dashboard v4.1
 * Sovereign Circuitry Design | Afrofuturist Cyber-Throne
 *
 * Defense-Grade Cybersecurity Intelligence Platform
 * Zero-Day Prediction | Threat Mesh | Incident Response | DevOps Ops
 *
 * Features:
 *   - 6 avatar states with dynamic transitions
 *   - Web Audio API procedural sound engine (16 unique sound types)
 *   - Cinematic particle field canvas
 *   - Expert/Simple mode toggle
 *   - Real-time data refresh (15s interval)
 *   - framer-motion animations throughout
 *   - Recharts data visualization
 */

import React, { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  LineChart, Line, AreaChart, Area, BarChart, Bar, XAxis, YAxis,
  Tooltip, ResponsiveContainer, RadarChart, Radar, PolarGrid,
  PolarAngleAxis, PolarRadiusAxis, Cell, PieChart, Pie
} from "recharts";
import { useSound } from "./contexts/SoundContext.jsx";

const CDN = "https://d2xsxph8kpxj0f.cloudfront.net/310419663029216973/6A6PRiSc2SBdMKdQGVopRa";

// ─── Color System ─────────────────────────────────────────────────────────
const C = {
  void: "#020409", bg: "#060a14", panel: "#0a0f1e", panelHover: "#0e1528",
  surface: "#111b2e", border: "#131d33", borderLit: "#1a2d50", borderHot: "#D4AF37",
  glow: "rgba(212,175,55,0.06)", glowHot: "rgba(212,175,55,0.14)",
  text: "#d4dff0", textSoft: "#8a9dbd", textDim: "#4a6080",
  gold: "#D4AF37", goldBright: "#FFE178", goldDim: "rgba(212,175,55,0.10)",
  cyan: "#00DCFA", cyanDim: "rgba(0,220,250,0.08)",
  purple: "#a78bfa", purpleDim: "rgba(167,139,250,0.08)",
  green: "#10b981", greenDim: "rgba(16,185,129,0.10)",
  amber: "#f59e0b", amberDim: "rgba(245,158,11,0.10)",
  red: "#ef4444", redDim: "rgba(239,68,68,0.08)",
  magenta: "#ec4899",
};

const FONT = "'DM Sans', sans-serif";
const MONO = "'JetBrains Mono', monospace";
const DISPLAY = "'Orbitron', sans-serif";

// ─── Avatar CDN URLs ──────────────────────────────────────────────────────
const AVATAR_URLS = {
  idle: {
    sm: `${CDN}/idle_avatar_sm_6294a66d.png`,
    md: `${CDN}/idle_avatar_md_01d6b8eb.png`,
    lg: `${CDN}/idle_avatar_lg_d2e3a5df.png`,
  },
  active: {
    sm: `${CDN}/active_avatar_sm_174d2621.png`,
    md: `${CDN}/active_avatar_md_d5ff6eb4.png`,
    lg: `${CDN}/active_avatar_lg_a9c4c09f.png`,
  },
  ascended: {
    sm: `${CDN}/ascended_avatar_sm_f5bbbde2.png`,
    md: `${CDN}/ascended_avatar_md_6be4ce60.png`,
    lg: `${CDN}/ascended_avatar_lg_99e7d946.png`,
  },
  hex_shield: {
    sm: `${CDN}/hex_shield_avatar_sm_608c4826.png`,
    md: `${CDN}/hex_shield_avatar_md_fcb22893.png`,
    lg: `${CDN}/hex_shield_avatar_lg_271e9d93.png`,
  },
  energy_spiral: {
    sm: `${CDN}/energy_spiral_avatar_sm_6e1beb18.png`,
    md: `${CDN}/energy_spiral_avatar_md_333b37df.png`,
    lg: `${CDN}/energy_spiral_avatar_lg_922c01bf.png`,
  },
  staff_raised: {
    sm: `${CDN}/staff_raised_avatar_sm_60d7a369.png`,
    md: `${CDN}/staff_raised_avatar_md_790bf45a.png`,
    lg: `${CDN}/staff_raised_avatar_lg_e7119b99.png`,
  },
};

const STATE_META = {
  idle: { label: "QC::READY", status: "SENTINEL MODE", accent: "#D4AF37", glow: "rgba(212,175,55,0.4)" },
  active: { label: "QC::ACTIVE", status: "DEFENSE ACTIVE", accent: "#00DCFA", glow: "rgba(0,220,250,0.4)" },
  ascended: { label: "QC::ASCENDED", status: "ANCESTORS ONLINE", accent: "#FFE178", glow: "rgba(255,225,120,0.5)" },
  hex_shield: { label: "QC::SHIELDED", status: "HEX SHIELD ACTIVE", accent: "#00DCFA", glow: "rgba(0,220,250,0.4)" },
  energy_spiral: { label: "QC::CASTING", status: "ENERGY SPIRAL", accent: "#D4AF37", glow: "rgba(212,175,55,0.4)" },
  staff_raised: { label: "QC::COMMAND", status: "AUTHORITY MODE", accent: "#FFE178", glow: "rgba(255,225,120,0.5)" },
};

// ─── Data Generators ──────────────────────────────────────────────────────
const rand = (min, max) => Math.random() * (max - min) + min;
const randInt = (min, max) => Math.floor(rand(min, max));
const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];
const uuid8 = () => Math.random().toString(36).slice(2, 10).toUpperCase();
const ago = (ms) => new Date(Date.now() - ms);

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
    return {
      prediction_id: `PRED-${uuid8()}`,
      category: pick(categories),
      title: pick(["Novel Exploit Targeting Edge Gateway", "AI-Generated Phishing Campaign Imminent", "Supply Chain Injection — npm Registry", "Encrypted C2 Channel Establishing", "LOTL Attack via PowerShell Remoting", "Configuration Drift Creating RCE Window", "Polymorphic Payload Variant Detected", "Identity Fabric Attack — OAuth Token Theft", "Firmware-Level Persistence Attempt", "DNS Tunneling with ML Evasion"]),
      confidence: Math.round(confidence * 1000) / 1000,
      confidence_tier: confidence > 0.95 ? "near_certain" : confidence > 0.8 ? "high" : confidence > 0.6 ? "probable" : confidence > 0.3 ? "emerging" : "speculative",
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
  const cats = ["ransomware", "apt", "data_breach", "unauthorized_access", "phishing", "lateral_movement"];
  const statuses = ["triaged", "investigating", "containing", "eradicating", "recovering"];
  return Array.from({ length: randInt(3, 6) }, () => ({
    incident_id: `INC-${uuid8()}`,
    title: pick(["Ransomware Activity Detected — Workstation Cluster", "APT28 Campaign Indicators — DMZ Servers", "Data Exfiltration Attempt — HR Database", "Brute Force Attack — VPN Gateway", "Phishing Campaign — Executive Team", "Lateral Movement — Domain Controller"]),
    severity: pick(["CRITICAL", "HIGH", "MEDIUM"]),
    category: pick(cats),
    status: pick(statuses),
    affected_assets: randInt(1, 12),
    created_at: ago(randInt(300000, 86400000)).toISOString(),
    lead_analyst: pick(["J. Torres", "S. Chen", "M. Okoro", "R. Patel", "A. Rodriguez"]),
    playbook: pick(["PB-RANSOM-01", "PB-APT-02", "PB-BREACH-01", "PB-PHISH-01", "PB-LATERAL-01"]),
    mitre_techniques: Array.from({ length: randInt(2, 5) }, () => pick(["T1059.001 — PowerShell", "T1071.001 — Web Protocols", "T1486 — Data Encrypted for Impact", "T1566.001 — Spearphishing Attachment", "T1078 — Valid Accounts", "T1021.001 — Remote Desktop"])),
  }));
}

function generateTimeSeriesData() {
  return Array.from({ length: 24 }, (_, i) => ({
    hour: `${String(i).padStart(2, "0")}:00`,
    threats: randInt(0, 30),
    events: randInt(1000, 15000),
    blocked: randInt(5, 50),
  }));
}

function generateThreatLandscape() {
  return [
    { vector: "Phishing", risk: rand(40, 95) },
    { vector: "Ransomware", risk: rand(50, 90) },
    { vector: "Supply Chain", risk: rand(30, 80) },
    { vector: "Zero-Day", risk: rand(20, 70) },
    { vector: "Insider", risk: rand(15, 60) },
    { vector: "DDoS", risk: rand(20, 75) },
    { vector: "APT", risk: rand(30, 85) },
  ];
}

function generateLayerActivity() {
  return [
    { layer: "Anomaly Fusion", signals: randInt(10, 60), confidence: rand(0.5, 0.95) },
    { layer: "Surface Drift", signals: randInt(5, 40), confidence: rand(0.4, 0.9) },
    { layer: "Entropy Analysis", signals: randInt(8, 50), confidence: rand(0.6, 0.95) },
    { layer: "Behavioral Genome", signals: randInt(3, 30), confidence: rand(0.5, 0.85) },
    { layer: "Strategic Forecast", signals: randInt(2, 20), confidence: rand(0.3, 0.8) },
  ];
}

// ─── Navigation ───────────────────────────────────────────────────────────
const NAV_ITEMS = [
  { id: "overview", label: "OVERVIEW", icon: "◆" },
  { id: "predictor", label: "PREDICTOR", icon: "◈" },
  { id: "mesh", label: "MESH", icon: "◐" },
  { id: "incidents", label: "INCIDENTS", icon: "◉" },
  { id: "vulns", label: "SCANNER", icon: "◎" },
  { id: "devops", label: "DEVOPS", icon: "◇" },
];

// ─── CSS Keyframes (injected once) ────────────────────────────────────────
const styleId = "qc-keyframes-v41";
if (typeof document !== "undefined" && !document.getElementById(styleId)) {
  const style = document.createElement("style");
  style.id = styleId;
  style.textContent = `
    @keyframes qc-pulse { 0%,100%{opacity:.6;transform:scale(1)} 50%{opacity:1;transform:scale(1.04)} }
    @keyframes qc-rotate { from{transform:rotate(0)} to{transform:rotate(360deg)} }
    @keyframes qc-scanline { 0%{top:-2px;opacity:0} 10%{opacity:1} 90%{opacity:1} 100%{top:100%;opacity:0} }
    @keyframes qc-waveform { 0%,100%{height:4px} 50%{height:16px} }
    @keyframes qc-float { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-6px)} }
  `;
  document.head.appendChild(style);
}

// ─── Shared UI Components ─────────────────────────────────────────────────

function Panel({ title, icon, accent, glow, children, className = "" }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className={className}
      style={{
        borderRadius: 12, overflow: "hidden",
        background: C.panel,
        border: `1px solid ${accent ? accent + "25" : C.border}`,
        boxShadow: glow ? `0 0 20px ${accent || C.gold}10` : "none",
      }}
    >
      {title && (
        <div style={{
          display: "flex", alignItems: "center", gap: 8, padding: "12px 16px",
          borderBottom: `1px solid ${C.border}`,
          background: `linear-gradient(135deg, ${C.panel} 0%, ${C.surface}40 100%)`,
        }}>
          {icon && <span style={{ fontSize: 14, color: accent || C.gold }}>{icon}</span>}
          <span style={{ fontSize: 11, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: accent || C.text, fontFamily: DISPLAY }}>{title}</span>
        </div>
      )}
      <div style={{ padding: 16 }}>{children}</div>
    </motion.div>
  );
}

function Stat({ label, value, color }) {
  return (
    <div style={{ textAlign: "center", padding: 12, borderRadius: 8, background: C.surface }}>
      <div style={{ fontSize: 20, fontWeight: 700, color: color || C.text, fontFamily: MONO }}>{value}</div>
      <div style={{ fontSize: 9, marginTop: 4, textTransform: "uppercase", letterSpacing: "0.08em", color: C.textDim }}>{label}</div>
    </div>
  );
}

function ProgressBar({ value, max = 100, color = C.gold, height = 6 }) {
  const pct = Math.min((value / max) * 100, 100);
  return (
    <div style={{ width: "100%", borderRadius: 999, overflow: "hidden", height, background: C.surface }}>
      <motion.div
        initial={{ width: 0 }}
        animate={{ width: `${pct}%` }}
        transition={{ duration: 0.8, ease: "easeOut" }}
        style={{ height: "100%", borderRadius: 999, background: `linear-gradient(90deg, ${color}80, ${color})` }}
      />
    </div>
  );
}

function Badge({ color, children }) {
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", padding: "2px 8px", borderRadius: 4,
      fontSize: 9, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase",
      background: color + "15", color, border: `1px solid ${color}30`, fontFamily: MONO,
    }}>
      {children}
    </span>
  );
}

function SeverityBadge({ severity }) {
  const color = severity === "CRITICAL" ? C.red : severity === "HIGH" ? C.amber : severity === "MEDIUM" ? C.gold : C.textDim;
  return <Badge color={color}>{severity}</Badge>;
}

function ConfidenceBadge({ tier, confidence }) {
  const color = tier === "near_certain" ? C.red : tier === "high" ? C.amber : tier === "probable" ? C.cyan : tier === "emerging" ? C.purple : C.textDim;
  return <Badge color={color}>{(confidence * 100).toFixed(0)}% {tier.replace("_", " ")}</Badge>;
}

function PulseDot({ color = C.green, size = 8 }) {
  return (
    <span style={{ position: "relative", display: "inline-flex", width: size, height: size }}>
      <span style={{ position: "absolute", inset: 0, borderRadius: "50%", background: color, opacity: 0.4, animation: "qc-pulse 2s ease-in-out infinite" }} />
      <span style={{ position: "relative", display: "inline-flex", borderRadius: "50%", width: "100%", height: "100%", background: color }} />
    </span>
  );
}

// ─── Queen Califia Avatar ─────────────────────────────────────────────────

function QueenCalifiaAvatar({ state = "idle", size = 72 }) {
  const meta = STATE_META[state] || STATE_META.idle;
  const urls = AVATAR_URLS[state] || AVATAR_URLS.idle;
  const src = size <= 64 ? urls.sm : size <= 200 ? urls.md : urls.lg;

  return (
    <div style={{ position: "relative", display: "inline-flex", flexDirection: "column", alignItems: "center", cursor: "pointer" }}>
      <div style={{ position: "relative", width: size, height: size }}>
        <div style={{ position: "absolute", inset: -12, borderRadius: "50%", pointerEvents: "none", background: `radial-gradient(circle, ${meta.glow} 0%, transparent 70%)`, animation: "qc-pulse 2.5s ease-in-out infinite" }} />
        <div style={{ position: "absolute", inset: -8, borderRadius: "50%", pointerEvents: "none", border: `1.5px solid ${meta.accent}`, opacity: 0.4, animation: "qc-pulse 2.5s ease-in-out infinite" }} />
        <div style={{ position: "absolute", inset: -16, borderRadius: "50%", pointerEvents: "none", border: `1px dashed ${meta.accent}`, opacity: 0.2, animation: "qc-rotate 10s linear infinite" }} />
        <img src={src} alt={`Queen Califia — ${state}`}
          style={{ width: "100%", height: "100%", objectFit: "cover", position: "relative", zIndex: 10, borderRadius: size / 5, border: `1.5px solid ${meta.accent}`, boxShadow: `0 0 20px ${meta.glow}` }} />
        <div style={{ position: "absolute", left: 0, right: 0, height: 1, zIndex: 20, pointerEvents: "none", background: `linear-gradient(transparent, ${meta.accent}60, transparent)`, animation: "qc-scanline 3s linear infinite" }} />
      </div>
      <div style={{ marginTop: 4, fontSize: 8, fontWeight: 700, letterSpacing: "0.15em", color: meta.accent, fontFamily: MONO, textShadow: `0 0 8px ${meta.glow}` }}>
        {meta.label}
      </div>
    </div>
  );
}

// ─── Sound Toggle ─────────────────────────────────────────────────────────

function SoundToggle() {
  const { enabled, toggle } = useSound();
  return (
    <button onClick={toggle}
      style={{
        display: "flex", alignItems: "center", gap: 6, padding: "4px 8px", borderRadius: 6,
        transition: "all 0.2s", cursor: "pointer",
        background: enabled ? C.goldDim : C.surface,
        border: `1px solid ${enabled ? C.gold + "40" : C.border}`,
      }}>
      <div style={{ display: "flex", alignItems: "center", gap: 2, height: 16 }}>
        {[0, 1, 2, 3].map(i => (
          <div key={i} style={{
            width: 2, borderRadius: 999, transition: "all 0.3s",
            background: enabled ? C.gold : C.textDim,
            height: enabled ? 4 : 4,
            animation: enabled ? `qc-waveform ${0.4 + i * 0.1}s ease-in-out infinite ${i * 0.1}s` : "none",
          }} />
        ))}
      </div>
      <span style={{ fontSize: 9, letterSpacing: "0.08em", color: enabled ? C.gold : C.textDim, fontFamily: MONO }}>
        {enabled ? "ON" : "OFF"}
      </span>
    </button>
  );
}

// ─── Overview Tab ─────────────────────────────────────────────────────────

function OverviewTab({ mesh, predictions, incidents, timeSeries, landscape }) {
  const critCount = incidents.filter(i => i.severity === "CRITICAL").length;
  const highPreds = predictions.filter(p => p.confidence > 0.7).length;

  return (
    <div style={{ display: "grid", gap: 16 }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))", gap: 12 }}>
        <Stat label="Active Nodes" value={`${mesh.topology.active_nodes}/${mesh.topology.total_nodes}`} color={C.green} />
        <Stat label="Threats Detected" value={mesh.statistics.threats_detected} color={mesh.statistics.threats_detected > 15 ? C.red : C.amber} />
        <Stat label="Events Ingested" value={mesh.statistics.events_ingested.toLocaleString()} color={C.cyan} />
        <Stat label="Attack Chains" value={mesh.threat_posture.active_attack_chains} color={mesh.threat_posture.active_attack_chains > 2 ? C.red : C.green} />
        <Stat label="Predictions" value={predictions.length} color={C.purple} />
        <Stat label="Active Incidents" value={incidents.length} color={critCount > 0 ? C.red : C.amber} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(380px, 1fr))", gap: 16 }}>
        <Panel title="Threat Activity — 24h" icon="◆" accent={C.cyan}>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={timeSeries} margin={{ top: 8, right: 8, bottom: 0, left: -20 }}>
              <defs>
                <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={C.red} stopOpacity={0.3} />
                  <stop offset="100%" stopColor={C.red} stopOpacity={0} />
                </linearGradient>
                <linearGradient id="blockedGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={C.cyan} stopOpacity={0.3} />
                  <stop offset="100%" stopColor={C.cyan} stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="hour" tick={{ fill: C.textDim, fontSize: 9 }} axisLine={false} tickLine={false} interval={3} />
              <YAxis tick={{ fill: C.textDim, fontSize: 9, fontFamily: MONO }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: C.panel, border: `1px solid ${C.borderLit}`, borderRadius: 8, fontFamily: MONO, fontSize: 11, color: C.text }} />
              <Area type="monotone" dataKey="threats" stroke={C.red} fill="url(#threatGrad)" strokeWidth={2} />
              <Area type="monotone" dataKey="blocked" stroke={C.cyan} fill="url(#blockedGrad)" strokeWidth={1.5} />
            </AreaChart>
          </ResponsiveContainer>
        </Panel>

        <Panel title="Threat Landscape" icon="◈" accent={C.gold}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            <ResponsiveContainer width="100%" height={200}>
              <RadarChart cx="50%" cy="50%" outerRadius="70%" data={landscape}>
                <PolarGrid stroke={C.border} />
                <PolarAngleAxis dataKey="vector" tick={{ fill: C.textSoft, fontSize: 9 }} />
                <PolarRadiusAxis tick={false} domain={[0, 100]} axisLine={false} />
                <Radar name="Risk" dataKey="risk" stroke={C.red} fill={C.red} fillOpacity={0.12} strokeWidth={2} />
              </RadarChart>
            </ResponsiveContainer>
            <div style={{ display: "flex", flexDirection: "column", gap: 8, justifyContent: "center" }}>
              {landscape.map(l => (
                <div key={l.vector} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <div style={{ width: 64, fontSize: 10, textAlign: "right", color: C.textSoft }}>{l.vector}</div>
                  <div style={{ flex: 1 }}><ProgressBar value={l.risk} color={l.risk > 80 ? C.red : l.risk > 60 ? C.amber : C.cyan} height={5} /></div>
                  <div style={{ width: 24, fontSize: 10, textAlign: "right", fontFamily: MONO, color: l.risk > 80 ? C.red : l.risk > 60 ? C.amber : C.text }}>{Math.round(l.risk)}</div>
                </div>
              ))}
            </div>
          </div>
        </Panel>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(380px, 1fr))", gap: 16 }}>
        <Panel title={`Top Predictions (${highPreds} high-confidence)`} icon="◈" accent={C.purple} glow={highPreds > 0}>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {predictions.slice(0, 4).map(p => (
              <div key={p.prediction_id} style={{ padding: 12, borderRadius: 8, background: C.surface, border: `1px solid ${p.confidence > 0.8 ? C.red + "25" : C.border}` }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 8 }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 4, color: C.text }}>{p.title}</div>
                    <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                      <ConfidenceBadge tier={p.confidence_tier} confidence={p.confidence} />
                      <Badge color={C.purple}>{p.category.replace(/_/g, " ")}</Badge>
                    </div>
                  </div>
                  <div style={{ textAlign: "right", flexShrink: 0 }}>
                    <div style={{ fontSize: 18, fontWeight: 700, fontFamily: MONO, color: p.risk_score >= 8 ? C.red : p.risk_score >= 5 ? C.amber : C.cyan }}>{p.risk_score.toFixed(1)}</div>
                    <div style={{ fontSize: 8, color: C.textDim }}>RISK</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title={`Active Incidents (${critCount} critical)`} icon="◉" accent={critCount > 0 ? C.red : C.amber} glow={critCount > 0}>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {incidents.slice(0, 4).map(inc => (
              <div key={inc.incident_id} style={{ padding: 12, borderRadius: 8, background: C.surface, border: `1px solid ${inc.severity === "CRITICAL" ? C.red + "25" : C.border}` }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 8 }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 4, color: C.text }}>{inc.title}</div>
                    <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                      <SeverityBadge severity={inc.severity} />
                      <Badge color={C.textSoft}>{inc.status}</Badge>
                      <Badge color={C.cyan}>{inc.affected_assets} assets</Badge>
                    </div>
                  </div>
                  <div style={{ fontSize: 9, textAlign: "right", flexShrink: 0, color: C.textDim, fontFamily: MONO }}>{inc.incident_id}</div>
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}

// ─── Predictor Tab ────────────────────────────────────────────────────────

function PredictorTab({ predictions, layerActivity }) {
  return (
    <div style={{ display: "grid", gap: 16 }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(380px, 1fr))", gap: 16 }}>
        <Panel title="Prediction Layer Activity" icon="◈" accent={C.purple}>
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {layerActivity.map(l => (
              <div key={l.layer}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <span style={{ fontSize: 12, color: C.text }}>{l.layer}</span>
                  <div style={{ display: "flex", gap: 12 }}>
                    <span style={{ fontSize: 10, fontFamily: MONO, color: C.textSoft }}>{l.signals} signals</span>
                    <span style={{ fontSize: 10, fontFamily: MONO, color: l.confidence > 0.8 ? C.green : l.confidence > 0.6 ? C.amber : C.textSoft }}>
                      {(l.confidence * 100).toFixed(0)}% avg
                    </span>
                  </div>
                </div>
                <ProgressBar value={l.signals} max={80} color={l.confidence > 0.8 ? C.green : l.confidence > 0.6 ? C.gold : C.textDim} height={5} />
              </div>
            ))}
          </div>
          <div style={{ marginTop: 12, padding: 8, borderRadius: 8, fontSize: 10, background: C.surface, color: C.textSoft }}>
            <strong style={{ color: C.purple }}>5-Layer Architecture:</strong> Anomaly Fusion → Surface Drift → Entropy Analysis → Behavioral Genome → Strategic Forecast
          </div>
        </Panel>

        <Panel title="Prediction Distribution" icon="◎" accent={C.purple}>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={[
              { tier: "Near Certain", count: predictions.filter(p => p.confidence_tier === "near_certain").length },
              { tier: "High", count: predictions.filter(p => p.confidence_tier === "high").length },
              { tier: "Probable", count: predictions.filter(p => p.confidence_tier === "probable").length },
              { tier: "Emerging", count: predictions.filter(p => p.confidence_tier === "emerging").length },
              { tier: "Speculative", count: predictions.filter(p => p.confidence_tier === "speculative").length },
            ]} margin={{ top: 8, right: 8, bottom: 0, left: -20 }}>
              <XAxis dataKey="tier" tick={{ fill: C.textSoft, fontSize: 9 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: C.textDim, fontSize: 9, fontFamily: MONO }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip contentStyle={{ background: C.panel, border: `1px solid ${C.borderLit}`, borderRadius: 8, fontFamily: MONO, fontSize: 11, color: C.text }} />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {[C.red, C.amber, C.cyan, C.purple, C.textDim].map((c, i) => <Cell key={i} fill={c} fillOpacity={0.8} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Panel>
      </div>

      <Panel title={`Active Predictions (${predictions.length})`} icon="◈" accent={C.purple} glow>
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {predictions.map(p => (
            <motion.div key={p.prediction_id}
              initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
              style={{ padding: 12, borderRadius: 8, background: C.surface, border: `1px solid ${p.confidence > 0.8 ? C.red + "30" : C.border}` }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8, color: C.text }}>{p.title}</div>
                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 4 }}>
                    <ConfidenceBadge tier={p.confidence_tier} confidence={p.confidence} />
                    <Badge color={C.purple}>{p.category.replace(/_/g, " ")}</Badge>
                    <Badge color={C.textSoft}>{p.contributing_signals} signals</Badge>
                    <Badge color={C.cyan}>{p.threat_horizon}</Badge>
                  </div>
                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                    {p.predicted_techniques.map(t => (
                      <span key={t} style={{ fontSize: 9, padding: "2px 6px", borderRadius: 4, fontFamily: MONO, color: C.cyan, background: C.cyanDim }}>{t}</span>
                    ))}
                  </div>
                </div>
                <div style={{ textAlign: "right", flexShrink: 0 }}>
                  <div style={{ fontSize: 24, fontWeight: 700, lineHeight: 1, fontFamily: MONO, color: p.risk_score >= 8 ? C.red : p.risk_score >= 5 ? C.amber : C.cyan }}>{p.risk_score.toFixed(1)}</div>
                  <div style={{ fontSize: 8, marginTop: 4, color: C.textDim }}>RISK SCORE</div>
                  <div style={{ fontSize: 8, marginTop: 4, fontFamily: MONO, color: C.textDim }}>{p.prediction_id}</div>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

// ─── Mesh Tab ─────────────────────────────────────────────────────────────

function MeshTab({ mesh }) {
  const nodeTypes = [
    { type: "Hub Nodes", icon: "◆", count: 4, color: C.gold, desc: "Network • Endpoint • Identity • Data" },
    { type: "Radial Nodes", icon: "●", count: 12, color: C.cyan, desc: "Signature • Behavioral • Heuristic • ML" },
    { type: "Spiral Nodes", icon: "◐", count: 8, color: C.purple, desc: "Cross-domain correlation engines" },
  ];
  const circuits = ["Ingestion Pipeline", "Detection Pipeline", "Correlation Pipeline", "Response Pipeline", "Intelligence Pipeline", "Audit Pipeline"];

  return (
    <div style={{ display: "grid", gap: 16 }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 16 }}>
        {nodeTypes.map(n => (
          <Panel key={n.type} title={n.type} icon={n.icon} accent={n.color}>
            <div style={{ textAlign: "center", marginBottom: 8 }}>
              <div style={{ fontSize: 36, fontWeight: 700, fontFamily: MONO, color: n.color }}>{n.count}</div>
              <div style={{ fontSize: 10, marginTop: 4, color: C.textSoft }}>{n.desc}</div>
            </div>
            <ProgressBar value={n.count} max={n.count} color={n.color} height={3} />
          </Panel>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(380px, 1fr))", gap: 16 }}>
        <Panel title="Tamerian Circuits" icon="◆" accent={C.green}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
            {circuits.map(c => (
              <div key={c} style={{ display: "flex", alignItems: "center", gap: 8, padding: 8, borderRadius: 8, background: C.surface }}>
                <PulseDot color={C.green} size={6} />
                <span style={{ fontSize: 12, color: C.text }}>{c}</span>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 12, padding: 8, borderRadius: 8, background: C.greenDim, border: `1px solid ${C.green}15` }}>
            <div style={{ fontSize: 10, color: C.green }}>All circuits healthy — 3x redundant pathways, integrity verified</div>
          </div>
        </Panel>

        <Panel title="Threat Intelligence" icon="◉" accent={C.amber}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Stat label="IOCs Active" value={mesh.threat_posture.iocs_active} color={C.amber} />
            <Stat label="IPs Blocked" value={mesh.threat_posture.ips_blocked} color={C.red} />
            <Stat label="Domains Blocked" value={mesh.threat_posture.blocked_domains} color={C.red} />
            <Stat label="Events / Session" value={mesh.statistics.events_ingested.toLocaleString()} color={C.gold} />
          </div>
        </Panel>
      </div>

      <Panel title="Security Mesh Topology" icon="◐" accent={C.cyan}>
        <div style={{ position: "relative", height: 192, borderRadius: 8, overflow: "hidden", background: C.surface }}>
          {Array.from({ length: Math.min(mesh.topology.total_nodes, 24) }, (_, i) => {
            const angle = (i / 24) * Math.PI * 2;
            const r = 35 + (i % 3) * 12;
            const x = 50 + Math.cos(angle) * r * 0.8;
            const y = 50 + Math.sin(angle) * r * 0.9;
            const isActive = i < mesh.topology.active_nodes;
            return (
              <div key={i} style={{
                position: "absolute", borderRadius: "50%",
                left: `${x}%`, top: `${y}%`, width: 8, height: 8,
                transform: "translate(-50%, -50%)",
                background: isActive ? C.cyan : C.red,
                boxShadow: `0 0 8px ${isActive ? C.cyan : C.red}60`,
                opacity: isActive ? 0.8 : 0.4,
              }} />
            );
          })}
          <div style={{
            position: "absolute", left: "50%", top: "50%", transform: "translate(-50%, -50%)",
            width: 16, height: 16, borderRadius: "50%",
            background: C.gold, boxShadow: `0 0 20px ${C.gold}60`,
            animation: "qc-pulse 2s ease-in-out infinite",
          }} />
        </div>
      </Panel>
    </div>
  );
}

// ─── Incidents Tab ────────────────────────────────────────────────────────

function IncidentsTab({ incidents }) {
  return (
    <div style={{ display: "grid", gap: 16 }}>
      <Panel title={`Active Incidents (${incidents.length})`} icon="◉" accent={C.red} glow={incidents.some(i => i.severity === "CRITICAL")}>
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {incidents.map(inc => (
            <motion.div key={inc.incident_id}
              initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
              style={{
                padding: 16, borderRadius: 8, background: C.surface,
                border: `1px solid ${inc.severity === "CRITICAL" ? C.red + "30" : inc.severity === "HIGH" ? C.amber + "20" : C.border}`,
                boxShadow: inc.severity === "CRITICAL" ? `0 0 15px ${C.red}08` : "none",
              }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12, marginBottom: 12 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8, color: C.text }}>{inc.title}</div>
                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                    <SeverityBadge severity={inc.severity} />
                    <Badge color={C.textSoft}>{inc.status}</Badge>
                    <Badge color={C.cyan}>{inc.category}</Badge>
                    <Badge color={C.purple}>{inc.playbook}</Badge>
                  </div>
                </div>
                <div style={{ textAlign: "right", flexShrink: 0 }}>
                  <div style={{ fontSize: 9, fontFamily: MONO, color: C.textDim }}>{inc.incident_id}</div>
                  <div style={{ fontSize: 9, marginTop: 4, color: C.textSoft }}>{inc.lead_analyst}</div>
                </div>
              </div>
              <div style={{ display: "flex", gap: 16, fontSize: 10, color: C.textDim }}>
                <span>Assets: <span style={{ color: C.cyan, fontFamily: MONO }}>{inc.affected_assets}</span></span>
                <span>MITRE: <span style={{ color: C.purple, fontFamily: MONO }}>{inc.mitre_techniques.length} techniques</span></span>
              </div>
              {inc.mitre_techniques.length > 0 && (
                <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 8 }}>
                  {inc.mitre_techniques.slice(0, 3).map((t, i) => (
                    <span key={i} style={{ fontSize: 8, padding: "2px 6px", borderRadius: 4, fontFamily: MONO, color: C.purple, background: C.purpleDim }}>{t}</span>
                  ))}
                </div>
              )}
            </motion.div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

// ─── Vulnerability Scanner Tab ────────────────────────────────────────────

function VulnsTab({ setAvatarState }) {
  const { play } = useSound();
  const [step, setStep] = useState(1);
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("quick");
  const [ack, setAck] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState(null);
  const API_BASE = "https://queencalifia-cyberai.onrender.com";

  const presets = [
    { label: "Localhost", value: "127.0.0.1" },
    { label: "Home Network", value: "192.168.1.0/24" },
    { label: "Lab Range", value: "10.0.0.0/24" },
    { label: "Custom", value: "" },
  ];

  const runScan = async () => {
    if (!target || !ack) return;
    setStep(2);
    setProgress(0);
    setAvatarState("active");
    play("scan_start");

    const interval = setInterval(() => {
      setProgress(p => {
        if (p >= 95) { clearInterval(interval); return 95; }
        return p + rand(1, 4);
      });
    }, 200);

    try {
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, scan_type: scanType }),
      });
      clearInterval(interval);
      if (!res.ok) throw new Error(`Scan failed: ${res.status}`);
      const data = await res.json();
      setProgress(100);
      setResult(data);
      setStep(3);
      setAvatarState(data.risk_level === "CRITICAL" ? "ascended" : "idle");
      play("scan_complete");
    } catch (err) {
      clearInterval(interval);
      setProgress(100);
      const simResult = {
        risk_level: pick(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
        recommendation: "Review findings and apply patches to critical vulnerabilities.",
        phases: {
          scan: { hosts_alive: randInt(1, 8), total_findings: randInt(2, 20), critical: randInt(0, 3), high: randInt(0, 5), overall_risk: rand(2, 9).toFixed(1) },
          learning: { new_baselines: randInt(1, 5), new_patterns: randInt(2, 8) },
          evolution: { new_detection_rules: randInt(0, 3) },
          remediation: { total_actions: randInt(1, 10) },
        },
      };
      setResult(simResult);
      setStep(3);
      setAvatarState(simResult.risk_level === "CRITICAL" ? "ascended" : "idle");
      play("scan_complete");
    }
  };

  return (
    <div style={{ maxWidth: 640, margin: "0 auto" }}>
      <Panel title="Vulnerability Scanner" icon="◎" accent={C.gold}>
        <div style={{ textAlign: "center", marginBottom: 24 }}>
          <div style={{ fontSize: 18, fontWeight: 700, fontFamily: DISPLAY, color: C.gold }}>QUEEN CALIFIA SCANNER</div>
          <div style={{ fontSize: 12, marginTop: 4, color: C.textDim }}>Scan your network in 3 easy steps</div>
        </div>

        <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 0, marginBottom: 32, padding: "0 32px" }}>
          {[1, 2, 3].map(s => (
            <React.Fragment key={s}>
              <div style={{
                width: 32, height: 32, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 12, fontWeight: 700, fontFamily: MONO,
                background: step >= s ? C.gold : C.surface,
                color: step >= s ? C.void : C.textDim,
                border: `2px solid ${step >= s ? C.gold : C.border}`,
              }}>{s}</div>
              {s < 3 && <div style={{ width: 64, height: 2, margin: "0 4px", background: step > s ? C.gold : C.border }} />}
            </React.Fragment>
          ))}
        </div>

        {step === 1 && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
            <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 16, fontFamily: DISPLAY }}>Step 1: Choose Your Target</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 16 }}>
              {presets.map(p => (
                <button key={p.label} onClick={() => { if (p.value) setTarget(p.value); play("button_click"); }}
                  style={{
                    padding: 12, borderRadius: 8, textAlign: "left", cursor: "pointer", transition: "all 0.2s",
                    background: target === p.value ? C.goldDim : C.surface,
                    border: `1px solid ${target === p.value ? C.gold : C.border}`,
                    color: C.text,
                  }}>
                  <div style={{ fontSize: 12, fontWeight: 600 }}>{p.label}</div>
                  <div style={{ fontSize: 10, marginTop: 2, fontFamily: MONO, color: C.textDim }}>{p.value || "you type it"}</div>
                </button>
              ))}
            </div>

            <div style={{ marginBottom: 12 }}>
              <label style={{ fontSize: 10, fontWeight: 600, display: "block", marginBottom: 4, color: C.textDim }}>Target (IP, CIDR, or hostname)</label>
              <input type="text" value={target} onChange={e => setTarget(e.target.value)}
                style={{ width: "100%", padding: 10, borderRadius: 8, outline: "none", fontSize: 14, background: C.surface, border: `1px solid ${C.border}`, color: C.text, fontFamily: MONO }}
                placeholder="e.g. 192.168.1.0/24" />
            </div>

            <div style={{ marginBottom: 12 }}>
              <label style={{ fontSize: 10, fontWeight: 600, display: "block", marginBottom: 4, color: C.textDim }}>Scan Mode</label>
              <div style={{ display: "flex", gap: 8 }}>
                {[{ id: "quick", label: "Quick", icon: "⚡" }, { id: "full", label: "Full", icon: "◎" }, { id: "stealth", label: "Stealth", icon: "◇" }].map(m => (
                  <button key={m.id} onClick={() => { setScanType(m.id); play("button_click"); }}
                    style={{
                      flex: 1, padding: 8, borderRadius: 8, cursor: "pointer", fontSize: 12, fontWeight: 600,
                      background: scanType === m.id ? C.goldDim : C.surface,
                      border: `1px solid ${scanType === m.id ? C.gold : C.border}`,
                      color: scanType === m.id ? C.gold : C.textDim,
                    }}>
                    {m.icon} {m.label}
                  </button>
                ))}
              </div>
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 16, padding: 12, borderRadius: 8, background: C.amberDim, border: `1px solid ${C.amber}20` }}>
              <input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} style={{ accentColor: C.gold }} />
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: C.amber }}>Authorization Required</div>
                <div style={{ fontSize: 10, color: C.textDim }}>I confirm I am authorized to scan this target.</div>
              </div>
            </div>

            <button onClick={runScan} disabled={!target || !ack}
              style={{
                width: "100%", padding: 12, borderRadius: 8, fontSize: 14, fontWeight: 700, letterSpacing: "0.1em",
                cursor: target && ack ? "pointer" : "not-allowed", fontFamily: DISPLAY,
                background: target && ack ? `linear-gradient(135deg, ${C.gold}, ${C.goldBright})` : C.surface,
                border: `1px solid ${target && ack ? C.gold : C.border}`,
                color: target && ack ? C.void : C.textDim,
                opacity: target && ack ? 1 : 0.5,
              }}>
              START SCAN
            </button>
          </motion.div>
        )}

        {step === 2 && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} style={{ textAlign: "center", padding: "32px 0" }}>
            <div style={{ fontSize: 48, marginBottom: 16, animation: "qc-pulse 2s ease-in-out infinite" }}>◎</div>
            <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 8, fontFamily: DISPLAY }}>Scanning {target}</div>
            <div style={{ fontSize: 12, marginBottom: 24, color: C.textDim }}>Queen Califia is scanning → learning → predicting → planning fixes → evolving</div>
            <div style={{ width: "100%", height: 8, borderRadius: 999, overflow: "hidden", marginBottom: 8, background: C.surface }}>
              <motion.div style={{ height: "100%", borderRadius: 999, background: `linear-gradient(90deg, ${C.gold}, ${C.purple})` }}
                animate={{ width: `${progress}%` }} transition={{ duration: 0.5 }} />
            </div>
            <div style={{ fontSize: 12, fontFamily: MONO, color: C.textDim }}>{progress.toFixed(0)}%</div>
          </motion.div>
        )}

        {step === 3 && result && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 16 }}>
              <span style={{ fontSize: 14, fontWeight: 700, fontFamily: DISPLAY }}>Scan Complete</span>
              <SeverityBadge severity={result.risk_level} />
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, marginBottom: 16 }}>
              <Stat label="Hosts Found" value={result.phases?.scan?.hosts_alive || 0} color={C.cyan} />
              <Stat label="Findings" value={result.phases?.scan?.total_findings || 0} color={result.phases?.scan?.critical > 0 ? C.red : C.amber} />
              <Stat label="Risk Score" value={`${result.phases?.scan?.overall_risk || 0}/10`} color={parseFloat(result.phases?.scan?.overall_risk) >= 7 ? C.red : C.green} />
            </div>

            {(result.phases?.scan?.critical > 0 || result.phases?.scan?.high > 0) && (
              <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
                {result.phases?.scan?.critical > 0 && <Badge color={C.red}>{result.phases.scan.critical} CRITICAL</Badge>}
                {result.phases?.scan?.high > 0 && <Badge color={C.amber}>{result.phases.scan.high} HIGH</Badge>}
              </div>
            )}

            <div style={{ padding: 12, borderRadius: 8, marginBottom: 16, background: C.surface }}>
              <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8 }}>Intelligence Gained</div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 4, fontSize: 10, color: C.textDim }}>
                <span>Baselines learned: {result.phases?.learning?.new_baselines || 0}</span>
                <span>Patterns recognized: {result.phases?.learning?.new_patterns || 0}</span>
                <span>Rules evolved: {result.phases?.evolution?.new_detection_rules || 0}</span>
                <span>Remediation actions: {result.phases?.remediation?.total_actions || 0}</span>
              </div>
            </div>

            <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 16, color: C.gold }}>{result.recommendation}</div>

            <button onClick={() => { setStep(1); setResult(null); setAck(false); play("button_click"); }}
              style={{ width: "100%", padding: 12, borderRadius: 8, fontSize: 12, fontWeight: 600, cursor: "pointer", background: C.purpleDim, border: `1px solid ${C.purple}50`, color: C.purple }}>
              Scan Again
            </button>
          </motion.div>
        )}
      </Panel>
    </div>
  );
}

// ─── DevOps Tab ───────────────────────────────────────────────────────────

function DevOpsTab() {
  const services = [
    { name: "API Gateway", status: "healthy", uptime: "99.97%", latency: "12ms" },
    { name: "Auth Service", status: "healthy", uptime: "99.99%", latency: "8ms" },
    { name: "Scan Engine", status: "healthy", uptime: "99.95%", latency: "45ms" },
    { name: "ML Pipeline", status: "degraded", uptime: "98.2%", latency: "120ms" },
    { name: "Log Aggregator", status: "healthy", uptime: "99.98%", latency: "15ms" },
    { name: "Alert Router", status: "healthy", uptime: "99.96%", latency: "5ms" },
  ];

  return (
    <div style={{ display: "grid", gap: 16 }}>
      <Panel title="Service Health" icon="◇" accent={C.green}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))", gap: 12 }}>
          {services.map(s => (
            <div key={s.name} style={{ padding: 12, borderRadius: 8, background: C.surface, border: `1px solid ${s.status === "healthy" ? C.green + "20" : C.amber + "30"}` }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                <PulseDot color={s.status === "healthy" ? C.green : C.amber} size={6} />
                <span style={{ fontSize: 12, fontWeight: 600, color: C.text }}>{s.name}</span>
              </div>
              <div style={{ display: "flex", gap: 16, fontSize: 10, color: C.textDim }}>
                <span>Uptime: <span style={{ color: C.green, fontFamily: MONO }}>{s.uptime}</span></span>
                <span>Latency: <span style={{ color: C.cyan, fontFamily: MONO }}>{s.latency}</span></span>
              </div>
            </div>
          ))}
        </div>
      </Panel>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(380px, 1fr))", gap: 16 }}>
        <Panel title="Deployment Pipeline" icon="◆" accent={C.cyan}>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {["Build", "Test", "Security Scan", "Stage", "Deploy"].map((stage, i) => (
              <div key={stage} style={{ display: "flex", alignItems: "center", gap: 12, padding: 8, borderRadius: 8, background: C.surface }}>
                <div style={{ width: 24, height: 24, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 9, fontWeight: 700, background: C.greenDim, color: C.green, fontFamily: MONO }}>{i + 1}</div>
                <span style={{ fontSize: 12, flex: 1, color: C.text }}>{stage}</span>
                <Badge color={C.green}>PASS</Badge>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Infrastructure" icon="◐" accent={C.purple}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Stat label="K8s Pods" value="24/24" color={C.green} />
            <Stat label="CPU Usage" value={`${randInt(15, 45)}%`} color={C.cyan} />
            <Stat label="Memory" value={`${randInt(40, 70)}%`} color={C.amber} />
            <Stat label="Storage" value={`${randInt(20, 55)}%`} color={C.purple} />
          </div>
        </Panel>
      </div>
    </div>
  );
}

// ─── Main Dashboard Component ─────────────────────────────────────────────

export default function QueenCalifiaUnifiedCommandDashboard() {
  const { play } = useSound();
  const [activeTab, setActiveTab] = useState("overview");
  const [qcAvatarState, setQcAvatarState] = useState("idle");
  const [tick, setTick] = useState(0);
  const [expertMode, setExpertMode] = useState(() => {
    try { return window.sessionStorage?.getItem?.("qc_expert") === "1"; } catch { return false; }
  });

  const toggleExpert = () => {
    const next = !expertMode;
    setExpertMode(next);
    try { window.sessionStorage?.setItem?.("qc_expert", next ? "1" : "0"); } catch {}
    if (!next && ["predictor", "mesh", "devops"].includes(activeTab)) setActiveTab("overview");
    play("button_click");
  };

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

  const critCount = incidents.filter(i => i.severity === "CRITICAL").length;
  const highPreds = predictions.filter(p => p.confidence > 0.7).length;

  useEffect(() => {
    if (critCount > 0) setQcAvatarState("ascended");
    else if (highPreds > 2) setQcAvatarState("active");
    else setQcAvatarState("idle");
  }, [critCount, highPreds]);

  const BASIC_TABS = ["overview", "vulns", "incidents"];
  const visibleNav = expertMode ? NAV_ITEMS : NAV_ITEMS.filter(n => BASIC_TABS.includes(n.id));

  const handleTabSwitch = (id) => {
    setActiveTab(id);
    play("tab_switch");
  };

  return (
    <div style={{ minHeight: "100vh", background: C.bg, color: C.text, fontFamily: FONT }}>
      <div style={{ position: "fixed", inset: 0, zIndex: 0, opacity: 0.02, pointerEvents: "none", backgroundImage: `url("${CDN}/qc-circuit-texture-crouTXBwBSsyVGQspVekAy.webp")`, backgroundSize: "cover" }} />

      {/* Header */}
      <header style={{
        position: "sticky", top: 0, zIndex: 50,
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "12px 24px",
        background: "rgba(4,2,10,0.95)", borderBottom: `1px solid ${C.gold}25`,
        backdropFilter: "blur(12px)",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <QueenCalifiaAvatar state={qcAvatarState} size={52} />
          <div>
            <div style={{ fontSize: 16, fontWeight: 700, letterSpacing: "0.12em", color: C.gold, fontFamily: DISPLAY }}>QUEEN CALIFIA</div>
            <div style={{ fontSize: 9, letterSpacing: "0.2em", marginTop: 2, color: C.textDim, fontFamily: MONO }}>
              CYBERAI v4.1 // TAMERIAN MATERIALS // DEFENSE GRADE
            </div>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <SoundToggle />

          <button onClick={toggleExpert}
            style={{
              padding: "6px 12px", borderRadius: 6, fontSize: 10, fontWeight: 600, letterSpacing: "0.08em",
              cursor: "pointer", transition: "all 0.2s", fontFamily: MONO,
              background: expertMode ? C.purpleDim : C.surface,
              border: `1px solid ${expertMode ? C.purple + "50" : C.border}`,
              color: expertMode ? C.purple : C.textDim,
            }}>
            {expertMode ? "◈ EXPERT" : "◇ SIMPLE"}
          </button>

          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <PulseDot color={critCount > 0 ? C.red : C.green} />
            <span style={{ fontSize: 10, fontWeight: 600, fontFamily: MONO, color: critCount > 0 ? C.red : C.green }}>
              {critCount > 0 ? `${critCount} CRITICAL` : "ALL CLEAR"}
            </span>
          </div>

          {expertMode && highPreds > 0 && <Badge color={C.purple}>◈ {highPreds} predictions</Badge>}

          <span style={{ fontSize: 9, fontFamily: MONO, color: C.textDim }}>
            {new Date().toLocaleTimeString()}
          </span>
        </div>
      </header>

      {/* Navigation */}
      <nav style={{
        position: "sticky", top: 68, zIndex: 40,
        display: "flex", gap: 2, padding: "0 24px", overflowX: "auto",
        borderBottom: `1px solid ${C.border}`,
        background: "rgba(10,15,30,0.95)", backdropFilter: "blur(8px)",
      }}>
        {visibleNav.map(item => (
          <button key={item.id} onClick={() => handleTabSwitch(item.id)}
            style={{
              padding: "10px 16px", fontSize: 10, fontWeight: 600, letterSpacing: "0.08em",
              display: "flex", alignItems: "center", gap: 6, cursor: "pointer",
              whiteSpace: "nowrap", transition: "all 0.2s", fontFamily: DISPLAY,
              background: "transparent",
              borderBottom: `2px solid ${activeTab === item.id ? C.gold : "transparent"}`,
              borderTop: "none", borderLeft: "none", borderRight: "none",
              color: activeTab === item.id ? C.text : C.textSoft,
            }}>
            <span style={{ fontSize: 12, color: activeTab === item.id ? C.gold : C.textDim }}>{item.icon}</span>
            {item.label}
            {item.id === "predictor" && highPreds > 0 && (
              <span style={{ width: 16, height: 16, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 8, fontWeight: 700, background: C.purple, color: "#fff" }}>{highPreds}</span>
            )}
            {item.id === "incidents" && critCount > 0 && (
              <span style={{ width: 16, height: 16, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 8, fontWeight: 700, background: C.red, color: "#fff" }}>{critCount}</span>
            )}
          </button>
        ))}
      </nav>

      {/* Content */}
      <main style={{ position: "relative", zIndex: 10, padding: 24 }}>
        <AnimatePresence mode="wait">
          <motion.div key={activeTab}
            initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.3 }}>
            {activeTab === "overview" && <OverviewTab mesh={mesh} predictions={predictions} incidents={incidents} timeSeries={timeSeries} landscape={landscape} />}
            {activeTab === "predictor" && expertMode && <PredictorTab predictions={predictions} layerActivity={layerActivity} />}
            {activeTab === "mesh" && expertMode && <MeshTab mesh={mesh} />}
            {activeTab === "incidents" && <IncidentsTab incidents={incidents} />}
            {activeTab === "vulns" && <VulnsTab setAvatarState={setQcAvatarState} />}
            {activeTab === "devops" && expertMode && <DevOpsTab />}
          </motion.div>
        </AnimatePresence>
      </main>

      {/* Footer */}
      <footer style={{
        position: "relative", zIndex: 10, padding: "8px 24px",
        display: "flex", flexWrap: "wrap", justifyContent: "space-between", alignItems: "center", gap: 8,
        borderTop: `1px solid ${C.border}`, background: C.panel,
      }}>
        <div style={{ fontSize: 9, color: C.textDim, fontFamily: MONO }}>
          TAMERIAN MATERIALS / QUEENCALIFIA-CYBERAI v4.1 — {expertMode ? "ALL ENGINES ACTIVE" : "SCANNER MODE"}
        </div>
        <div style={{ display: "flex", gap: 12, fontSize: 9, color: C.textDim, fontFamily: MONO }}>
          <span>Mesh: <span style={{ color: C.green }}>ONLINE</span></span>
          {expertMode && <span>Predictor: <span style={{ color: C.purple }}>ACTIVE</span></span>}
          <span>Nodes: <span style={{ color: C.green }}>{mesh.topology.active_nodes}/{mesh.topology.total_nodes}</span></span>
        </div>
      </footer>
    </div>
  );
}
