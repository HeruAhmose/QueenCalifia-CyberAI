import { useState, useEffect, useRef } from "react";

/* ═══════════════════════════════════════════════════════════
   QC SOVEREIGN TRAINING COMMAND CENTER v3
   
   Architecture:
     This console does NOT call Anthropic directly.
     It visualizes QC's training architecture and displays
     results from qc_sovereign_training.py (the Python service
     that hits the real QC backend on Render).
     
   The Python script → QC Backend (Render) → All API routes
   This console → Reads TRAINING_REPORT.json → Visualizes
   ═══════════════════════════════════════════════════════════ */

const C = {
  bg: "#06060B", panel: "#0C0C14", panelAlt: "#10101A",
  border: "#18182A", borderLit: "#D4A01744",
  gold: "#D4A017", goldDim: "#8B6914", amber: "#F59E0B",
  text: "#E2DED4", dim: "#5A5A6C",
  green: "#22C55E", red: "#EF4444", blue: "#3B82F6",
  purple: "#A855F7", cyan: "#06B6D4", white: "#F5F5F0",
};

// ─── ARCHITECTURE DATA ─────────────────────────────────────

const ARCH_LAYERS = [
  {
    name: "Training Service",
    desc: "scripts/qc_sovereign_training.py — runs locally/CI, holds no LLM secrets in browser",
    color: C.amber,
    components: ["Python CLI", "HTTP Client", "Result Collector", "Report Generator"],
  },
  {
    name: "QC Backend (Render)",
    desc: "Flask API — the real system under test",
    color: C.gold,
    components: [
      "/api/chat/",
      "/api/market/*",
      "/api/forecast/*",
      "/api/training/readiness",
      "/api/training/capabilities-catalog",
      "/healthz",
    ],
  },
  {
    name: "QC Core",
    desc: "Conversation Engine · Memory · Tool Routing · Personas · Audit Log",
    color: C.purple,
    components: ["Claude API (server-side)", "Memory Store", "Tool Router", "Persona Switcher"],
  },
  {
    name: "Intelligence Modules",
    desc: "Market data from trusted sources only — no random web browsing",
    color: C.cyan,
    components: ["SEC EDGAR", "FRED API", "ECB Data", "Coinbase", "Kraken", "Nasdaq"],
  },
  {
    name: "Storage & Audit",
    desc: "SQLite with full audit trail — every interaction logged",
    color: C.green,
    components: ["Sessions", "Turns", "Memories", "Source Cache", "Audit Log"],
  },
];

const PHASES = [
  {
    id: "infrastructure",
    name: "Infrastructure Health",
    icon: "🏗️",
    color: C.dim,
    tests: 6,
    desc: "Health endpoint, cold start latency, training readiness API, basic connectivity, auth verification",
    what_it_proves: "The platform is alive, responsive, and properly gated",
  },
  {
    id: "identity",
    name: "Identity & Personality",
    icon: "♛",
    color: C.gold,
    tests: 8,
    desc: "Sovereign voice calibration across all three personas (Cyber Guardian, Research Companion, Quant Lab), memory formation/recall, decisiveness testing, cross-mode coherence",
    what_it_proves: "QC maintains a consistent sovereign identity — she doesn't hedge, doesn't break character, and carries context across persona switches",
  },
  {
    id: "functions",
    name: "Function Validation",
    icon: "⚙️",
    color: C.cyan,
    tests: 17,
    desc: "Every API endpoint tested: chat (all 3 modes), market sources, crypto, FX, FRED, SEC, Nasdaq, forecast, portfolio, memory. Plus error handling for bad inputs.",
    what_it_proves: "Every route works, returns correct status codes, handles edge cases without crashing",
  },
  {
    id: "workflows",
    name: "Workflow Orchestration",
    icon: "🔗",
    color: C.purple,
    tests: 7,
    desc: "Multi-turn, multi-domain workflows: Threat Intel Pipeline (3 turns: detect → blast radius → exec summary), Market Intel Pipeline (snapshot → cross-domain synthesis), Context Accumulation (5-turn conversation referencing all prior details)",
    what_it_proves: "QC can sustain complex operational workflows, not just answer isolated questions. She accumulates context, escalates appropriately, and produces production-ready outputs mid-workflow.",
  },
  {
    id: "adversarial",
    name: "Adversarial Red-Team",
    icon: "🗡️",
    color: C.red,
    tests: 7,
    desc: "Prompt injection (role override + instruction override), social engineering (false authority), data extraction (system internals), persona escape, hallucination resistance (fabricated CVE), contradiction detection",
    what_it_proves: "QC cannot be manipulated into breaking character, leaking system details, hallucinating, or ignoring contradictions. Her guardrails are real.",
  },
  {
    id: "production",
    name: "Production Stress",
    icon: "🔥",
    color: C.amber,
    tests: 9,
    desc: "5-request latency benchmark, large input handling (50 events), burst tolerance (3 rapid requests), mode switching under load, graceful auth failure",
    what_it_proves: "QC handles production traffic patterns without degradation — fast responses, large payloads, rapid mode switches, and clean error states",
  },
  {
    id: "competitive",
    name: "Competitive Calibration",
    icon: "📡",
    color: C.blue,
    tests: 4,
    desc: "Self-positioning articulation, cross-domain analysis depth (cyber→market correlation), MITRE ATT&CK mapping quality, trusted source provenance",
    what_it_proves: "QC knows who she is relative to competitors, produces analyst-grade outputs, and can articulate her unique value: sovereign intelligence across cyber + market domains",
  },
];

// ─── COMPONENTS ────────────────────────────────────────────

const Badge = ({ children, color = C.gold, outline }) => (
  <span style={{
    display: "inline-flex", alignItems: "center", padding: "2px 9px",
    fontSize: 10, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase",
    borderRadius: 3, color: outline ? color : C.bg,
    background: outline ? "transparent" : color,
    border: outline ? `1px solid ${color}55` : "none",
    lineHeight: "18px",
  }}>{children}</span>
);

const GlowLine = ({ color = C.gold }) => (
  <div style={{ height: 1, background: `linear-gradient(90deg, transparent, ${color}55, transparent)`, margin: "14px 0" }} />
);

const MonoBlock = ({ children }) => (
  <div style={{
    background: "#08080E", border: `1px solid ${C.border}`, borderRadius: 6,
    padding: "12px 16px", fontFamily: "'IBM Plex Mono', 'Menlo', monospace",
    fontSize: 11.5, color: C.green, lineHeight: 1.7, overflowX: "auto",
    whiteSpace: "pre", tabSize: 2,
  }}>{children}</div>
);

function TabBar({ tabs, active, onChange }) {
  return (
    <div style={{
      display: "flex", borderBottom: `1px solid ${C.border}`, padding: "0 20px",
      background: C.panel, overflowX: "auto",
    }}>
      {tabs.map(t => (
        <button
          key={t.id}
          onClick={() => onChange(t.id)}
          style={{
            background: "none", border: "none",
            borderBottom: active === t.id ? `2px solid ${C.gold}` : "2px solid transparent",
            color: active === t.id ? C.gold : C.dim,
            padding: "11px 18px", fontSize: 11.5, fontWeight: active === t.id ? 700 : 500,
            letterSpacing: "0.05em", textTransform: "uppercase", cursor: "pointer",
            whiteSpace: "nowrap", fontFamily: "inherit", transition: "all 0.15s",
          }}
        >{t.icon} {t.label}</button>
      ))}
    </div>
  );
}

// ─── TAB: ARCHITECTURE ─────────────────────────────────────

function ArchitectureTab() {
  return (
    <div>
      <p style={{ color: C.dim, fontSize: 12.5, lineHeight: 1.7, marginBottom: 20 }}>
        How the training service connects to the real QC platform. No browser→Anthropic
        calls. The Python script hits QC's Render backend, which holds the API key and
        runs the real conversation engine, memory system, and tool routing.
      </p>

      {/* Architecture Stack */}
      <div style={{ position: "relative" }}>
        {ARCH_LAYERS.map((layer, i) => (
          <div key={i} style={{ marginBottom: 2 }}>
            <div style={{
              background: `${layer.color}08`, border: `1px solid ${layer.color}30`,
              borderRadius: i === 0 ? "10px 10px 0 0" : i === ARCH_LAYERS.length - 1 ? "0 0 10px 10px" : 0,
              padding: "14px 18px",
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                <div style={{ color: layer.color, fontSize: 13, fontWeight: 700 }}>{layer.name}</div>
                {i > 0 && (
                  <span style={{ color: C.dim, fontSize: 10 }}>↑ calls ↑</span>
                )}
              </div>
              <div style={{ color: C.dim, fontSize: 11, marginBottom: 8 }}>{layer.desc}</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
                {layer.components.map((c, j) => (
                  <span key={j} style={{
                    padding: "3px 8px", background: `${layer.color}15`,
                    border: `1px solid ${layer.color}25`, borderRadius: 3,
                    color: C.text, fontSize: 10,
                  }}>{c}</span>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>

      <GlowLine />

      {/* Key Architecture Decisions */}
      <div style={{ color: C.gold, fontSize: 11, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 700, marginBottom: 12 }}>
        Why This Architecture
      </div>
      {[
        { q: "Why not call Anthropic from the browser?", a: "API key exposure, CORS blocks, and you'd be testing a simulated persona — not QC's actual system prompt, memory engine, or tool routing." },
        { q: "Why not call Anthropic from the Python script directly?", a: "That's prompt-testing, not platform training. You'd skip QC's backend entirely — no memory formation, no persona switching, no trusted source pipeline, no audit trail." },
        { q: "What does this actually train?", a: "It validates and calibrates the entire system: personality consistency, workflow execution, endpoint reliability, adversarial resilience, and production performance. The training reports tell you exactly where QC is sovereign and where she needs work." },
      ].map((item, i) => (
        <div key={i} style={{ marginBottom: 14 }}>
          <div style={{ color: C.text, fontSize: 12, fontWeight: 600, marginBottom: 3 }}>{item.q}</div>
          <div style={{ color: C.dim, fontSize: 11.5, lineHeight: 1.6, paddingLeft: 12, borderLeft: `2px solid ${C.gold}30` }}>
            {item.a}
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── TAB: PHASES ───────────────────────────────────────────

function PhasesTab() {
  const [expanded, setExpanded] = useState(null);

  return (
    <div>
      <p style={{ color: C.dim, fontSize: 12.5, lineHeight: 1.7, marginBottom: 20 }}>
        Seven phases, {PHASES.reduce((a, p) => a + p.tests, 0)} tests. Each phase targets a different
        dimension of QC's operational capability. Run all phases with{" "}
        <span style={{ color: C.green, fontFamily: "'IBM Plex Mono', monospace", fontSize: 11 }}>
          --phase all
        </span>{" "}
        or isolate any phase for focused training.
      </p>

      <div style={{ display: "grid", gap: 8 }}>
        {PHASES.map((phase, i) => (
          <div key={phase.id} style={{
            background: expanded === i ? `${phase.color}06` : C.panel,
            border: `1px solid ${expanded === i ? phase.color + "40" : C.border}`,
            borderRadius: 8, overflow: "hidden", transition: "all 0.2s",
          }}>
            <div
              onClick={() => setExpanded(expanded === i ? null : i)}
              style={{
                padding: "14px 16px", cursor: "pointer",
                display: "grid", gridTemplateColumns: "auto 1fr auto auto",
                gap: 12, alignItems: "center",
              }}
            >
              <span style={{ fontSize: 20 }}>{phase.icon}</span>
              <div>
                <div style={{ color: C.text, fontSize: 13.5, fontWeight: 700 }}>{phase.name}</div>
                <div style={{ color: C.dim, fontSize: 10.5, marginTop: 1 }}>Phase {i} — {phase.id}</div>
              </div>
              <Badge color={phase.color}>{phase.tests} tests</Badge>
              <span style={{ color: C.dim, fontSize: 14, transition: "transform 0.2s", transform: expanded === i ? "rotate(90deg)" : "rotate(0)" }}>›</span>
            </div>

            {expanded === i && (
              <div style={{ padding: "0 16px 16px 16px", borderTop: `1px solid ${C.border}` }}>
                <div style={{ marginTop: 12 }}>
                  <div style={{ color: phase.color, fontSize: 10, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 700, marginBottom: 6 }}>
                    What It Tests
                  </div>
                  <div style={{ color: C.text, fontSize: 12, lineHeight: 1.7 }}>{phase.desc}</div>
                </div>
                <div style={{ marginTop: 12 }}>
                  <div style={{ color: C.green, fontSize: 10, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 700, marginBottom: 6 }}>
                    What It Proves
                  </div>
                  <div style={{ color: C.text, fontSize: 12, lineHeight: 1.7 }}>{phase.what_it_proves}</div>
                </div>
                <MonoBlock>
{`python scripts/qc_sovereign_training.py --phase ${phase.id}`}
                </MonoBlock>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── TAB: RUN ──────────────────────────────────────────────

function RunTab() {
  return (
    <div>
      <div style={{ color: C.gold, fontSize: 11, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 700, marginBottom: 16 }}>
        Initiation Sequence
      </div>

      {[
        {
          step: "01", title: "Set Environment",
          code: `export QC_BASE_URL=https://queencalifia-cyberai.onrender.com
export QC_API_KEY=your-api-key-here
export QC_ADMIN_KEY=your-admin-key-here`,
          note: "No pip install required — stdlib only. QC_API_KEY is sent as the X-QC-API-Key header (same as the dashboard). Your Anthropic key never leaves the server.",
        },
        {
          step: "02", title: "Quick Health Check",
          code: `python scripts/qc_sovereign_training.py --phase infrastructure`,
          note: "Verifies connectivity, cold start timing, and auth. Run this first.",
        },
        {
          step: "03", title: "Identity Calibration",
          code: `python scripts/qc_sovereign_training.py --phase identity`,
          note: "Tests QC's sovereign voice, memory, decisiveness, mode switching. This is where you find persona drift.",
        },
        {
          step: "04", title: "Full Training Run",
          code: `python scripts/qc_sovereign_training.py --phase all`,
          note: "All 7 phases, ~58 checks. Takes 5-15 minutes depending on cold start and response times. Produces TRAINING_REPORT.json.",
        },
        {
          step: "05", title: "Adversarial Focus",
          code: `python scripts/qc_sovereign_training.py --phase adversarial`,
          note: "Red-team only. Prompt injection, social engineering, hallucination resistance. Run this after any system prompt changes.",
        },
        {
          step: "06", title: "Local Development",
          code: `QC_BASE_URL=http://localhost:5000 python scripts/qc_sovereign_training.py --phase all`,
          note: "Point at your local Flask server during development. Same tests, faster iteration.",
        },
      ].map((s, i) => (
        <div key={i} style={{
          display: "grid", gridTemplateColumns: "44px 1fr",
          gap: 14, marginBottom: 20,
        }}>
          <div style={{
            color: C.gold, fontSize: 20, fontWeight: 800,
            fontFamily: "'IBM Plex Mono', monospace", textAlign: "center",
            lineHeight: "44px",
          }}>{s.step}</div>
          <div>
            <div style={{ color: C.text, fontSize: 14, fontWeight: 700, marginBottom: 6 }}>{s.title}</div>
            <MonoBlock>{s.code}</MonoBlock>
            <div style={{ color: C.dim, fontSize: 11, marginTop: 6, lineHeight: 1.5 }}>{s.note}</div>
          </div>
        </div>
      ))}

      <GlowLine />

      {/* CI/CD Integration */}
      <div style={{ color: C.gold, fontSize: 11, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 700, marginBottom: 12 }}>
        CI/CD Integration
      </div>
      <p style={{ color: C.dim, fontSize: 12, lineHeight: 1.6, marginBottom: 12 }}>
        Add this to your GitHub Actions workflow to run training on every deploy:
      </p>
      <MonoBlock>
{`# .github/workflows/qc-training.yml
name: QC Training
on:
  push:
    branches: [main]
  schedule:
    - cron: '0 6 * * *'  # Daily at 6 AM UTC

jobs:
  train:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Run QC Training
        env:
          QC_BASE_URL: \${{ secrets.QC_BASE_URL }}
          QC_API_KEY: \${{ secrets.QC_API_KEY }}
        run: python scripts/qc_sovereign_training.py --phase all
      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: training-report
          path: qc_training_*/TRAINING_REPORT.json`}
      </MonoBlock>
    </div>
  );
}

// ─── TAB: REPORT VIEWER ────────────────────────────────────

function ReportTab() {
  const [report, setReport] = useState(null);
  const fileRef = useRef(null);

  const loadReport = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        setReport(JSON.parse(ev.target.result));
      } catch { alert("Invalid JSON file"); }
    };
    reader.readAsText(file);
  };

  // Demo data for rendering
  const demoReport = report || null;

  if (!demoReport) {
    return (
      <div style={{ textAlign: "center", padding: 40 }}>
        <div style={{ fontSize: 36, marginBottom: 12, opacity: 0.3 }}>📊</div>
        <div style={{ color: C.text, fontSize: 15, fontWeight: 600, marginBottom: 8 }}>
          Load Training Report
        </div>
        <div style={{ color: C.dim, fontSize: 12, lineHeight: 1.6, marginBottom: 20, maxWidth: 400, margin: "0 auto 20px" }}>
          Run <span style={{ color: C.green, fontFamily: "'IBM Plex Mono', monospace", fontSize: 11 }}>
          python scripts/qc_sovereign_training.py --phase all</span> then
          load the generated TRAINING_REPORT.json here to visualize results.
        </div>
        <input
          ref={fileRef}
          type="file"
          accept=".json"
          onChange={loadReport}
          style={{ display: "none" }}
        />
        <button
          onClick={() => fileRef.current?.click()}
          style={{
            padding: "12px 28px", borderRadius: 6, border: "none",
            background: `linear-gradient(135deg, ${C.gold}, ${C.amber})`,
            color: C.bg, fontSize: 13, fontWeight: 700, cursor: "pointer",
            textTransform: "uppercase", letterSpacing: "0.06em",
          }}
        >Load TRAINING_REPORT.json</button>
      </div>
    );
  }

  const meta = demoReport.meta || {};
  const phases = demoReport.phase_scores || {};
  const results = demoReport.results || [];
  const failures = results.filter(r => !r.passed);

  return (
    <div>
      {/* Summary Header */}
      <div style={{
        background: `linear-gradient(135deg, ${C.panel}, ${meta.pass_rate >= 90 ? C.green : meta.pass_rate >= 70 ? C.amber : C.red}08)`,
        border: `1px solid ${meta.pass_rate >= 90 ? C.green : meta.pass_rate >= 70 ? C.amber : C.red}33`,
        borderRadius: 10, padding: 20, marginBottom: 20, textAlign: "center",
      }}>
        <div style={{ color: C.dim, fontSize: 10, textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 8 }}>
          Overall Pass Rate
        </div>
        <div style={{
          fontSize: 48, fontWeight: 800, fontFamily: "'IBM Plex Mono', monospace",
          color: meta.pass_rate >= 90 ? C.green : meta.pass_rate >= 70 ? C.amber : C.red,
        }}>
          {meta.pass_rate}%
        </div>
        <div style={{ color: C.dim, fontSize: 12, marginTop: 4 }}>
          {meta.total_passed}/{meta.total_tests} tests passed · {meta.session_id} · {new Date(meta.timestamp).toLocaleString()}
        </div>
      </div>

      {/* Phase Bars */}
      <div style={{ display: "grid", gap: 6, marginBottom: 20 }}>
        {Object.entries(phases).map(([name, data]) => {
          const pct = data.rate;
          const color = pct >= 90 ? C.green : pct >= 70 ? C.amber : C.red;
          return (
            <div key={name} style={{
              display: "grid", gridTemplateColumns: "140px 1fr 80px 70px",
              gap: 12, alignItems: "center", padding: "8px 12px",
              background: C.panel, borderRadius: 6,
            }}>
              <span style={{ color: C.text, fontSize: 11.5, fontWeight: 600 }}>{name}</span>
              <div style={{ height: 6, background: `${C.dim}22`, borderRadius: 3, overflow: "hidden" }}>
                <div style={{ height: "100%", width: `${pct}%`, background: color, borderRadius: 3, transition: "width 0.5s" }} />
              </div>
              <span style={{ color, fontSize: 12, fontWeight: 700, fontFamily: "'IBM Plex Mono', monospace", textAlign: "right" }}>
                {data.passed}/{data.total}
              </span>
              <span style={{ color: C.dim, fontSize: 10, textAlign: "right" }}>{data.avg_latency_ms}ms</span>
            </div>
          );
        })}
      </div>

      {/* Failures */}
      {failures.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <div style={{ color: C.red, fontSize: 11, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 700, marginBottom: 10 }}>
            Failed Tests ({failures.length})
          </div>
          {failures.map((f, i) => (
            <div key={i} style={{
              padding: "10px 14px", background: `${C.red}08`, border: `1px solid ${C.red}22`,
              borderRadius: 6, marginBottom: 6,
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div>
                  <Badge color={C.red} outline>{f.phase}</Badge>
                  <span style={{ color: C.text, fontSize: 12, marginLeft: 8 }}>{f.test}</span>
                </div>
                {f.latency_ms && <span style={{ color: C.dim, fontSize: 10 }}>{f.latency_ms}ms</span>}
              </div>
              {f.detail && <div style={{ color: C.dim, fontSize: 11, marginTop: 4 }}>{f.detail}</div>}
              {f.response_preview && (
                <div style={{
                  marginTop: 6, padding: 8, background: C.bg, borderRadius: 4,
                  fontFamily: "'IBM Plex Mono', monospace", fontSize: 10,
                  color: C.dim, maxHeight: 80, overflowY: "auto", whiteSpace: "pre-wrap",
                }}>{f.response_preview}</div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Load Another */}
      <div style={{ textAlign: "center" }}>
        <input ref={fileRef} type="file" accept=".json" onChange={loadReport} style={{ display: "none" }} />
        <button
          onClick={() => fileRef.current?.click()}
          style={{
            padding: "8px 20px", borderRadius: 4, border: `1px solid ${C.border}`,
            background: "transparent", color: C.dim, fontSize: 11, cursor: "pointer",
          }}
        >Load Different Report</button>
      </div>
    </div>
  );
}

// ─── MAIN APP ──────────────────────────────────────────────

export default function QCTrainingConsole() {
  const [tab, setTab] = useState("architecture");
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    const link = document.createElement("link");
    link.href = "https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@600;700&family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap";
    link.rel = "stylesheet";
    document.head.appendChild(link);
    setTimeout(() => setLoaded(true), 60);
  }, []);

  const tabs = [
    { id: "architecture", label: "Architecture", icon: "◆" },
    { id: "phases", label: "Training Phases", icon: "▣" },
    { id: "run", label: "How to Run", icon: "▶" },
    { id: "report", label: "Report Viewer", icon: "◈" },
  ];

  return (
    <div style={{
      background: C.bg, minHeight: "100vh", color: C.text,
      fontFamily: "'IBM Plex Sans', sans-serif",
      opacity: loaded ? 1 : 0, transition: "opacity 0.3s",
    }}>
      {/* Header */}
      <div style={{
        borderBottom: `1px solid ${C.border}`, padding: "18px 20px",
        background: `linear-gradient(180deg, ${C.bg}, ${C.panel})`,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <div style={{
            width: 38, height: 38, borderRadius: "50%",
            background: `conic-gradient(from 0deg, ${C.gold}, ${C.amber}, ${C.gold})`,
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 16, color: C.bg, fontWeight: 900,
          }}>♛</div>
          <div>
            <h1 style={{
              margin: 0, fontSize: 19,
              fontFamily: "'Cormorant Garamond', serif", fontWeight: 700,
              letterSpacing: "0.02em",
            }}>
              QC Training Command Center
            </h1>
            <div style={{ color: C.dim, fontSize: 10, letterSpacing: "0.1em", textTransform: "uppercase", marginTop: 1 }}>
              v3 · Production Training Service · {PHASES.reduce((a, p) => a + p.tests, 0)} checks · 7 phases
            </div>
          </div>
        </div>

        <div style={{
          display: "flex", gap: 16, marginTop: 14, padding: "8px 14px",
          background: `${C.gold}06`, borderRadius: 6, border: `1px solid ${C.gold}12`,
          fontSize: 10,
        }}>
          {[
            { label: "Backend", value: "Render (Flask)", color: C.gold },
            { label: "Frontend", value: "Firebase", color: C.cyan },
            { label: "Personas", value: "Cyber · Research · Lab", color: C.purple },
            { label: "Sources", value: "6 Trusted", color: C.green },
          ].map((s, i) => (
            <div key={i}>
              <span style={{ color: C.dim }}>{s.label}: </span>
              <span style={{ color: s.color, fontWeight: 600 }}>{s.value}</span>
            </div>
          ))}
        </div>
      </div>

      <TabBar tabs={tabs} active={tab} onChange={setTab} />

      <div style={{ padding: 20, maxWidth: 800, margin: "0 auto" }}>
        {tab === "architecture" && <ArchitectureTab />}
        {tab === "phases" && <PhasesTab />}
        {tab === "run" && <RunTab />}
        {tab === "report" && <ReportTab />}
      </div>
    </div>
  );
}
