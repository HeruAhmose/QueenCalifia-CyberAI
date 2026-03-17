import { useEffect, useMemo, useRef, useState } from "react";
import { API, hdrs } from "./lib/api";
import IdentityPanel from "./panels/IdentityPanel";
import LearningDock from "./panels/LearningDock";
import ModelManager from "./panels/ModelManager";
import CyberMissionPanel from "./panels/CyberMissionPanel";
import "./panels/panels.css";

const CONFIGURED_API_KEY = import.meta.env.VITE_QC_API_KEY || "";

function uid(p) {
  return globalThis.crypto?.randomUUID ? `${p}-${globalThis.crypto.randomUUID()}` : `${p}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}
function stored(k, p) { const v = localStorage.getItem(k); if (v) return v; const n = uid(p); localStorage.setItem(k, n); return n; }
function pretty(v) { return JSON.stringify(v, null, 2); }

const MODES = {
  cyber:    { label: "Cyber Guardian",     icon: "\u{1F6E1}\uFE0F", color: "#00e5ff" },
  research: { label: "Research Companion", icon: "\u{1F4CA}", color: "#ffd740" },
  lab:      { label: "Quant Lab",          icon: "\u2697\uFE0F",  color: "#ea80fc" },
};

const SAMPLE_HOLDINGS = [
  { symbol: "BTC-USD", asset_type: "crypto", units: 0.25, latest_price: 65000 },
  { symbol: "ETH-USD", asset_type: "crypto", units: 2, latest_price: 3500 },
  { symbol: "AAPL", asset_type: "stock", units: 10, latest_price: 220 },
];

const SAMPLE_QUANT = {
  risk_aversion: 0.5,
  candidates: [
    { symbol: "BTC-USD", expected_return: 0.18, risk: 0.32 },
    { symbol: "ETH-USD", expected_return: 0.15, risk: 0.28 },
    { symbol: "AAPL", expected_return: 0.08, risk: 0.14 },
  ],
};

export default function App() {
  const [mode, setMode] = useState("cyber");
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [config, setConfig] = useState({ name: "Queen Califia", persona: "" });
  const [memories, setMemories] = useState([]);
  const [sources, setSources] = useState([]);
  const [error, setError] = useState("");
  const [mktForm, setMktForm] = useState({ asset_type: "crypto", symbol: "BTC-USD" });
  const [snapshot, setSnapshot] = useState(null);
  const [forecast, setForecast] = useState(null);
  const [holdingsText, setHoldingsText] = useState(pretty(SAMPLE_HOLDINGS));
  const [portfolioResult, setPortfolioResult] = useState(null);
  const [adminKey, setAdminKey] = useState("");
  const [quantText, setQuantText] = useState(pretty(SAMPLE_QUANT));
  const [quantResult, setQuantResult] = useState(null);

  const streamRef = useRef(null);
  const sessionId = useMemo(() => stored("qc_session", "ses"), []);
  const userId = useMemo(() => stored("qc_user", "usr"), []);

  // Boot
  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const [cr, sr] = await Promise.all([
          fetch(`${API}/api/config`),
          fetch(`${API}/api/market/sources`, { headers: hdrs() }),
        ]);
        const cd = await cr.json();
        const sd = sr.ok ? await sr.json() : {};
        if (!alive) return;
        setConfig(cd);
        setSources(sd.sources || []);
        setMessages([{ id: "w", role: "assistant", content: cd.welcome_message }]);
      } catch (e) {
        if (!alive) return;
        setError(e.message);
        setMessages([{ id: "e", role: "assistant", content: "Backend unreachable. Check API URL." }]);
      }
    })();
    return () => { alive = false; };
  }, []);

  useEffect(() => {
    streamRef.current?.scrollTo({ top: streamRef.current.scrollHeight, behavior: "smooth" });
  }, [messages]);

  // ── Chat ──
  async function send() {
    const t = input.trim(); if (!t || busy) return;
    setError(""); setBusy(true);
    setMessages(m => [...m, { id: uid("u"), role: "user", content: t }]); setInput("");
    try {
      const r = await fetch(`${API}/api/chat/`, {
        method: "POST", headers: hdrs(),
        body: JSON.stringify({ message: t, session_id: sessionId, user_id: userId, mode }),
      });
      const d = await r.json(); if (!r.ok) throw new Error(d.error || r.status);
      if (d.memories_added?.length) setMemories(p => [...d.memories_added, ...p].slice(0, 12));
      setMessages(m => [...m, { id: uid("a"), role: "assistant", content: d.reply }]);
    } catch (e) {
      setError(e.message);
      setMessages(m => [...m, { id: uid("e"), role: "assistant", content: `Error: ${e.message}` }]);
    } finally { setBusy(false); }
  }

  // ── Market ──
  async function loadSnapshot(e) {
    e.preventDefault(); setError(""); setForecast(null);
    try {
      const r = await fetch(`${API}/api/market/snapshot?asset_type=${mktForm.asset_type}&symbol=${mktForm.symbol}`,
        { headers: hdrs() });
      const d = await r.json(); if (!r.ok) throw new Error(d.error || r.status);
      setSnapshot(d);
    } catch (e) { setError(e.message); }
  }

  async function runForecast() {
    if (!snapshot) return; setError("");
    try {
      const r = await fetch(`${API}/api/forecast/run`, {
        method: "POST", headers: hdrs(),
        body: JSON.stringify({ user_id: userId, run_type: "telemetry_forecast",
          input: { asset_type: snapshot.asset_type, symbol: snapshot.symbol, horizon: "short" } }),
      });
      const d = await r.json(); if (!r.ok) throw new Error(d.error || r.status);
      setForecast(d);
    } catch (e) { setError(e.message); }
  }

  // ── Portfolio ──
  async function analyzePortfolio(e) {
    e.preventDefault(); setError("");
    try {
      const h = JSON.parse(holdingsText);
      const r = await fetch(`${API}/api/forecast/portfolio/analyze`, {
        method: "POST", headers: hdrs(), body: JSON.stringify({ holdings: h }),
      });
      const d = await r.json(); if (!r.ok) throw new Error(d.error || r.status);
      setPortfolioResult(d);
    } catch (e) { setError(e.message); }
  }

  // ── Quant (admin) ──
  async function runQuant(e) {
    e.preventDefault(); setError("");
    try {
      const p = JSON.parse(quantText);
      const r = await fetch(`${API}/api/forecast/quant/run`, {
        method: "POST", headers: hdrs(adminKey), body: JSON.stringify(p),
      });
      const d = await r.json(); if (!r.ok) throw new Error(d.error || r.status);
      setQuantResult(d);
    } catch (e) { setError(e.message); }
  }

  const mi = MODES[mode];

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-glyph">{"\u265B"}</div>
          <h1>Queen Califia</h1>
          <p className="brand-sub">CyberAI v4.2.1 — QC OS</p>
        </div>

        <div className="mode-switcher">
          {Object.entries(MODES).map(([k, m]) => (
            <button key={k} className={`mode-btn ${mode === k ? "active" : ""}`}
              style={{ "--accent": m.color }} onClick={() => setMode(k)}>
              <span className="mode-icon">{m.icon}</span>
              <span className="mode-label">{m.label}</span>
            </button>
          ))}
        </div>

        <div className="panel"><h2>Memory</h2>
          {memories.length === 0 ? <p className="muted">No memories yet.</p>
            : memories.map((m, i) => (
              <div key={i} className="mem-item">
                <span className="mem-key">{m.key}</span>
                <span className="mem-val">{m.value}</span>
              </div>
            ))}
        </div>

        <div className="panel"><h2>Trusted Sources</h2>
          {sources.length === 0 ? <p className="muted">Loading...</p>
            : sources.map(s => (
              <div key={s.id} className="source-row">
                <span className={`dot ${s.enabled ? "on" : "off"}`} />
                <span className="source-name">{s.name}</span>
                <span className="source-score">{(s.confidence_score * 100).toFixed(0)}%</span>
              </div>
            ))}
        </div>

        <div className="panel"><h2>Quant Lab Unlock</h2>
          <input className="input-sm" value={adminKey}
            onChange={e => setAdminKey(e.target.value)} placeholder="X-QC-Admin-Key" />
        </div>

        <div className="panel status-panel">
          <div className="status-row"><span>API</span><code>{API}</code></div>
          <div className="status-row"><span>Mode</span><code style={{color: mi.color}}>{mi.label}</code></div>
        </div>

        {error && <div className="error-box">{error}</div>}
      </aside>

      <main className="main">
        {/* Chat */}
        <section className="chat-section">
          <header className="chat-header">
            <div><span className="header-icon">{mi.icon}</span><h2>{mi.label}</h2></div>
            <div className={`status-pill ${busy ? "busy" : "ready"}`}>{busy ? "Thinking\u2026" : "Ready"}</div>
          </header>
          <div className="stream" ref={streamRef}>
            {messages.map(msg => (
              <article key={msg.id} className={`bubble ${msg.role}`}>
                <div className="bubble-who">{msg.role === "assistant" ? config.name : "You"}</div>
                <div className="bubble-text">{msg.content}</div>
              </article>
            ))}
            {busy && <article className="bubble assistant"><div className="bubble-who">{config.name}</div>
              <div className="bubble-text typing"><span/><span/><span/></div></article>}
          </div>
          <form className="composer" onSubmit={e => { e.preventDefault(); send(); }}>
            <textarea value={input} onChange={e => setInput(e.target.value)}
              onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } }}
              placeholder={mode === "cyber" ? "Ask about threats, vulnerabilities, architecture\u2026"
                : mode === "research" ? "Query market data, economic indicators\u2026"
                : "Design experiments, run scenarios\u2026"} rows={3} disabled={busy} />
            <button type="submit" disabled={busy || !input.trim()}>{busy ? "\u2026" : "\u2192"}</button>
          </form>
        </section>

        {/* Labs */}
        <div className="labs-grid">
          <form className="panel lab-panel" onSubmit={loadSnapshot}>
            <h2 className="lab-title">Market Lab</h2>
            <div className="lab-row">
              <select value={mktForm.asset_type} onChange={e => setMktForm(f => ({...f, asset_type: e.target.value}))}>
                <option value="crypto">crypto</option><option value="forex">forex</option>
                <option value="stock">stock</option><option value="macro">macro</option>
              </select>
              <input className="input-sm" value={mktForm.symbol}
                onChange={e => setMktForm(f => ({...f, symbol: e.target.value.toUpperCase()}))} placeholder="BTC-USD" />
              <button type="submit">Load</button>
              <button type="button" onClick={runForecast} disabled={!snapshot}>Forecast</button>
            </div>
            {snapshot && <pre className="lab-output">{pretty(snapshot)}</pre>}
            {forecast && <pre className="lab-output">{pretty(forecast)}</pre>}
          </form>

          <form className="panel lab-panel" onSubmit={analyzePortfolio}>
            <h2 className="lab-title">Portfolio Lab</h2>
            <textarea className="lab-textarea" value={holdingsText}
              onChange={e => setHoldingsText(e.target.value)} rows={8} />
            <button type="submit">Analyze</button>
            {portfolioResult && <pre className="lab-output">{pretty(portfolioResult)}</pre>}
          </form>

          {adminKey && (
            <form className="panel lab-panel lab-quant" onSubmit={runQuant}>
              <h2 className="lab-title">Quant Lab (Admin)</h2>
              <textarea className="lab-textarea" value={quantText}
                onChange={e => setQuantText(e.target.value)} rows={8} />
              <button type="submit">Run Optimizer</button>
              {quantResult && <pre className="lab-output">{pretty(quantResult)}</pre>}
            </form>
          )}
        </div>

        {/* ── Identity Core Section ── */}
        <section className="identity-section">
          <div className="identity-section-head">
            <h2>{"\u265B"} Identity Core</h2>
          </div>
          <div className="identity-grid">
            <IdentityPanel adminKey={adminKey} />
            <div style={{ display: "flex", flexDirection: "column", gap: "1px", background: "var(--border)" }}>
              <ModelManager adminKey={adminKey} />
              <LearningDock adminKey={adminKey} />
            </div>
            <CyberMissionPanel adminKey={adminKey} />
          </div>
        </section>
      </main>
    </div>
  );
}
