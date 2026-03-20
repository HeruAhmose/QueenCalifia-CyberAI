/**
 * Queen Califia CyberAI — Cinematic Intro v4.1
 * Sovereign Circuitry Design | Afrofuturist Cyber-Throne
 * Particle field + avatar reveal + golden shimmer cascade
 */
import React, { useState, useEffect, useRef, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useSound } from "../contexts/SoundContext.jsx";
import { playSound, setMasterVolume, startAmbient } from "../lib/SoundEngine.js";

const CDN = "https://d2xsxph8kpxj0f.cloudfront.net/310419663029216973/6A6PRiSc2SBdMKdQGVopRa";

function createParticle(w, h) {
  const colors = ["#D4AF37", "#FFE178", "#00DCFA", "#A78BFA", "#D4AF37"];
  return {
    x: Math.random() * w, y: Math.random() * h,
    vx: (Math.random() - 0.5) * 0.8, vy: (Math.random() - 0.5) * 0.8 - 0.3,
    size: Math.random() * 2.5 + 0.5, alpha: 0,
    color: colors[Math.floor(Math.random() * colors.length)],
    life: 0, maxLife: 200 + Math.random() * 300,
  };
}

export default function CinematicIntro({ onComplete, onAwaken }) {
  const canvasRef = useRef(null);
  const [phase, setPhase] = useState("waiting");
  const [textVisible, setTextVisible] = useState(false);
  const [subtitleVisible, setSubtitleVisible] = useState(false);
  const [buttonVisible, setButtonVisible] = useState(false);
  const [telemetryIndex, setTelemetryIndex] = useState(0);
  const particlesRef = useRef([]);
  const animFrameRef = useRef(0);
  const { toggle, enabled } = useSound();
  const telemetryLines = [
    "Hex mesh aligning",
    "Ancestral signal online",
    "Threat lattice calibrating",
    "Sovereign circuit stabilized",
  ];

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const resize = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
    resize();
    window.addEventListener("resize", resize);

    for (let i = 0; i < 120; i++) {
      particlesRef.current.push(createParticle(canvas.width, canvas.height));
    }

    const animate = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      particlesRef.current.forEach((p, i) => {
        p.life++;
        p.x += p.vx;
        p.y += p.vy;
        const lifeRatio = p.life / p.maxLife;
        if (lifeRatio < 0.1) p.alpha = lifeRatio * 10;
        else if (lifeRatio > 0.8) p.alpha = (1 - lifeRatio) * 5;
        else p.alpha = 1;

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = p.color;
        ctx.globalAlpha = p.alpha * 0.6;
        ctx.fill();

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size * 3, 0, Math.PI * 2);
        const grad = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.size * 3);
        grad.addColorStop(0, p.color);
        grad.addColorStop(1, "transparent");
        ctx.fillStyle = grad;
        ctx.globalAlpha = p.alpha * 0.15;
        ctx.fill();

        if (p.life >= p.maxLife || p.x < -10 || p.x > canvas.width + 10 || p.y < -10 || p.y > canvas.height + 10) {
          particlesRef.current[i] = createParticle(canvas.width, canvas.height);
        }
      });
      ctx.globalAlpha = 1;
      animFrameRef.current = requestAnimationFrame(animate);
    };
    animate();

    return () => { window.removeEventListener("resize", resize); cancelAnimationFrame(animFrameRef.current); };
  }, []);

  useEffect(() => {
    if (phase === "awakening") {
      const t1 = setTimeout(() => setTextVisible(true), 800);
      const t2 = setTimeout(() => setSubtitleVisible(true), 1800);
      const t3 = setTimeout(() => { setPhase("revealing"); setButtonVisible(true); }, 2800);
      return () => { clearTimeout(t1); clearTimeout(t2); clearTimeout(t3); };
    }
  }, [phase]);

  useEffect(() => {
    const timer = setInterval(() => {
      setTelemetryIndex((prev) => (prev + 1) % telemetryLines.length);
    }, 2200);
    return () => clearInterval(timer);
  }, [telemetryLines.length]);

  const handleEnter = useCallback(() => {
    if (!enabled) {
      toggle();
      setMasterVolume(0.3);
      startAmbient();
    }
    playSound("sovereign_awaken");

    if (phase === "waiting") {
      onAwaken?.();
      setPhase("awakening");
    } else if (phase === "revealing") {
      setPhase("ready");
      setTimeout(onComplete, 600);
    }
  }, [enabled, onAwaken, onComplete, phase, toggle]);

  const title = "QUEEN CALIFIA";
  const subtitle = "CYBERAI — SOVEREIGN CYBERSECURITY INTELLIGENCE";

  const cornerClasses = [
    "top-1 left-1 border-t-2 border-l-2",
    "top-1 right-1 border-t-2 border-r-2",
    "bottom-1 left-1 border-b-2 border-l-2",
    "bottom-1 right-1 border-b-2 border-r-2",
  ];

  return (
    <div
      className="qc-intro-root"
      onClick={handleEnter}
      style={{
        position: "fixed", inset: 0, zIndex: 50,
        display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
        overflow: "hidden", cursor: "pointer",
        background: "radial-gradient(ellipse at center, #0a0f1e 0%, #020409 70%)",
      }}
    >
      <style>{`
        @keyframes qc-pulse {
          0%, 100% { opacity: 0.6; transform: scale(1); }
          50% { opacity: 1; transform: scale(1.04); }
        }
        @keyframes qc-rotate {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        @keyframes qc-scanline {
          0% { top: -2px; opacity: 0; }
          10% { opacity: 1; }
          90% { opacity: 1; }
          100% { top: 100%; opacity: 0; }
        }
        @keyframes qc-drift {
          0%, 100% { transform: translate3d(0, 0, 0) scale(1); opacity: 0.22; }
          50% { transform: translate3d(0, -18px, 0) scale(1.06); opacity: 0.36; }
        }
        @keyframes qc-fade-shift {
          0%, 100% { opacity: 0.45; transform: translateY(0); }
          50% { opacity: 1; transform: translateY(-2px); }
        }
      `}</style>
      <canvas ref={canvasRef} style={{ position: "absolute", inset: 0, zIndex: 0 }} />

      <div style={{
        position: "absolute",
        inset: "-12%",
        zIndex: 1,
        pointerEvents: "none",
        background: "radial-gradient(circle at 50% 40%, rgba(212,175,55,0.18) 0%, rgba(6,182,212,0.08) 28%, transparent 62%)",
        filter: "blur(18px)",
        animation: "qc-drift 8s ease-in-out infinite",
      }} />

      <div style={{
        position: "absolute", inset: 0, zIndex: 1, opacity: 0.03,
        backgroundImage: `url("${CDN}/qc-hex-grid-bg-Ckjfegc53A383DCfoyh5Xe.webp")`,
        backgroundSize: "cover", backgroundPosition: "center",
      }} />

      <div style={{
        position: "absolute", inset: 0, zIndex: 10,
        background: "radial-gradient(ellipse at center, transparent 40%, #020409 100%)",
      }} />

      <div style={{
        position: "absolute",
        top: 22,
        left: 22,
        zIndex: 22,
        display: "flex",
        flexDirection: "column",
        gap: 8,
        pointerEvents: "none",
      }}>
        <div style={{
          color: "#D4AF37",
          fontSize: 10,
          letterSpacing: "0.28em",
          textTransform: "uppercase",
          fontFamily: "'JetBrains Mono', monospace",
          opacity: 0.9,
        }}>
          Sovereign Awakening Sequence
        </div>
        <div style={{
          color: "#7dd3fc",
          fontSize: 11,
          letterSpacing: "0.16em",
          textTransform: "uppercase",
          fontFamily: "'JetBrains Mono', monospace",
          animation: "qc-fade-shift 2.2s ease-in-out infinite",
        }}>
          {telemetryLines[telemetryIndex]}
        </div>
      </div>

      <div style={{
        position: "absolute",
        bottom: 24,
        left: 24,
        right: 24,
        zIndex: 22,
        display: "flex",
        justifyContent: "space-between",
        gap: 16,
        flexWrap: "wrap",
        pointerEvents: "none",
      }}>
        {[
          ["Aura", phase === "waiting" ? "Dormant" : phase === "awakening" ? "Igniting" : "Online"],
          ["Mesh", phase === "waiting" ? "Idle" : "Synced"],
          ["Voice", enabled ? "Audible" : "Muted"],
        ].map(([label, value]) => (
          <div
            key={label}
            style={{
              minWidth: 140,
              padding: "10px 12px",
              borderRadius: 10,
              border: "1px solid rgba(212,175,55,0.18)",
              background: "linear-gradient(135deg, rgba(10,15,30,0.72), rgba(2,4,9,0.42))",
              boxShadow: "0 0 30px rgba(212,175,55,0.06)",
              backdropFilter: "blur(12px)",
            }}
          >
            <div style={{ color: "#4a6080", fontSize: 9, letterSpacing: "0.24em", textTransform: "uppercase", fontFamily: "'JetBrains Mono', monospace" }}>{label}</div>
            <div style={{ color: "#d4dff0", fontSize: 13, marginTop: 4, letterSpacing: "0.08em", textTransform: "uppercase", fontFamily: "'Orbitron', sans-serif" }}>{value}</div>
          </div>
        ))}
      </div>

      <div
        style={{
          position: "absolute",
          top: 24,
          right: 24,
          zIndex: 22,
          width: 180,
          padding: "10px 12px",
          borderRadius: 12,
          border: "1px solid rgba(125,211,252,0.2)",
          background: "linear-gradient(135deg, rgba(8,18,36,0.82), rgba(2,4,9,0.45))",
          backdropFilter: "blur(14px)",
          boxShadow: "0 0 30px rgba(6,182,212,0.05)",
          pointerEvents: "none",
        }}
      >
        <div style={{ color: "#4a6080", fontSize: 9, letterSpacing: "0.22em", textTransform: "uppercase", fontFamily: "'JetBrains Mono', monospace" }}>
          Transition Matrix
        </div>
        <div style={{ marginTop: 10, display: "grid", gap: 8 }}>
          {[
            ["Phase", phase.toUpperCase()],
            ["Telemetry", telemetryLines[telemetryIndex]],
            ["Engine", enabled ? "Sonic Field Armed" : "Awaiting Audio Unlock"],
          ].map(([label, value]) => (
            <div key={label} style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
              <span style={{ color: "#7dd3fc", fontSize: 10, letterSpacing: "0.12em", textTransform: "uppercase", fontFamily: "'JetBrains Mono', monospace" }}>{label}</span>
              <span style={{ color: "#d4dff0", fontSize: 10, textAlign: "right", fontFamily: "'JetBrains Mono', monospace" }}>{value}</span>
            </div>
          ))}
        </div>
      </div>

      <AnimatePresence>
        {phase === "waiting" && (
          <motion.div key="waiting"
            style={{ position: "relative", zIndex: 20, display: "flex", flexDirection: "column", alignItems: "center", gap: 32 }}
            exit={{ opacity: 0, scale: 0.95 }} transition={{ duration: 0.5 }}>
            <motion.div animate={{ scale: [1, 1.05, 1] }} transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}>
              <div style={{ width: 96, height: 96, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", position: "relative" }}>
                <div style={{
                  position: "absolute", inset: 0, borderRadius: "50%",
                  border: "2px solid #D4AF37", opacity: 0.4,
                  animation: "qc-pulse 2.5s ease-in-out infinite",
                }} />
                <div style={{
                  position: "absolute", inset: -16, borderRadius: "50%",
                  border: "1px dashed #D4AF37", opacity: 0.2,
                  animation: "qc-rotate 12s linear infinite",
                }} />
                <img src={`${CDN}/idle_avatar_sm_6294a66d.png`} alt="Queen Califia"
                  style={{
                    width: 80, height: 80, borderRadius: "50%", objectFit: "cover",
                    border: "2px solid #D4AF37",
                    boxShadow: "0 0 30px rgba(212,175,55,0.3), 0 0 60px rgba(212,175,55,0.1)",
                  }} />
              </div>
            </motion.div>

            <motion.div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 12 }}
              animate={{ opacity: [0.5, 1, 0.5] }} transition={{ duration: 2.5, repeat: Infinity }}>
              <span style={{ color: "#D4AF37", fontSize: 12, letterSpacing: "0.3em", textTransform: "uppercase", fontFamily: "'Orbitron', sans-serif" }}>
                Initialize Sovereign Protocol
              </span>
              <div style={{
                width: 48, height: 48, borderRadius: "50%", border: "1px solid rgba(212,175,55,0.4)",
                display: "flex", alignItems: "center", justifyContent: "center",
              }}>
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                  <path d="M4 2L12 8L4 14V2Z" fill="#D4AF37" />
                </svg>
              </div>
              <span style={{ color: "#4a6080", fontSize: 10, letterSpacing: "0.2em", fontFamily: "'JetBrains Mono', monospace" }}>
                CLICK TO AWAKEN
              </span>
            </motion.div>
          </motion.div>
        )}

        {(phase === "awakening" || phase === "revealing") && (
          <motion.div key="awakening"
            style={{ position: "relative", zIndex: 20, display: "flex", flexDirection: "column", alignItems: "center", gap: 24 }}
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0, scale: 1.1 }}
            transition={{ duration: 0.6 }}>
            <motion.div initial={{ scale: 0.8, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}
              transition={{ duration: 1.2, ease: [0.16, 1, 0.3, 1] }} style={{ position: "relative" }}>
              <div style={{
                position: "absolute", inset: -32, borderRadius: "50%",
                background: "radial-gradient(circle, rgba(212,175,55,0.15) 0%, transparent 70%)",
                animation: "qc-pulse 2s ease-in-out infinite",
              }} />
              <div style={{
                position: "absolute", inset: -16, borderRadius: "50%",
                border: "2px solid #D4AF37", opacity: 0.4,
                boxShadow: "0 0 20px rgba(212,175,55,0.4), inset 0 0 20px rgba(212,175,55,0.15)",
                animation: "qc-pulse 2.5s ease-in-out infinite",
              }} />
              <div style={{
                position: "absolute", inset: -32, borderRadius: "50%",
                border: "1px dashed #D4AF37", opacity: 0.3,
                animation: "qc-rotate 8s linear infinite",
              }} />
              <img src={`${CDN}/idle_avatar_lg_d2e3a5df.png`} alt="Queen Califia — Sovereign"
                style={{
                  width: 160, height: 160, borderRadius: 12, objectFit: "cover", position: "relative", zIndex: 10,
                  border: "2px solid #D4AF37",
                  boxShadow: "0 0 40px rgba(212,175,55,0.4), 0 0 80px rgba(212,175,55,0.15)",
                }} />
              {cornerClasses.map((cls, i) => (
                <div key={i} className={`absolute w-4 h-4 border-[#D4AF37] z-20 ${cls}`} />
              ))}
              <div style={{
                position: "absolute", left: 0, right: 0, height: 2, zIndex: 20,
                background: "linear-gradient(transparent, rgba(212,175,55,0.5), transparent)",
                animation: "qc-scanline 3s linear infinite",
              }} />
            </motion.div>

            {textVisible && (
              <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }} style={{ textAlign: "center" }}>
                <h1 style={{
                  fontSize: "clamp(1.5rem, 5vw, 3rem)", fontWeight: 700, letterSpacing: "0.15em",
                  color: "#D4AF37", fontFamily: "'Orbitron', sans-serif",
                  textShadow: "0 0 30px rgba(212,175,55,0.4), 0 0 60px rgba(212,175,55,0.15)",
                }}>
                  {title.split("").map((char, i) => (
                    <motion.span key={i} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: i * 0.04, duration: 0.3 }}>{char}</motion.span>
                  ))}
                </h1>
              </motion.div>
            )}

            {subtitleVisible && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 1 }}
                style={{ fontSize: "clamp(8px, 1.2vw, 12px)", letterSpacing: "0.25em", color: "#4a6080", textAlign: "center", fontFamily: "'JetBrains Mono', monospace" }}>
                {subtitle}
              </motion.div>
            )}

            {buttonVisible && (
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5 }} style={{ marginTop: 16 }}>
                <button onClick={(e) => { e.stopPropagation(); handleEnter(); }}
                  style={{
                    padding: "12px 32px", border: "1px solid rgba(212,175,55,0.4)", borderRadius: 8,
                    background: "linear-gradient(135deg, rgba(212,175,55,0.06), rgba(125,211,252,0.04))", color: "#D4AF37", fontSize: 14, letterSpacing: "0.2em",
                    cursor: "pointer", fontFamily: "'Orbitron', sans-serif",
                    transition: "all 0.3s",
                    boxShadow: "0 0 24px rgba(212,175,55,0.08)",
                  }}
                  onMouseOver={e => { e.target.style.background = "rgba(212,175,55,0.1)"; e.target.style.borderColor = "#D4AF37"; }}
                  onMouseOut={e => { e.target.style.background = "transparent"; e.target.style.borderColor = "rgba(212,175,55,0.4)"; }}>
                  ENTER COMMAND
                </button>
                <div style={{ textAlign: "center", marginTop: 8, fontSize: 9, color: "#4a6080", letterSpacing: "0.15em", fontFamily: "'JetBrains Mono', monospace" }}>
                  DEFENSE-GRADE CYBERSECURITY INTELLIGENCE
                </div>
              </motion.div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      <div style={{
        position: "absolute", inset: 0, zIndex: 2, opacity: 0.04, pointerEvents: "none",
        backgroundImage: `url("${CDN}/qc-circuit-texture-crouTXBwBSsyVGQspVekAy.webp")`,
        backgroundSize: "cover", backgroundPosition: "center",
      }} />
    </div>
  );
}
