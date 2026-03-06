/**
 * Queen Califia Avatar Component — v4.1
 * Sovereign state machine with animated transitions
 * 
 * States: idle | active | ascended
 * Bonus:  hex_shield | energy_spiral | staff_raised
 */

import { useState, useEffect, useRef } from "react";

// ── CDN-hosted avatar assets ──────────────────────────────────────────────
const CDN = "https://d2xsxph8kpxj0f.cloudfront.net/310419663029216973/6A6PRiSc2SBdMKdQGVopRa";

const AVATAR_CDN = {
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
  idle: {
    label:       "QC::READY",
    status:      "SENTINEL MODE",
    accent:      "#D4AF37",
    glow:        "rgba(212,175,55,0.4)",
    pulse:       "rgba(212,175,55,0.15)",
    description: "Monitoring for threats",
  },
  active: {
    label:       "QC::ACTIVE",
    status:      "DEFENSE ACTIVE",
    accent:      "#00DCFA",
    glow:        "rgba(0,220,250,0.4)",
    pulse:       "rgba(0,220,250,0.15)",
    description: "Processing & defending",
  },
  ascended: {
    label:       "QC::ASCENDED",
    status:      "ANCESTORS ONLINE",
    accent:      "#FFE178",
    glow:        "rgba(255,225,120,0.5)",
    pulse:       "rgba(255,225,120,0.2)",
    description: "Critical threat — full power",
  },
  hex_shield: {
    label:       "QC::SHIELDED",
    status:      "HEX SHIELD ACTIVE",
    accent:      "#00DCFA",
    glow:        "rgba(0,220,250,0.4)",
    pulse:       "rgba(0,220,250,0.15)",
    description: "Cyber defense engaged",
  },
  energy_spiral: {
    label:       "QC::CASTING",
    status:      "ENERGY SPIRAL",
    accent:      "#D4AF37",
    glow:        "rgba(212,175,55,0.4)",
    pulse:       "rgba(212,175,55,0.15)",
    description: "Active spellcasting",
  },
  staff_raised: {
    label:       "QC::COMMAND",
    status:      "AUTHORITY MODE",
    accent:      "#FFE178",
    glow:        "rgba(255,225,120,0.5)",
    pulse:       "rgba(255,225,120,0.2)",
    description: "Command & control",
  },
};

// ── Avatar image with lazy-loading + fallback ──────────────────────────────
function AvatarImage({ state, size }) {
  const [loaded, setLoaded] = useState(false);
  const [src, setSrc] = useState(null);

  const sizeKey = size <= 200 ? "sm" : size <= 400 ? "md" : "lg";
  const path = AVATAR_CDN[state]?.[sizeKey] || AVATAR_CDN.idle[sizeKey];

  useEffect(() => {
    setLoaded(false);
    setSrc(path);
  }, [path]);

  return (
    <div style={{ position: "relative", width: size, height: size }}>
      {!loaded && (
        <div style={{
          position: "absolute", inset: 0,
          background: "radial-gradient(circle, rgba(212,175,55,0.1) 0%, transparent 70%)",
          display: "flex", alignItems: "center", justifyContent: "center",
          fontSize: 24,
        }}>
          👁
        </div>
      )}
      <img
        src={src}
        alt={`Queen Califia — ${state}`}
        onLoad={() => setLoaded(true)}
        style={{
          width: size, height: size,
          objectFit: "cover",
          opacity: loaded ? 1 : 0,
          transition: "opacity 0.4s ease",
          display: "block",
        }}
      />
    </div>
  );
}

// ── Animated glow ring ─────────────────────────────────────────────────────
function GlowRing({ accent, glow, pulse, size, isAscended }) {
  return (
    <>
      <style>{`
        @keyframes qc-pulse {
          0%, 100% { opacity: 0.6; transform: scale(1); }
          50%       { opacity: 1;   transform: scale(1.04); }
        }
        @keyframes qc-rotate {
          from { transform: rotate(0deg); }
          to   { transform: rotate(360deg); }
        }
        @keyframes qc-ascend {
          0%, 100% { opacity: 0.8; transform: scale(1)   rotate(0deg); }
          50%      { opacity: 1;   transform: scale(1.06) rotate(180deg); }
        }
        @keyframes qc-scanline {
          0%   { top: -2px; opacity: 0; }
          10%  { opacity: 1; }
          90%  { opacity: 1; }
          100% { top: 100%; opacity: 0; }
        }
        .qc-ring-outer {
          animation: ${isAscended ? "qc-ascend 2s ease-in-out infinite" : "qc-pulse 2.5s ease-in-out infinite"};
        }
        .qc-ring-spin {
          animation: qc-rotate ${isAscended ? "3s" : "8s"} linear infinite;
        }
        .qc-scanline {
          animation: qc-scanline 3s linear infinite;
        }
      `}</style>

      {/* Outer pulse ring */}
      <div className="qc-ring-outer" style={{
        position: "absolute", inset: -8,
        borderRadius: "50%",
        border: `2px solid ${accent}`,
        boxShadow: `0 0 20px ${glow}, inset 0 0 20px ${pulse}`,
        pointerEvents: "none",
      }} />

      {/* Spinning dashed ring */}
      <div className="qc-ring-spin" style={{
        position: "absolute", inset: -16,
        borderRadius: "50%",
        border: `1px dashed ${accent}`,
        opacity: 0.4,
        pointerEvents: "none",
      }} />

      {/* Corner accent dots */}
      {[0, 90, 180, 270].map(deg => (
        <div key={deg} style={{
          position: "absolute",
          width: 6, height: 6,
          borderRadius: "50%",
          background: accent,
          boxShadow: `0 0 8px ${accent}`,
          top: "50%", left: "50%",
          transform: `rotate(${deg}deg) translateY(-${size / 2 + 20}px) translate(-50%, -50%)`,
          pointerEvents: "none",
        }} />
      ))}
    </>
  );
}

// ── All states in cycle order for dev mode ────────────────────────────────
const ALL_STATES = ["idle", "active", "ascended", "hex_shield", "energy_spiral", "staff_raised"];

// ── Main Avatar Component ──────────────────────────────────────────────────
export default function QueenCalifiaAvatar({
  state = "idle",
  size = 200,
  showLabel = true,
  showStatus = true,
  showDescription = false,
  onClick = null,
  className = "",
  style = {},
}) {
  const prevState = useRef(state);
  const [transitioning, setTransitioning] = useState(false);

  // ── Dev mode easter egg ──────────────────────────────────────────────────
  const [devMode, setDevMode]           = useState(false);
  const [devStateIdx, setDevStateIdx]   = useState(0);
  const [clickCount, setClickCount]     = useState(0);
  const [devToast, setDevToast]         = useState("");
  const clickTimer                      = useRef(null);

  const handleAvatarClick = (e) => {
    e.stopPropagation();

    if (devMode) {
      // Cycle to next state
      const next = (devStateIdx + 1) % ALL_STATES.length;
      setDevStateIdx(next);
      setDevToast(ALL_STATES[next].toUpperCase().replace("_", " "));
      clearTimeout(clickTimer.current);
      clickTimer.current = setTimeout(() => setDevToast(""), 1500);
      return;
    }

    // Count rapid clicks
    const newCount = clickCount + 1;
    setClickCount(newCount);
    clearTimeout(clickTimer.current);

    if (newCount >= 5) {
      setDevMode(true);
      setDevStateIdx(ALL_STATES.indexOf(activeState));
      setClickCount(0);
      setDevToast("⚡ DEV MODE — click to cycle states");
      clickTimer.current = setTimeout(() => setDevToast(""), 2500);
    } else {
      clickTimer.current = setTimeout(() => setClickCount(0), 800);
    }

    onClick && onClick(e);
  };

  // Hold Escape to exit dev mode
  useEffect(() => {
    const handler = (e) => {
      if (e.key === "Escape" && devMode) {
        setDevMode(false);
        setClickCount(0);
        setDevToast("Dev mode off");
        setTimeout(() => setDevToast(""), 1200);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [devMode]);

  const activeState = devMode ? ALL_STATES[devStateIdx] : (state || "idle");
  const meta = STATE_META[activeState] || STATE_META.idle;
  const isAscended = activeState === "ascended";

  useEffect(() => {
    if (prevState.current !== activeState) {
      setTransitioning(true);
      const t = setTimeout(() => setTransitioning(false), 400);
      prevState.current = activeState;
      return () => clearTimeout(t);
    }
  }, [activeState]);

  const borderRadius = size < 150 ? size / 4 : size / 5;

  return (
    <div
      className={className}
      onClick={handleAvatarClick}
      style={{
        display: "inline-flex",
        flexDirection: "column",
        alignItems: "center",
        gap: 10,
        cursor: "pointer",
        userSelect: "none",
        position: "relative",
        ...style,
      }}
    >
      {/* Dev mode toast */}
      {devToast && (
        <div style={{
          position: "absolute", top: -36, left: "50%",
          transform: "translateX(-50%)",
          background: devMode ? "rgba(0,220,250,0.15)" : "rgba(212,175,55,0.15)",
          border: `1px solid ${devMode ? "#00DCFA" : "#D4AF37"}`,
          color: devMode ? "#00DCFA" : "#D4AF37",
          padding: "4px 10px", borderRadius: 4,
          fontSize: 10, fontFamily: "monospace",
          whiteSpace: "nowrap", zIndex: 999,
          animation: "qc-pulse 1s ease-in-out infinite",
        }}>
          {devToast}
        </div>
      )}

      {/* Dev mode indicator dot */}
      {devMode && (
        <div style={{
          position: "absolute", top: 4, right: 4,
          width: 8, height: 8, borderRadius: "50%",
          background: "#00DCFA",
          boxShadow: "0 0 8px #00DCFA",
          zIndex: 10,
          animation: "qc-pulse 1s ease-in-out infinite",
        }} />
      )}
      {/* Avatar frame */}
      <div style={{
        position: "relative",
        width: size,
        height: size,
      }}>
        {/* Background glow */}
        <div style={{
          position: "absolute", inset: -20,
          background: `radial-gradient(circle, ${meta.pulse} 0%, transparent 70%)`,
          borderRadius: "50%",
          pointerEvents: "none",
          transition: "background 0.6s ease",
        }} />

        {/* Avatar clip frame */}
        <div style={{
          position: "relative",
          width: size, height: size,
          borderRadius,
          overflow: "hidden",
          border: `2px solid ${meta.accent}`,
          boxShadow: `0 0 30px ${meta.glow}, 0 0 60px ${meta.pulse}`,
          transition: "border-color 0.5s ease, box-shadow 0.5s ease",
          opacity: transitioning ? 0 : 1,
          transform: transitioning ? "scale(0.97)" : "scale(1)",
          transitionProperty: "opacity, transform, border-color, box-shadow",
          transitionDuration: transitioning ? "0.15s" : "0.4s",
        }}>
          <AvatarImage state={activeState} size={size} />

          {/* Scanline effect */}
          <div className="qc-scanline" style={{
            position: "absolute",
            left: 0, right: 0,
            height: 2,
            background: `linear-gradient(transparent, ${meta.accent}80, transparent)`,
            pointerEvents: "none",
          }} />

          {/* Corner brackets */}
          {[
            { top: 4, left: 4, borderTop: `2px solid ${meta.accent}`, borderLeft: `2px solid ${meta.accent}` },
            { top: 4, right: 4, borderTop: `2px solid ${meta.accent}`, borderRight: `2px solid ${meta.accent}` },
            { bottom: 4, left: 4, borderBottom: `2px solid ${meta.accent}`, borderLeft: `2px solid ${meta.accent}` },
            { bottom: 4, right: 4, borderBottom: `2px solid ${meta.accent}`, borderRight: `2px solid ${meta.accent}` },
          ].map((s, i) => (
            <div key={i} style={{
              position: "absolute", width: 12, height: 12,
              ...s, pointerEvents: "none",
            }} />
          ))}
        </div>

        {/* Glow rings */}
        {size >= 100 && (
          <GlowRing
            accent={meta.accent}
            glow={meta.glow}
            pulse={meta.pulse}
            size={size}
            isAscended={isAscended}
          />
        )}
      </div>

      {/* Label */}
      {showLabel && (
        <div style={{
          fontFamily: "'Courier New', monospace",
          fontSize: Math.max(9, size * 0.06),
          fontWeight: 700,
          letterSpacing: "0.15em",
          color: meta.accent,
          textShadow: `0 0 10px ${meta.glow}`,
          transition: "color 0.5s ease, text-shadow 0.5s ease",
        }}>
          {devMode ? `[DEV] ${meta.label}` : meta.label}
        </div>
      )}

      {/* Status */}
      {showStatus && (
        <div style={{
          fontFamily: "'Courier New', monospace",
          fontSize: Math.max(8, size * 0.05),
          color: "#4a6080",
          letterSpacing: "0.1em",
        }}>
          {meta.status}
        </div>
      )}

      {/* Description */}
      {showDescription && (
        <div style={{
          fontSize: Math.max(9, size * 0.05),
          color: "#6a7a90",
          textAlign: "center",
          maxWidth: size,
        }}>
          {meta.description}
        </div>
      )}
    </div>
  );
}

// ── Export state inferrer for dashboard integration ────────────────────────
export function inferQCState({ isScanning, isCritical, isRemediating, riskLevel, predictions }) {
  if (isCritical || (riskLevel >= 9) || (predictions?.high_risk > 0)) return "ascended";
  if (isScanning || isRemediating || riskLevel >= 7) return "active";
  return "idle";
}

// STATE_META and AVATAR_PATHS available via import of module
