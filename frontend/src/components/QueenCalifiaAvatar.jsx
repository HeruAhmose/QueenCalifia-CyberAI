/**
 * Queen Califia Avatar Component — v4.1
 * Sovereign state machine with animated transitions
 * 
 * States: idle | active | ascended
 * Bonus:  hex_shield | energy_spiral | staff_raised
 */

import { useState, useEffect, useRef } from "react";
import { useSound } from "../contexts/SoundContext.jsx";

// ── Asset paths (relative to /public/qc-assets/) ──────────────────────────
const AVATAR_PATHS = {
  idle:          "/qc-assets/idle_avatar",
  active:        "/qc-assets/active_avatar",
  ascended:      "/qc-assets/ascended_avatar",
  hex_shield:    "/qc-assets/hex_shield_avatar",
  energy_spiral: "/qc-assets/energy_spiral_avatar",
  staff_raised:  "/qc-assets/staff_raised_avatar",
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

const STATE_VISUALS = {
  idle: {
    frameAnimation: "qc-avatar-breathe 5.4s ease-in-out infinite",
    auraAnimation: "qc-aura-wave 6.6s ease-in-out infinite",
    orbitDuration: "16s",
    latticeOpacity: 0.2,
    sweepOpacity: 0.18,
    beamCount: 1,
  },
  active: {
    frameAnimation: "qc-avatar-scan 2.1s cubic-bezier(0.16, 1, 0.3, 1) infinite",
    auraAnimation: "qc-aura-wave 2.6s ease-in-out infinite",
    orbitDuration: "7s",
    latticeOpacity: 0.34,
    sweepOpacity: 0.42,
    beamCount: 3,
  },
  ascended: {
    frameAnimation: "qc-avatar-ascend 2.8s ease-in-out infinite",
    auraAnimation: "qc-aura-crown 2.8s ease-in-out infinite",
    orbitDuration: "4.4s",
    latticeOpacity: 0.48,
    sweepOpacity: 0.58,
    beamCount: 4,
  },
  hex_shield: {
    frameAnimation: "qc-avatar-hex 2.2s ease-in-out infinite",
    auraAnimation: "qc-aura-shield 2.4s linear infinite",
    orbitDuration: "5.4s",
    latticeOpacity: 0.52,
    sweepOpacity: 0.48,
    beamCount: 4,
  },
  energy_spiral: {
    frameAnimation: "qc-avatar-spiral 2.4s ease-in-out infinite",
    auraAnimation: "qc-aura-wave 2.2s ease-in-out infinite",
    orbitDuration: "4.8s",
    latticeOpacity: 0.46,
    sweepOpacity: 0.44,
    beamCount: 3,
  },
  staff_raised: {
    frameAnimation: "qc-avatar-command 1.9s cubic-bezier(0.16, 1, 0.3, 1) infinite",
    auraAnimation: "qc-aura-crown 2.1s ease-in-out infinite",
    orbitDuration: "4.2s",
    latticeOpacity: 0.42,
    sweepOpacity: 0.5,
    beamCount: 5,
  },
};

// ── Avatar image with lazy-loading + fallback ──────────────────────────────
function AvatarImage({ state, size }) {
  const [loaded, setLoaded] = useState(false);
  const [src, setSrc] = useState(null);

  const suffix = size <= 200 ? "_sm" : size <= 400 ? "_md" : "_lg";
  const path = `${AVATAR_PATHS[state]}${suffix}.png`;

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
function GlowRing({ accent, glow, pulse, size, state, visuals, isAscended }) {
  const outerAnimation = visuals?.frameAnimation || (isAscended ? "qc-ascend 2s ease-in-out infinite" : "qc-pulse 2.5s ease-in-out infinite");
  const spinDuration = visuals?.orbitDuration || (isAscended ? "3s" : "8s");
  const ringInset = size < 90 ? -6 : -8;
  const spinInset = size < 90 ? -12 : -16;
  const nodeCount = Math.max(4, visuals?.beamCount ? visuals.beamCount + 2 : 4);
  const stateSweepOpacity = visuals?.sweepOpacity ?? 0.26;
  const stateLatticeOpacity = visuals?.latticeOpacity ?? 0.24;

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
        @keyframes qc-avatar-breathe {
          0%, 100% { transform: translateY(0px) scale(1); }
          50% { transform: translateY(-2px) scale(1.02); }
        }
        @keyframes qc-avatar-scan {
          0%, 100% { transform: translateY(0px) scale(1); }
          25% { transform: translateY(-2px) scale(1.05); }
          50% { transform: translateY(1px) scale(1.025); }
          75% { transform: translateY(-3px) scale(1.055); }
        }
        @keyframes qc-avatar-ascend {
          0%, 100% { transform: translateY(0px) scale(1.02); }
          50% { transform: translateY(-5px) scale(1.09); }
        }
        @keyframes qc-avatar-hex {
          0%, 100% { transform: scale(1) rotate(0deg); }
          25% { transform: scale(1.04) rotate(-1deg); }
          50% { transform: scale(1.07) rotate(0deg); }
          75% { transform: scale(1.04) rotate(1deg); }
        }
        @keyframes qc-avatar-spiral {
          0%, 100% { transform: scale(1) rotate(0deg); }
          50% { transform: scale(1.065) rotate(2deg); }
        }
        @keyframes qc-avatar-command {
          0%, 100% { transform: scale(1) translateY(0px); }
          35% { transform: scale(1.08) translateY(-4px); }
          70% { transform: scale(1.03) translateY(1px); }
        }
        @keyframes qc-aura-wave {
          0%, 100% { opacity: 0.62; transform: scale(0.96); }
          50% { opacity: 1; transform: scale(1.16); }
        }
        @keyframes qc-aura-crown {
          0%, 100% { opacity: 0.7; transform: scale(0.94); filter: blur(10px); }
          50% { opacity: 1; transform: scale(1.22); filter: blur(14px); }
        }
        @keyframes qc-aura-shield {
          0% { transform: rotate(0deg) scale(0.98); opacity: 0.72; }
          100% { transform: rotate(360deg) scale(1.12); opacity: 1; }
        }
        @keyframes qc-lattice-rotate {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        @keyframes qc-sweep-orbit {
          0% { transform: rotate(0deg); opacity: 0.18; }
          50% { opacity: 1; }
          100% { transform: rotate(360deg); opacity: 0.18; }
        }
        @keyframes qc-beam-pulse {
          0%, 100% { opacity: 0.22; transform: scaleY(0.82); }
          50% { opacity: 1; transform: scaleY(1.08); }
        }
        @keyframes qc-node-orbit {
          0%, 100% { transform: scale(0.9); opacity: 0.5; }
          50% { transform: scale(1.35); opacity: 1; }
        }
        .qc-ring-outer {
          animation: ${outerAnimation};
        }
        .qc-ring-spin {
          animation: qc-rotate ${spinDuration} linear infinite;
        }
        .qc-scanline {
          animation: qc-scanline 3s linear infinite;
        }
      `}</style>

      <div style={{
        position: "absolute",
        inset: -26,
        borderRadius: "50%",
        background: `radial-gradient(circle, ${pulse} 0%, transparent 68%)`,
        filter: "blur(12px)",
        opacity: 0.9,
        animation: visuals?.auraAnimation || "qc-aura-wave 4.8s ease-in-out infinite",
        pointerEvents: "none",
      }} />

      <div style={{
        position: "absolute",
        inset: -20,
        borderRadius: "50%",
        background: `repeating-conic-gradient(from 0deg, ${accent}00 0deg 18deg, ${accent}55 18deg 26deg, ${accent}00 26deg 60deg)`,
        opacity: stateLatticeOpacity,
        mixBlendMode: "screen",
        animation: `qc-lattice-rotate ${spinDuration} linear infinite`,
        pointerEvents: "none",
      }} />

      <div style={{
        position: "absolute",
        inset: -24,
        borderRadius: "50%",
        background: `conic-gradient(from 180deg, transparent 0deg, ${accent}00 52deg, ${accent}90 92deg, transparent 132deg, ${accent}00 220deg, ${accent}65 280deg, transparent 325deg, ${accent}00 360deg)`,
        opacity: stateSweepOpacity,
        filter: "blur(2px)",
        animation: `qc-sweep-orbit ${spinDuration} linear infinite`,
        pointerEvents: "none",
      }} />

      {/* Outer pulse ring */}
      <div className="qc-ring-outer" style={{
        position: "absolute", inset: ringInset,
        borderRadius: "50%",
        border: `2px solid ${accent}`,
        boxShadow: `0 0 20px ${glow}, inset 0 0 20px ${pulse}, 0 0 42px ${pulse}`,
        pointerEvents: "none",
      }} />

      {/* Spinning dashed ring */}
      <div className="qc-ring-spin" style={{
        position: "absolute", inset: spinInset,
        borderRadius: "50%",
        border: `1px dashed ${accent}`,
        opacity: state === "idle" ? 0.28 : 0.48,
        pointerEvents: "none",
      }} />

      {/* Corner accent dots */}
      {Array.from({ length: nodeCount }, (_, idx) => Math.round((360 / nodeCount) * idx)).map((deg, idx) => (
        <div key={deg} style={{
          position: "absolute",
          width: state === "staff_raised" ? 7 : 6,
          height: state === "staff_raised" ? 7 : 6,
          borderRadius: "50%",
          background: accent,
          boxShadow: `0 0 8px ${accent}`,
          top: "50%", left: "50%",
          transform: `rotate(${deg}deg) translateY(-${size / 2 + 20}px) translate(-50%, -50%)`,
          animation: `qc-node-orbit ${Math.max(1.2, 2.4 + idx * 0.16)}s ease-in-out infinite`,
          animationDelay: `${idx * 120}ms`,
          opacity: 0.9,
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
  const { play } = useSound();

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
  const visuals = STATE_VISUALS[activeState] || STATE_VISUALS.idle;
  const isAscended = activeState === "ascended";

  useEffect(() => {
    if (prevState.current !== activeState) {
      setTransitioning(true);
      play("avatar_transition");
      const t = setTimeout(() => setTransitioning(false), 400);
      prevState.current = activeState;
      return () => clearTimeout(t);
    }
  }, [activeState, play]);

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
        animation: visuals.frameAnimation,
      }}>
        {/* Background glow */}
        <div style={{
          position: "absolute", inset: -20,
          background: `radial-gradient(circle, ${meta.pulse} 0%, transparent 70%)`,
          borderRadius: "50%",
          pointerEvents: "none",
          transition: "background 0.6s ease",
          animation: visuals.auraAnimation,
        }} />

        {Array.from({ length: visuals.beamCount }, (_, idx) => (
          <div key={`beam-${idx}`} style={{
            position: "absolute",
            top: size * 0.08,
            bottom: size * 0.08,
            left: `${22 + idx * (52 / Math.max(1, visuals.beamCount - 1 || 1))}%`,
            width: Math.max(2, Math.round(size * 0.022)),
            borderRadius: 999,
            background: `linear-gradient(180deg, transparent, ${meta.accent}90, transparent)`,
            boxShadow: `0 0 14px ${meta.glow}`,
            opacity: visuals.sweepOpacity,
            mixBlendMode: "screen",
            transformOrigin: "center",
            animation: `qc-beam-pulse ${1.1 + idx * 0.18}s ease-in-out infinite`,
            animationDelay: `${idx * 120}ms`,
            pointerEvents: "none",
          }} />
        ))}

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

          <div style={{
            position: "absolute",
            inset: 0,
            background: `linear-gradient(130deg, ${meta.accent}00 0%, ${meta.accent}18 28%, transparent 42%, transparent 100%)`,
            opacity: visuals.sweepOpacity,
            mixBlendMode: "screen",
            pointerEvents: "none",
          }} />

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
            state={activeState}
            visuals={visuals}
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
