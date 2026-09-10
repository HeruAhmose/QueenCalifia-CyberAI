import React, { useCallback, useEffect, useRef, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import QueenCalifiaAvatar from "./QueenCalifiaAvatar.jsx";
import { useSound } from "../contexts/SoundContext.jsx";
import {
  playSound,
  setMasterVolume,
  startAmbient,
} from "../lib/SoundEngine.js";

const states = [
  ["IDENTITY", "SOVEREIGN"],
  ["THREAT MESH", "STANDBY"],
  ["RESEARCH", "LINKED"],
  ["HUMAN AUTHORITY", "REQUIRED"],
];

const AVATAR_STATE_BY_PHASE = {
  sealed: "idle",
  linking: "active",
  authorized: "staff_raised",
  entering: "ascended",
};

export default function SovereignAwakening({ onComplete, onAwaken }) {
  const reduce = !!useReducedMotion();
  const [phase, setPhase] = useState("sealed");
  const [signal, setSignal] = useState(0);
  const timerRef = useRef([]);
  const { toggle, enabled } = useSound();

  useEffect(() => () => timerRef.current.forEach(clearTimeout), []);
  useEffect(() => {
    const timer = setInterval(
      () => setSignal((v) => (v + 1) % states.length),
      1900,
    );
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!reduce) return;
    onAwaken?.();
    onComplete?.();
  }, [reduce, onAwaken, onComplete]);

  const awaken = useCallback(() => {
    if (phase === "sealed") {
      if (!enabled) toggle();
      else {
        setMasterVolume(0.26);
        startAmbient();
      }
      playSound("sovereign_awaken");
      onAwaken?.();
      setPhase("linking");
      timerRef.current.push(setTimeout(() => setPhase("authorized"), 1700));
      return;
    }
    if (phase === "authorized") {
      playSound("button_click");
      setPhase("entering");
      timerRef.current.push(setTimeout(onComplete, 650));
    }
  }, [enabled, onAwaken, onComplete, phase, toggle]);

  if (reduce) return null;

  const ready = phase === "authorized";
  const active = phase !== "sealed";
  const avatarState = AVATAR_STATE_BY_PHASE[phase] ?? "idle";

  return (
    <main
      className="qc-sovereign-awakening"
      data-qc-awakening-phase={phase}
      data-qc-awakening-avatar-state={avatarState}
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 100,
        overflow: "hidden",
        color: "#e8edf7",
        background: "#020407",
        fontFamily: "'DM Sans', system-ui, sans-serif",
      }}
    >
      <style>{`
        .qc-sovereign-awakening:before{content:"";position:absolute;inset:0;pointer-events:none;background:linear-gradient(rgba(125,211,252,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(125,211,252,.025) 1px,transparent 1px);background-size:48px 48px;mask-image:radial-gradient(circle at 50% 48%,#000,transparent 72%)}
        .qc-sovereign-awakening:after{content:"";position:absolute;inset:0;pointer-events:none;background:radial-gradient(circle at 50% 42%,rgba(212,175,55,.12),transparent 20%),radial-gradient(circle at 50% 48%,rgba(14,116,144,.09) 0%,transparent 44%),linear-gradient(180deg,transparent,rgba(0,0,0,.42))}
        .qc-seal-line{position:absolute;left:50%;top:50%;width:1px;height:42%;transform-origin:center top;background:linear-gradient(#d4af37,transparent);opacity:.15}
        .qc-awaken-portrait{width:238px;height:238px;margin:0 auto 26px;position:relative;display:grid;place-items:center;isolation:isolate}
        .qc-awaken-portrait:before{content:"";position:absolute;inset:-20px;border-radius:50%;background:radial-gradient(circle,rgba(0,220,250,.08),transparent 65%);filter:blur(14px);pointer-events:none}
        .qc-awaken-holo-scan{position:absolute;z-index:6;left:16px;right:16px;height:1px;background:linear-gradient(90deg,transparent,rgba(125,211,252,.9),transparent);box-shadow:0 0 14px rgba(125,211,252,.5);mix-blend-mode:screen;pointer-events:none;animation:qc-awaken-holo-scan 3.8s ease-in-out infinite}
        .qc-awaken-phase-chip{position:absolute;z-index:8;left:50%;bottom:-4px;transform:translateX(-50%);white-space:nowrap;border:1px solid rgba(212,175,55,.32);background:rgba(2,4,7,.82);backdrop-filter:blur(12px);padding:5px 9px;font:700 8px/1 'JetBrains Mono',monospace;letter-spacing:.18em;color:#d4af37;text-transform:uppercase}
        @keyframes qc-awaken-holo-scan{0%,100%{top:18%;opacity:.12}50%{top:80%;opacity:.72}}
        @media(max-width:760px){.qc-awaken-telemetry{display:none!important}.qc-awaken-status{grid-template-columns:1fr 1fr!important}.qc-awaken-card{width:min(90vw,26rem)!important}.qc-awaken-portrait{transform:scale(.86);margin-bottom:6px}.qc-awaken-card h1{font-size:clamp(2.35rem,13vw,3.7rem)!important}.qc-awaken-card button{margin-top:24px!important}}
        @media(max-height:700px){.qc-awaken-status{display:none!important}.qc-awaken-portrait{transform:scale(.76);margin-top:-24px;margin-bottom:-18px}.qc-awaken-card button{margin-top:18px!important}}
      `}</style>

      {[0, 45, 90, 135].map((deg) => (
        <motion.i
          key={deg}
          className="qc-seal-line"
          style={{ rotate: `${deg}deg` }}
          animate={{ opacity: active ? [0.1, 0.34, 0.1] : 0.1 }}
          transition={{ duration: 3.6, repeat: Infinity, delay: deg / 180 }}
        />
      ))}

      <div
        className="qc-awaken-telemetry"
        style={{ position: "absolute", left: 28, top: 28, zIndex: 4 }}
      >
        <div
          style={{
            font: "600 9px/1.4 'JetBrains Mono',monospace",
            letterSpacing: ".26em",
            color: "#d4af37",
          }}
        >
          QUEEN CALIFIA /// SOVEREIGN COGNITIVE DEFENSE
        </div>
        <div
          style={{
            marginTop: 9,
            font: "500 10px/1.5 'JetBrains Mono',monospace",
            letterSpacing: ".12em",
            color: "#66809d",
          }}
        >
          CEREMONIAL ACCESS LAYER · HUMAN AUTHORITY PRESERVED
        </div>
      </div>

      <div
        className="qc-awaken-telemetry"
        style={{
          position: "absolute",
          right: 28,
          top: 28,
          zIndex: 4,
          width: 230,
          padding: "14px 16px",
          border: "1px solid rgba(125,211,252,.14)",
          background: "rgba(4,8,14,.72)",
          backdropFilter: "blur(18px)",
        }}
      >
        <div
          style={{
            font: "600 8px/1.3 'JetBrains Mono',monospace",
            letterSpacing: ".22em",
            color: "#66809d",
          }}
        >
          INTELLIGENCE STATE
        </div>
        <AnimatePresence mode="wait">
          <motion.div
            key={signal}
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -5 }}
            style={{
              display: "flex",
              justifyContent: "space-between",
              gap: 14,
              marginTop: 10,
              font: "600 10px/1.4 'JetBrains Mono',monospace",
            }}
          >
            <span style={{ color: "#7dd3fc" }}>{states[signal][0]}</span>
            <span style={{ color: "#d6deec", textAlign: "right" }}>
              {states[signal][1]}
            </span>
          </motion.div>
        </AnimatePresence>
      </div>

      <div
        style={{
          position: "relative",
          zIndex: 5,
          minHeight: "100vh",
          display: "grid",
          placeItems: "center",
          padding: 24,
        }}
      >
        <motion.section
          className="qc-awaken-card"
          style={{ width: "min(78vw, 34rem)", textAlign: "center" }}
          animate={
            phase === "entering"
              ? { opacity: 0, scale: 1.04, filter: "blur(12px)" }
              : { opacity: 1, scale: 1, filter: "blur(0px)" }
          }
        >
          <motion.div
            className="qc-awaken-portrait"
            data-qc-sovereign-portrait="active-awakening"
            initial={{ opacity: 0, scale: 0.94 }}
            animate={{
              opacity: 1,
              scale: active ? [1, 1.012, 1] : 1,
              y: active ? [0, -3, 0] : 0,
            }}
            transition={{
              opacity: { duration: 0.65 },
              scale: active
                ? { duration: 4.6, repeat: Infinity, ease: "easeInOut" }
                : { duration: 0.65 },
              y: active
                ? { duration: 4.6, repeat: Infinity, ease: "easeInOut" }
                : { duration: 0.65 },
            }}
          >
            <QueenCalifiaAvatar
              state={avatarState}
              size={190}
              showLabel={false}
              showStatus={false}
              showDescription={false}
              style={{ pointerEvents: "none", cursor: "default", zIndex: 4 }}
            />
            <span className="qc-awaken-holo-scan" aria-hidden="true" />
            <span className="qc-awaken-phase-chip" aria-hidden="true">
              {avatarState === "idle"
                ? "SENTINEL"
                : avatarState === "active"
                  ? "DEFENSE ACTIVE"
                  : avatarState === "staff_raised"
                    ? "AUTHORITY"
                    : "ASCENDED"}
            </span>
          </motion.div>

          <p
            style={{
              margin: 0,
              font: "600 9px/1.4 'JetBrains Mono',monospace",
              letterSpacing: ".3em",
              color: ready ? "#7dd3fc" : "#d4af37",
            }}
          >
            {phase === "sealed"
              ? "SOVEREIGN IDENTITY /// SENTINEL"
              : phase === "linking"
                ? "INTELLIGENCE LATTICE /// LINKING"
                : phase === "authorized"
                  ? "HUMAN AUTHORITY /// ACKNOWLEDGED"
                  : "COMMAND FIELD /// MATERIALIZING"}
          </p>
          <h1
            style={{
              margin: "16px 0 0",
              font: "700 clamp(2.6rem,8vw,5rem)/.9 Georgia,serif",
              letterSpacing: "-.045em",
              color: "#f3eee3",
            }}
          >
            Queen Califia
          </h1>
          <p
            style={{
              margin: "12px auto 0",
              maxWidth: 520,
              font: "500 11px/1.65 'JetBrains Mono',monospace",
              letterSpacing: ".12em",
              color: "#8091aa",
            }}
          >
            SOVEREIGN CYBERSECURITY INTELLIGENCE · RESEARCH ORCHESTRATION ·
            DEFENSIBLE HUMAN-IN-THE-LOOP DECISION SYSTEMS
          </p>

          <button
            type="button"
            onClick={awaken}
            disabled={phase === "linking" || phase === "entering"}
            style={{
              marginTop: 32,
              minWidth: 250,
              padding: "14px 20px",
              border: `1px solid ${ready ? "rgba(125,211,252,.48)" : "rgba(212,175,55,.42)"}`,
              background: ready
                ? "linear-gradient(135deg,rgba(125,211,252,.08),rgba(212,175,55,.035))"
                : "linear-gradient(135deg,rgba(212,175,55,.08),rgba(8,13,22,.8))",
              color: ready ? "#bde9f8" : "#eadca6",
              font: "700 10px/1 'JetBrains Mono',monospace",
              letterSpacing: ".2em",
              cursor: phase === "linking" ? "wait" : "pointer",
              opacity: phase === "linking" ? 0.6 : 1,
            }}
          >
            {phase === "sealed"
              ? "AWAKEN SOVEREIGN INTELLIGENCE"
              : phase === "linking"
                ? "LINKING INTELLIGENCE LATTICE…"
                : "ENTER COMMAND FIELD"}
          </button>
        </motion.section>
      </div>

      <div
        className="qc-awaken-status"
        style={{
          position: "absolute",
          zIndex: 5,
          left: 28,
          right: 28,
          bottom: 24,
          display: "grid",
          gridTemplateColumns: "repeat(4,1fr)",
          gap: 8,
        }}
      >
        {states.map(([label, value], index) => (
          <div
            key={label}
            style={{
              borderTop: `1px solid ${index <= signal && active ? "rgba(212,175,55,.38)" : "rgba(255,255,255,.08)"}`,
              paddingTop: 8,
            }}
          >
            <div
              style={{
                font: "600 8px/1.3 'JetBrains Mono',monospace",
                letterSpacing: ".16em",
                color: "#526984",
              }}
            >
              {label}
            </div>
            <div
              style={{
                marginTop: 4,
                font: "600 9px/1.3 'JetBrains Mono',monospace",
                color: index <= signal && active ? "#d4af37" : "#8b99ad",
              }}
            >
              {value}
            </div>
          </div>
        ))}
      </div>
    </main>
  );
}
