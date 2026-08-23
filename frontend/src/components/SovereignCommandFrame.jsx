import React from "react";
import { motion, useReducedMotion } from "framer-motion";

export default function SovereignCommandFrame({ children }) {
  const reduce = !!useReducedMotion();
  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#010307",
        color: "#dce5f3",
        position: "relative",
        overflow: "hidden",
      }}
      data-qc-command-frame="prestige-v1"
    >
      <style>{`
        .qc-command-frame-grid{position:fixed;inset:0;pointer-events:none;z-index:0;background:linear-gradient(rgba(125,211,252,.018) 1px,transparent 1px),linear-gradient(90deg,rgba(125,211,252,.018) 1px,transparent 1px);background-size:52px 52px;mask-image:linear-gradient(to bottom,#000,transparent 82%)}
        .qc-command-surface{position:relative;z-index:1;padding:44px 10px 10px}
        @media(max-width:760px){.qc-command-surface{padding:38px 0 0}.qc-command-meta{display:none!important}}
      `}</style>
      <div className="qc-command-frame-grid" />
      <header
        style={{
          position: "fixed",
          zIndex: 20,
          left: 0,
          right: 0,
          top: 0,
          height: 36,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 16,
          padding: "0 14px",
          borderBottom: "1px solid rgba(212,175,55,.14)",
          background: "rgba(1,3,7,.86)",
          backdropFilter: "blur(18px)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
          <motion.i
            style={{
              width: 6,
              height: 6,
              borderRadius: "50%",
              background: "#d4af37",
              boxShadow: "0 0 14px rgba(212,175,55,.7)",
            }}
            animate={reduce ? {} : { opacity: [0.4, 1, 0.4] }}
            transition={{ duration: 2.6, repeat: Infinity }}
          />
          <span
            style={{
              font: "700 8px/1 'JetBrains Mono',monospace",
              letterSpacing: ".2em",
              color: "#d4af37",
            }}
          >
            QUEEN CALIFIA /// SOVEREIGN COMMAND FIELD
          </span>
        </div>
        <div
          className="qc-command-meta"
          style={{
            display: "flex",
            gap: 18,
            font: "600 8px/1 'JetBrains Mono',monospace",
            letterSpacing: ".13em",
            color: "#5e718a",
          }}
        >
          <span>HUMAN AUTHORITY: PRIMARY</span>
          <span>DECISION MODE: ASSISTIVE</span>
          <span>PROVENANCE: REQUIRED</span>
        </div>
      </header>
      <div className="qc-command-surface">{children}</div>
    </div>
  );
}
