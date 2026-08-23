import React, { Suspense, lazy, useCallback, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import SovereignAwakening from "./components/SovereignAwakening.jsx";
import SovereignCommandFrame from "./components/SovereignCommandFrame.jsx";
import { SoundProvider } from "./contexts/SoundContext.jsx";

const loadDashboard = () => import("./QueenCalifia_Unified_Command_Dashboard.jsx");
const loadLegacy = () => import("./AppLegacy.jsx");
const loadTrainingConsole = () => import("./panels/QCTrainingConsole.jsx");

const QueenCalifiaUnifiedCommandDashboard = lazy(loadDashboard);
const AppLegacy = lazy(loadLegacy);
const QCTrainingConsole = lazy(loadTrainingConsole);

function ShellLoading({ label = "Linking sovereign systems..." }) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      style={{
        minHeight: "100vh",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: 18,
        background:
          "radial-gradient(circle at 50% 43%, rgba(212,175,55,0.08), transparent 24%), radial-gradient(circle at center, rgba(14,116,144,0.08) 0%, #020407 58%)",
        color: "#dce5f3",
        fontFamily: "'DM Sans', system-ui, sans-serif",
      }}
    >
      <div style={{ width: 132, height: 132, position: "relative" }}>
        <motion.div
          style={{ position: "absolute", inset: 0, borderRadius: "50%", border: "1px solid rgba(212,175,55,.28)" }}
          animate={{ rotate: 360 }}
          transition={{ duration: 16, repeat: Infinity, ease: "linear" }}
        />
        <motion.div
          style={{ position: "absolute", inset: 16, borderRadius: "50%", border: "1px dashed rgba(125,211,252,.28)" }}
          animate={{ rotate: -360 }}
          transition={{ duration: 12, repeat: Infinity, ease: "linear" }}
        />
        <div style={{ position: "absolute", inset: 42, display: "grid", placeItems: "center", borderRadius: "50%", background: "#050910", border: "1px solid rgba(212,175,55,.26)", boxShadow: "0 0 54px rgba(212,175,55,.08)" }}>
          <span style={{ font: "700 21px/1 Georgia,serif", color: "#d4af37" }}>QC</span>
        </div>
      </div>
      <div style={{ font: "600 10px/1.4 'JetBrains Mono',monospace", letterSpacing: ".22em", textTransform: "uppercase", color: "#7dd3fc" }}>{label}</div>
      <div style={{ font: "500 8px/1.4 'JetBrains Mono',monospace", letterSpacing: ".16em", color: "#536984" }}>HUMAN AUTHORITY · SOURCE PROVENANCE · DEFENSIBLE DECISIONS</div>
    </motion.div>
  );
}

/**
 * Queen Califia CyberAI — sovereign prestige entry point.
 * The public UI may evolve independently from production authorization: this
 * shell does not bypass the sovereign edge runtime gate or alter deployment
 * authority.
 */
export default function App() {
  const useLegacy = import.meta?.env?.VITE_QC_USE_LEGACY_DASHBOARD === "1";
  const trainingConsole =
    typeof window !== "undefined" &&
    (new URLSearchParams(window.location.search).get("qc_training") === "1" ||
      import.meta?.env?.VITE_QC_TRAINING_CONSOLE === "1");
  const [introComplete, setIntroComplete] = useState(false);
  const primeDashboard = useCallback(() => {
    void loadDashboard();
  }, []);

  if (trainingConsole) {
    return (
      <Suspense fallback={<ShellLoading label="Loading training command center..." />}>
        <QCTrainingConsole />
      </Suspense>
    );
  }

  if (useLegacy) {
    return (
      <SoundProvider>
        <Suspense fallback={<ShellLoading label="Recovering legacy command stack..." />}>
          <AppLegacy />
        </Suspense>
      </SoundProvider>
    );
  }

  return (
    <SoundProvider>
      <AnimatePresence mode="wait">
        {!introComplete ? (
          <motion.div
            key="intro"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0, filter: "blur(10px)", scale: 1.02 }}
            transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
          >
            <SovereignAwakening
              onAwaken={primeDashboard}
              onComplete={() => setIntroComplete(true)}
            />
          </motion.div>
        ) : (
          <motion.div
            key="dashboard"
            initial={{ opacity: 0, scale: 1.012, filter: "blur(12px)" }}
            animate={{ opacity: 1, scale: 1, filter: "blur(0px)" }}
            transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
          >
            <SovereignCommandFrame>
              <Suspense fallback={<ShellLoading label="Materializing command field..." />}>
                <QueenCalifiaUnifiedCommandDashboard />
              </Suspense>
            </SovereignCommandFrame>
          </motion.div>
        )}
      </AnimatePresence>
    </SoundProvider>
  );
}
