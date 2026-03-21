import React, { Suspense, lazy, useCallback, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import CinematicIntro from "./components/CinematicIntro.jsx";
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
        gap: 16,
        background:
          "radial-gradient(circle at center, rgba(37,99,235,0.12) 0%, rgba(6,10,20,1) 55%)",
        color: "#d4dff0",
        fontFamily: "'DM Sans', system-ui, sans-serif",
      }}
    >
      <div
        style={{
          width: 120,
          height: 120,
          borderRadius: "50%",
          border: "1px solid rgba(212,175,55,0.28)",
          boxShadow: "0 0 60px rgba(212,175,55,0.08)",
          position: "relative",
        }}
      >
        <div
          style={{
            position: "absolute",
            inset: 12,
            borderRadius: "50%",
            border: "2px dashed rgba(125,211,252,0.38)",
            animation: "qc-app-rotate 4s linear infinite",
          }}
        />
        <div
          style={{
            position: "absolute",
            inset: 34,
            borderRadius: "50%",
            background:
              "radial-gradient(circle, rgba(212,175,55,0.45) 0%, rgba(212,175,55,0.08) 55%, transparent 70%)",
            animation: "qc-app-pulse 2.2s ease-in-out infinite",
          }}
        />
      </div>
      <div style={{ fontSize: 12, letterSpacing: "0.28em", textTransform: "uppercase", color: "#7dd3fc" }}>
        {label}
      </div>
      <style>{`
        @keyframes qc-app-rotate {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        @keyframes qc-app-pulse {
          0%, 100% { transform: scale(1); opacity: 0.7; }
          50% { transform: scale(1.08); opacity: 1; }
        }
      `}</style>
    </motion.div>
  );
}

/**
 * Queen Califia CyberAI v4.1 — God-Tier Entry Point
 * Cinematic intro → Sovereign Command Dashboard
 * Set VITE_QC_USE_LEGACY_DASHBOARD=1 to render the legacy App UI instead.
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
            exit={{ opacity: 0, filter: "blur(8px)" }}
            transition={{ duration: 0.5, ease: "easeOut" }}
          >
            <CinematicIntro
              onAwaken={primeDashboard}
              onComplete={() => setIntroComplete(true)}
            />
          </motion.div>
        ) : (
          <motion.div
            key="dashboard"
            initial={{ opacity: 0, scale: 1.015, filter: "blur(10px)" }}
            animate={{ opacity: 1, scale: 1, filter: "blur(0px)" }}
            transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
          >
            <Suspense fallback={<ShellLoading label="Materializing command dashboard..." />}>
              <QueenCalifiaUnifiedCommandDashboard />
            </Suspense>
          </motion.div>
        )}
      </AnimatePresence>
    </SoundProvider>
  );
}
