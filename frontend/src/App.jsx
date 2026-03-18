import React, { useState } from "react";
import CinematicIntro from "./components/CinematicIntro.jsx";
import QueenCalifiaUnifiedCommandDashboard from "./QueenCalifia_Unified_Command_Dashboard.jsx";
import AppLegacy from "./AppLegacy.jsx";
import { SoundProvider } from "./contexts/SoundContext.jsx";

/**
 * Queen Califia CyberAI v4.1 ΓÇö God-Tier Entry Point
 * Cinematic intro ΓåÆ Sovereign Command Dashboard
 * Set VITE_QC_USE_LEGACY_DASHBOARD=1 to render the legacy App UI instead.
 */
export default function App() {
  const useLegacy = import.meta?.env?.VITE_QC_USE_LEGACY_DASHBOARD === "1";
  const [introComplete, setIntroComplete] = useState(false);

  if (useLegacy) return <AppLegacy />;

  return (
    <SoundProvider>
      {!introComplete ? (
        <CinematicIntro onComplete={() => setIntroComplete(true)} />
      ) : (
        <QueenCalifiaUnifiedCommandDashboard />
      )}
    </SoundProvider>
  );
}
