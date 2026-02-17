import React from "react";
import QueenCalifiaCommandDashboard from "./QueenCalifia_Unified_Command_Dashboard.jsx";
import AppLegacy from "./AppLegacy.jsx";

/**
 * Default to the Unified Command Dashboard v3.1.
 * Set VITE_QC_USE_LEGACY_DASHBOARD=1 to render the legacy App UI instead.
 */
export default function App() {
  const useLegacy = import.meta?.env?.VITE_QC_USE_LEGACY_DASHBOARD === "1";
  return useLegacy ? <AppLegacy /> : <QueenCalifiaCommandDashboard />;
}
