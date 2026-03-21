/**
 * Queen Califia CyberAI — Sound Context v4.1
 * Provides sound toggle and play functions to all components
 */
import React, { createContext, useContext, useState, useCallback } from "react";
import { playSound, setMasterVolume, startAmbient, stopAmbient } from "../lib/SoundEngine.js";

const SoundContext = createContext({
  enabled: false,
  toggle: () => {},
  play: () => {},
});

export function SoundProvider({ children }) {
  const [enabled, setEnabled] = useState(() => {
    try {
      return window.localStorage?.getItem("qc_audio_enabled") === "1";
    } catch {
      return false;
    }
  });

  const toggle = useCallback(() => {
    setEnabled(prev => {
      const next = !prev;
      try {
        window.localStorage?.setItem("qc_audio_enabled", next ? "1" : "0");
      } catch {}
      if (next) {
        setMasterVolume(0.3);
        startAmbient();
      } else {
        setMasterVolume(0);
        stopAmbient();
      }
      return next;
    });
  }, []);

  const play = useCallback(
    (type) => {
      if (enabled) playSound(type);
    },
    [enabled]
  );

  return (
    <SoundContext.Provider value={{ enabled, toggle, play }}>
      {children}
    </SoundContext.Provider>
  );
}

export function useSound() {
  return useContext(SoundContext);
}
