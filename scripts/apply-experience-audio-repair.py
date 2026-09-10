from pathlib import Path


def replace_exact(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"expected text not found in {path}: {old[:160]!r}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")

replace_exact(
    "frontend/src/components/SovereignAwakening.jsx",
    '''import { useSound } from "../contexts/SoundContext.jsx";
import {
  playSound,
  setMasterVolume,
  startAmbient,
} from "../lib/SoundEngine.js";
''',
    '''import { useSound } from "../contexts/SoundContext.jsx";
''',
)
replace_exact(
    "frontend/src/components/SovereignAwakening.jsx",
    '  const { toggle, enabled } = useSound();',
    '  const { toggle, enabled, play } = useSound();',
)
replace_exact(
    "frontend/src/components/SovereignAwakening.jsx",
    '''    if (phase === "sealed") {
      if (!enabled) toggle();
      else {
        setMasterVolume(0.26);
        startAmbient();
      }
      playSound("sovereign_awaken");
      onAwaken?.();
''',
    '''    if (phase === "sealed") {
      // Awakening and audio consent are independent. Sound only plays after
      // the dedicated sound control has been explicitly enabled.
      play("sovereign_awaken");
      onAwaken?.();
''',
)
replace_exact(
    "frontend/src/components/SovereignAwakening.jsx",
    '      playSound("button_click");',
    '      play("button_click");',
)
replace_exact(
    "frontend/src/components/SovereignAwakening.jsx",
    '''          </button>
        </motion.section>
''',
    '''          </button>

          <button
            type="button"
            onClick={toggle}
            aria-pressed={enabled}
            data-qc-sound={enabled ? "on" : "off"}
            style={{
              marginTop: 12,
              padding: "9px 14px",
              border: "1px solid rgba(125,211,252,.2)",
              background: "rgba(4,8,14,.54)",
              color: enabled ? "#bde9f8" : "#8091aa",
              font: "600 8px/1 'JetBrains Mono',monospace",
              letterSpacing: ".18em",
              cursor: "pointer",
            }}
          >
            {enabled ? "SOUND /// ON" : "SOUND /// OFF · ENABLE"}
          </button>
        </motion.section>
''',
)
replace_exact(
    "frontend/src/contexts/SoundContext.jsx",
    '''      if (next) {
        setMasterVolume(0.3);
        startAmbient();
      } else {
''',
    '''      if (next) {
        setMasterVolume(0.3);
        startAmbient();
        playSound("button_click");
      } else {
''',
)
print("QC_EXPERIENCE_AUDIO_PATCH=APPLIED")
