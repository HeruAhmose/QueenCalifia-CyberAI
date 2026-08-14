/**
 * TRAI Organism Protocol v5
 *
 * Six independent worlds, one shared navigation organism.
 * Cross-origin transitions use paired departure/arrival choreography.
 * Same-origin SPA transitions can opt into the View Transition API.
 */
(function () {
  "use strict";

  var VERSION = "5.3.0";
  var script = document.currentScript;

  if (!script) return;
  if (window.TRAIOrganismV5 && window.TRAIOrganismV5.version === VERSION) return;

  var SELF = script.dataset.traiWorld || "trai";
  var STATIC_NAVIGATION = script.dataset.traiStatic === "true";
  var manifestUrl =
    script.dataset.traiManifest ||
    new URL("trai-organism-v5.json", script.src).href;
  var reducedMotion =
    window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var legacyHost = ["manus", "computer"].join(".");
  var protocolSearch = new URL(window.location.href).searchParams;
  var pendingArrival =
    (protocolSearch.get("trai_v") === "5" ||
      protocolSearch.get("trai_v") === "5.2") &&
    protocolSearch.get("trai_to") === SELF;
  var pendingArrivalStyle = null;

  if (pendingArrival) {
    document.documentElement.classList.add("trai-v5-pending-arrival");
    pendingArrivalStyle = document.createElement("style");
    pendingArrivalStyle.id = "trai-v5-pending-arrival-style";
    pendingArrivalStyle.textContent =
      "html.trai-v5-pending-arrival body > *:not(.trai-v5-transition){" +
      "visibility:hidden!important}" +
      "html.trai-v5-pending-arrival .trai-v5-transition{" +
      "visibility:visible!important}";
    (document.head || document.documentElement).appendChild(pendingArrivalStyle);
  }

  var state = {
    manifest: null,
    worlds: new Map(),
    current: null,
    dialog: null,
    launcher: null,
    selected: null,
    previousFocus: null,
    transitionNode: null,
    routePath: window.location.pathname + window.location.search + window.location.hash,
    busy: false
  };

  var CSS = String.raw`
:root {
  --trai-v5-gold: #d6a33a;
  --trai-v5-bone: #f4ede0;
  --trai-v5-ink: #040609;
  --trai-v5-panel: rgba(7, 10, 15, 0.965);
}
.trai-v5-launcher,
.trai-v5-dialog,
.trai-v5-transition,
.trai-v5-internal-pulse {
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
.trai-v5-launcher {
  position: fixed;
  right: max(1rem, env(safe-area-inset-right));
  bottom: max(1rem, env(safe-area-inset-bottom));
  z-index: 2147482000;
  min-height: 44px;
  max-width: min(78vw, 19rem);
  display: inline-flex;
  align-items: center;
  gap: .7rem;
  padding: .62rem .85rem;
  color: var(--trai-v5-bone);
  background:
    linear-gradient(180deg, rgba(12, 16, 23, .96), rgba(5, 8, 13, .96));
  border: 1px solid color-mix(in srgb, var(--trai-v5-current, var(--trai-v5-gold)) 44%, transparent);
  border-radius: 999px;
  box-shadow:
    0 18px 50px rgba(0, 0, 0, .34),
    0 0 34px color-mix(in srgb, var(--trai-v5-current, var(--trai-v5-gold)) 12%, transparent);
  backdrop-filter: blur(18px) saturate(1.15);
  cursor: pointer;
  isolation: isolate;
  transition: transform .28s cubic-bezier(.16,1,.3,1), border-color .28s ease, box-shadow .28s ease;
}
.trai-v5-launcher[data-trai-self="techbridge"] {
  right: auto;
  left: max(1rem, env(safe-area-inset-left));
}
.trai-v5-launcher:hover {
  transform: translateY(-2px);
  border-color: color-mix(in srgb, var(--trai-v5-current, var(--trai-v5-gold)) 72%, transparent);
  box-shadow:
    0 22px 60px rgba(0, 0, 0, .38),
    0 0 48px color-mix(in srgb, var(--trai-v5-current, var(--trai-v5-gold)) 18%, transparent);
}
.trai-v5-launcher:focus-visible,
.trai-v5-dialog :focus-visible {
  outline: 2px solid var(--trai-v5-focus, #f1ca72);
  outline-offset: 3px;
}
.trai-v5-launcher__glyph {
  position: relative;
  width: 1.55rem;
  height: 1.55rem;
  flex: none;
  border-radius: 50%;
  border: 1px solid var(--trai-v5-current, var(--trai-v5-gold));
  box-shadow: inset 0 0 18px color-mix(in srgb, var(--trai-v5-current, var(--trai-v5-gold)) 14%, transparent);
}
.trai-v5-launcher__glyph::before,
.trai-v5-launcher__glyph::after {
  content: "";
  position: absolute;
  inset: 4px;
  border: 1px solid color-mix(in srgb, var(--trai-v5-current, var(--trai-v5-gold)) 65%, transparent);
  border-radius: 50%;
  transform: rotate(58deg) scaleX(.47);
}
.trai-v5-launcher__glyph::after {
  transform: rotate(-58deg) scaleX(.47);
}
.trai-v5-launcher__copy {
  min-width: 0;
  display: grid;
  gap: .06rem;
  text-align: left;
}
.trai-v5-launcher__eyebrow {
  color: color-mix(in srgb, var(--trai-v5-current, var(--trai-v5-gold)) 85%, white);
  font: 700 .58rem/1.1 ui-monospace, SFMono-Regular, Menlo, monospace;
  letter-spacing: .19em;
  text-transform: uppercase;
}
.trai-v5-launcher__world {
  overflow: hidden;
  color: rgba(244, 237, 224, .82);
  font-size: .73rem;
  line-height: 1.2;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.trai-v5-dialog {
  width: min(70rem, calc(100vw - 1.25rem));
  max-height: min(50rem, calc(100vh - 1.25rem));
  padding: 0;
  color: var(--trai-v5-bone);
  background: transparent;
  border: 0;
  overflow: visible;
}
.trai-v5-dialog::backdrop {
  background:
    radial-gradient(circle at 50% 35%, rgba(34, 52, 76, .22), transparent 42%),
    rgba(2, 4, 7, .84);
  backdrop-filter: blur(16px) saturate(.9);
}
.trai-v5-shell {
  position: relative;
  max-height: min(50rem, calc(100vh - 1.25rem));
  overflow: auto;
  border: 1px solid rgba(214, 163, 58, .27);
  border-radius: 1.35rem;
  background:
    radial-gradient(circle at 10% 0%, color-mix(in srgb, var(--trai-v5-current, #d6a33a) 12%, transparent), transparent 34%),
    radial-gradient(circle at 90% 10%, rgba(66, 153, 225, .09), transparent 30%),
    linear-gradient(145deg, rgba(8, 12, 18, .99), rgba(4, 7, 11, .985));
  box-shadow: 0 42px 120px rgba(0, 0, 0, .62);
}
.trai-v5-shell::before {
  content: "";
  position: absolute;
  inset: 0;
  pointer-events: none;
  border-radius: inherit;
  background-image:
    linear-gradient(rgba(255,255,255,.018) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.018) 1px, transparent 1px);
  background-size: 36px 36px;
  mask-image: radial-gradient(circle at center, black, transparent 82%);
}
.trai-v5-head {
  position: sticky;
  top: 0;
  z-index: 4;
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1rem;
  padding: 1.25rem 1.25rem 1rem;
  background: linear-gradient(180deg, rgba(7,10,15,.985), rgba(7,10,15,.88), transparent);
}
.trai-v5-head__kicker {
  color: color-mix(in srgb, var(--trai-v5-current, #d6a33a) 78%, white);
  font: 700 .62rem/1.2 ui-monospace, SFMono-Regular, Menlo, monospace;
  letter-spacing: .19em;
  text-transform: uppercase;
}
.trai-v5-head h2 {
  margin: .25rem 0 0;
  color: #fffaf2;
  font: 650 clamp(1.4rem, 3.1vw, 2.35rem)/1.04 ui-serif, Georgia, serif;
  letter-spacing: -.025em;
}
.trai-v5-close {
  width: 44px;
  height: 44px;
  flex: none;
  display: grid;
  place-items: center;
  color: rgba(244,237,224,.72);
  background: rgba(255,255,255,.035);
  border: 1px solid rgba(255,255,255,.1);
  border-radius: 50%;
  cursor: pointer;
  transition: transform .2s ease, background .2s ease, color .2s ease;
}
.trai-v5-close:hover {
  transform: rotate(5deg);
  color: white;
  background: rgba(255,255,255,.075);
}
.trai-v5-body {
  position: relative;
  z-index: 2;
  display: grid;
  grid-template-columns: minmax(0, 1.18fr) minmax(18rem, .82fr);
  gap: 1rem;
  padding: .2rem 1.25rem 1.25rem;
}
.trai-v5-worlds {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: .65rem;
  align-content: start;
}
.trai-v5-world {
  position: relative;
  min-height: 7.5rem;
  padding: .95rem;
  text-align: left;
  color: rgba(244,237,224,.82);
  background: linear-gradient(145deg, rgba(255,255,255,.04), rgba(255,255,255,.018));
  border: 1px solid rgba(255,255,255,.08);
  border-radius: 1rem;
  overflow: hidden;
  cursor: pointer;
  transition:
    transform .3s cubic-bezier(.16,1,.3,1),
    border-color .3s ease,
    background .3s ease,
    box-shadow .3s ease;
}
.trai-v5-world::before {
  content: "";
  position: absolute;
  width: 7rem;
  height: 7rem;
  right: -2rem;
  bottom: -3rem;
  border-radius: 50%;
  background: radial-gradient(circle, var(--world-accent) 0, transparent 68%);
  opacity: .13;
  filter: blur(4px);
}
.trai-v5-world:hover,
.trai-v5-world[data-selected="true"] {
  transform: translateY(-2px);
  border-color: color-mix(in srgb, var(--world-accent) 52%, transparent);
  background: linear-gradient(145deg, color-mix(in srgb, var(--world-accent) 8%, rgba(255,255,255,.035)), rgba(255,255,255,.018));
  box-shadow: 0 18px 34px rgba(0,0,0,.22), 0 0 28px color-mix(in srgb, var(--world-accent) 10%, transparent);
}
.trai-v5-world[data-current="true"] {
  cursor: default;
  border-color: color-mix(in srgb, var(--world-accent) 60%, transparent);
}
.trai-v5-world__index {
  display: block;
  margin-bottom: .55rem;
  color: var(--world-accent);
  font: 700 .58rem/1 ui-monospace, SFMono-Regular, Menlo, monospace;
  letter-spacing: .16em;
}
.trai-v5-world strong {
  display: block;
  color: #fffaf1;
  font-size: .95rem;
  line-height: 1.12;
}
.trai-v5-world span {
  display: block;
  margin-top: .35rem;
  color: rgba(244,237,224,.5);
  font-size: .72rem;
  line-height: 1.3;
}
.trai-v5-detail {
  position: sticky;
  top: 5rem;
  min-height: 21rem;
  align-self: start;
  padding: 1.1rem;
  border: 1px solid color-mix(in srgb, var(--detail-accent, #d6a33a) 28%, transparent);
  border-radius: 1rem;
  background:
    radial-gradient(circle at 100% 0%, color-mix(in srgb, var(--detail-accent, #d6a33a) 14%, transparent), transparent 35%),
    rgba(255,255,255,.025);
}
.trai-v5-detail__role {
  color: var(--detail-accent, #d6a33a);
  font: 700 .61rem/1.2 ui-monospace, SFMono-Regular, Menlo, monospace;
  letter-spacing: .16em;
  text-transform: uppercase;
}
.trai-v5-detail h3 {
  margin: .48rem 0 .3rem;
  color: #fffaf1;
  font: 650 clamp(1.35rem, 2.2vw, 1.8rem)/1.08 ui-serif, Georgia, serif;
}
.trai-v5-detail__thesis {
  margin: 0 0 .85rem;
  color: rgba(244,237,224,.64);
  font-size: .87rem;
  line-height: 1.5;
}
.trai-v5-detail details {
  border-top: 1px solid rgba(255,255,255,.08);
  border-bottom: 1px solid rgba(255,255,255,.08);
  padding: .75rem 0;
}
.trai-v5-detail summary {
  color: rgba(244,237,224,.82);
  cursor: pointer;
  font-size: .79rem;
  font-weight: 650;
}
.trai-v5-detail details p {
  margin: .7rem 0 0;
  color: rgba(244,237,224,.58);
  font-size: .82rem;
  line-height: 1.55;
}
.trai-v5-actions {
  display: flex;
  flex-wrap: wrap;
  gap: .6rem;
  margin-top: 1rem;
}
.trai-v5-enter,
.trai-v5-newtab {
  min-height: 44px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: .35rem;
  padding: .68rem .9rem;
  border-radius: .75rem;
  font-size: .78rem;
  font-weight: 750;
  text-decoration: none;
  cursor: pointer;
}
.trai-v5-enter {
  color: #05070a;
  background: linear-gradient(135deg, color-mix(in srgb, var(--detail-accent) 82%, white), var(--detail-accent));
  border: 0;
  box-shadow: 0 10px 28px color-mix(in srgb, var(--detail-accent) 18%, transparent);
}
.trai-v5-newtab {
  color: rgba(244,237,224,.78);
  background: rgba(255,255,255,.035);
  border: 1px solid rgba(255,255,255,.11);
}
.trai-v5-current-note {
  margin-top: 1rem;
  padding: .78rem;
  color: rgba(244,237,224,.58);
  background: rgba(255,255,255,.025);
  border: 1px solid rgba(255,255,255,.08);
  border-radius: .7rem;
  font-size: .76rem;
  line-height: 1.45;
}
.trai-v5-transition {
  --accent: #d6a33a;
  --secondary: #5e86c9;
  position: fixed;
  inset: 0;
  z-index: 2147483600;
  display: grid;
  place-items: center;
  color: #fffaf1;
  background:
    radial-gradient(circle at 50% 50%, color-mix(in srgb, var(--accent) 14%, transparent), transparent 34%),
    linear-gradient(145deg, #030508, #070b12 55%, #020304);
  overflow: hidden;
  pointer-events: all;
  isolation: isolate;
}
.trai-v5-transition::before {
  content: "";
  position: absolute;
  inset: -20%;
  background:
    radial-gradient(circle at 30% 25%, color-mix(in srgb, var(--secondary) 12%, transparent), transparent 28%),
    radial-gradient(circle at 70% 70%, color-mix(in srgb, var(--accent) 10%, transparent), transparent 30%);
  filter: blur(28px);
  animation: trai-v5-breathe 2.2s ease-in-out infinite alternate;
}
.trai-v5-transition[data-phase="departure"] {
  animation: trai-v5-overlay-in .72s cubic-bezier(.16,1,.3,1) both;
}
.trai-v5-transition[data-phase="arrival"] {
  animation: trai-v5-overlay-out 1.15s .1s cubic-bezier(.16,1,.3,1) both;
}
.trai-v5-transition__field {
  position: absolute;
  inset: 0;
  z-index: 1;
}
.trai-v5-transition__copy {
  position: relative;
  z-index: 4;
  width: min(42rem, calc(100vw - 2rem));
  text-align: center;
  padding: 1rem;
  text-shadow: 0 6px 36px rgba(0,0,0,.6);
}
.trai-v5-transition__kicker {
  color: color-mix(in srgb, var(--accent) 82%, white);
  font: 700 .64rem/1.2 ui-monospace, SFMono-Regular, Menlo, monospace;
  letter-spacing: .23em;
  text-transform: uppercase;
}
.trai-v5-transition__copy h2 {
  margin: .55rem 0 .45rem;
  color: #fffaf2;
  font: 650 clamp(2rem, 6vw, 4.7rem)/.95 ui-serif, Georgia, serif;
  letter-spacing: -.045em;
}
.trai-v5-transition__copy p {
  margin: 0 auto;
  max-width: 34rem;
  color: rgba(244,237,224,.62);
  font-size: clamp(.78rem, 2vw, .98rem);
  line-height: 1.5;
}
.trai-v5-transition__route {
  margin-top: .85rem;
  color: rgba(244,237,224,.38);
  font: 650 .58rem/1.3 ui-monospace, SFMono-Regular, Menlo, monospace;
  letter-spacing: .12em;
  text-transform: uppercase;
}
.trai-v5-orbits {
  position: absolute;
  inset: 50%;
  width: 1px;
  height: 1px;
}
.trai-v5-orbits i {
  --i: 0;
  position: absolute;
  width: calc(10rem + var(--i) * 7rem);
  aspect-ratio: 1;
  left: 50%;
  top: 50%;
  border: 1px solid color-mix(in srgb, var(--accent) calc(55% - var(--i) * 7%), transparent);
  border-radius: 50%;
  transform: translate(-50%, -50%) rotate(calc(var(--i) * 19deg)) scaleX(calc(1 - var(--i) * .045));
  animation: trai-v5-orbit calc(7s + var(--i) * 1.2s) linear infinite;
}
.trai-v5-orbits i::after {
  content: "";
  position: absolute;
  width: .42rem;
  height: .42rem;
  top: 50%;
  left: -0.22rem;
  border-radius: 50%;
  background: var(--accent);
  box-shadow: 0 0 18px var(--accent);
}
.trai-v5-lineage {
  position: absolute;
  inset: 0;
}
.trai-v5-lineage i {
  --i: 0;
  position: absolute;
  width: 1px;
  height: 72vh;
  left: calc(8% + var(--i) * 7.4%);
  top: 14%;
  transform-origin: 50% 100%;
  transform: rotate(calc(-24deg + var(--i) * 4deg));
  background: linear-gradient(transparent, color-mix(in srgb, var(--accent) 58%, transparent), transparent);
  box-shadow: 0 0 12px color-mix(in srgb, var(--accent) 18%, transparent);
  animation: trai-v5-thread calc(2.4s + var(--i) * .12s) ease-in-out infinite alternate;
}
.trai-v5-lineage i::after {
  content: "";
  position: absolute;
  left: -.22rem;
  top: calc(12% + var(--i) * 5%);
  width: .46rem;
  height: .46rem;
  border-radius: 50%;
  background: color-mix(in srgb, var(--accent) 70%, white);
  box-shadow: 0 0 20px var(--accent);
}
.trai-v5-phi {
  position: absolute;
  inset: 0;
}
.trai-v5-phi i {
  position: absolute;
  width: var(--s);
  height: var(--s);
  left: var(--x);
  top: var(--y);
  border-radius: 50%;
  background: color-mix(in srgb, var(--accent) 78%, white);
  box-shadow: 0 0 calc(var(--s) * 3.4) color-mix(in srgb, var(--accent) 42%, transparent);
  opacity: var(--o);
  animation: trai-v5-phi-pulse calc(1.7s + var(--n) * .035s) ease-in-out infinite alternate;
}
.trai-v5-crystal {
  position: absolute;
  inset: -6%;
  background:
    linear-gradient(30deg, transparent 47.8%, color-mix(in srgb, var(--accent) 28%, transparent) 48%, color-mix(in srgb, var(--accent) 28%, transparent) 52%, transparent 52.2%) 0 0 / 6rem 10.4rem,
    linear-gradient(150deg, transparent 47.8%, color-mix(in srgb, var(--secondary) 22%, transparent) 48%, color-mix(in srgb, var(--secondary) 22%, transparent) 52%, transparent 52.2%) 0 0 / 6rem 10.4rem,
    linear-gradient(90deg, transparent 47.8%, rgba(255,255,255,.06) 48%, rgba(255,255,255,.06) 52%, transparent 52.2%) 0 0 / 6rem 10.4rem;
  transform: perspective(900px) rotateX(58deg) rotateZ(4deg) scale(1.35);
  transform-origin: center;
  animation: trai-v5-crystal-drift 7s ease-in-out infinite alternate;
  mask-image: radial-gradient(circle at center, black 0 45%, transparent 78%);
}
.trai-v5-command {
  position: absolute;
  inset: 0;
}
.trai-v5-command::before,
.trai-v5-command::after {
  content: "";
  position: absolute;
  left: 50%;
  top: 50%;
  border-radius: 50%;
  transform: translate(-50%, -50%);
}
.trai-v5-command::before {
  width: min(66vw, 42rem);
  aspect-ratio: 1;
  border: 1px solid color-mix(in srgb, var(--accent) 44%, transparent);
  box-shadow:
    inset 0 0 0 3rem transparent,
    0 0 80px color-mix(in srgb, var(--secondary) 12%, transparent);
  background:
    conic-gradient(from 0deg, transparent 0 8%, color-mix(in srgb, var(--accent) 28%, transparent) 8.5% 9%, transparent 9.5% 24%, color-mix(in srgb, var(--secondary) 24%, transparent) 24.5% 25%, transparent 25.5%);
  animation: trai-v5-command-spin 10s linear infinite;
}
.trai-v5-command::after {
  width: min(18vw, 8rem);
  aspect-ratio: 1;
  background: radial-gradient(circle, white 0 1%, var(--accent) 3%, color-mix(in srgb, var(--accent) 28%, transparent) 25%, transparent 70%);
  box-shadow: 0 0 90px color-mix(in srgb, var(--accent) 40%, transparent);
  animation: trai-v5-command-core 1.8s ease-in-out infinite alternate;
}
.trai-v5-command .scan {
  position: absolute;
  inset: 0;
  background: linear-gradient(180deg, transparent 0 46%, color-mix(in srgb, var(--secondary) 40%, transparent) 49.5%, transparent 53%);
  animation: trai-v5-scan 2.2s linear infinite;
}
.trai-v5-bridge {
  position: absolute;
  inset: 0;
  display: grid;
  place-items: center;
}
.trai-v5-bridge svg {
  width: min(88vw, 70rem);
  overflow: visible;
  filter: drop-shadow(0 0 18px color-mix(in srgb, var(--accent) 14%, transparent));
}
.trai-v5-bridge .arch,
.trai-v5-bridge .deck,
.trai-v5-bridge .support {
  fill: none;
  stroke-linecap: round;
  vector-effect: non-scaling-stroke;
}
.trai-v5-bridge .arch {
  stroke: var(--accent);
  stroke-width: 2;
  stroke-dasharray: 1200;
  animation: trai-v5-draw 1.35s cubic-bezier(.16,1,.3,1) both;
}
.trai-v5-bridge .deck {
  stroke: color-mix(in srgb, var(--secondary) 75%, white);
  stroke-width: 1.4;
  stroke-dasharray: 1000;
  animation: trai-v5-draw 1.05s .12s cubic-bezier(.16,1,.3,1) both;
}
.trai-v5-bridge .support {
  stroke: color-mix(in srgb, var(--accent) 65%, transparent);
  stroke-width: 1;
  stroke-dasharray: 300;
  animation: trai-v5-draw .9s .28s ease-out both;
}
.trai-v5-bridge circle {
  fill: var(--accent);
  filter: drop-shadow(0 0 7px var(--accent));
  animation: trai-v5-node 1.3s ease-in-out infinite alternate;
}
.trai-v5-internal-pulse {
  --accent: var(--trai-v5-current, #d6a33a);
  position: fixed;
  inset: 0;
  z-index: 2147481500;
  pointer-events: none;
  background:
    radial-gradient(circle at var(--trai-v5-x, 50%) var(--trai-v5-y, 50%),
      color-mix(in srgb, var(--accent) 17%, transparent),
      transparent 28%),
    linear-gradient(90deg, transparent, color-mix(in srgb, var(--accent) 5%, transparent), transparent);
  opacity: 0;
  animation: trai-v5-internal .52s cubic-bezier(.16,1,.3,1) both;
}
@keyframes trai-v5-overlay-in {
  from { opacity: 0; clip-path: circle(0% at var(--trai-v5-origin-x,50%) var(--trai-v5-origin-y,50%)); }
  to { opacity: 1; clip-path: circle(150% at var(--trai-v5-origin-x,50%) var(--trai-v5-origin-y,50%)); }
}
@keyframes trai-v5-overlay-out {
  0% { opacity: 1; clip-path: circle(150% at 50% 50%); }
  72% { opacity: .92; }
  100% { opacity: 0; clip-path: circle(0% at 50% 50%); visibility: hidden; }
}
@keyframes trai-v5-breathe {
  from { transform: scale(.98) rotate(-1deg); opacity: .65; }
  to { transform: scale(1.05) rotate(1deg); opacity: 1; }
}
@keyframes trai-v5-orbit {
  to { transform: translate(-50%, -50%) rotate(360deg) scaleX(.84); }
}
@keyframes trai-v5-thread {
  from { opacity: .3; filter: blur(.1px); }
  to { opacity: .9; filter: blur(0); }
}
@keyframes trai-v5-phi-pulse {
  from { transform: scale(.55); opacity: calc(var(--o) * .45); }
  to { transform: scale(1.35); opacity: var(--o); }
}
@keyframes trai-v5-crystal-drift {
  from { transform: perspective(900px) rotateX(58deg) rotateZ(1deg) scale(1.28); opacity: .48; }
  to { transform: perspective(900px) rotateX(61deg) rotateZ(7deg) scale(1.42); opacity: .82; }
}
@keyframes trai-v5-command-spin {
  to { transform: translate(-50%, -50%) rotate(360deg); }
}
@keyframes trai-v5-command-core {
  from { transform: translate(-50%, -50%) scale(.84); opacity: .6; }
  to { transform: translate(-50%, -50%) scale(1.12); opacity: 1; }
}
@keyframes trai-v5-scan {
  from { transform: translateY(-55%); }
  to { transform: translateY(55%); }
}
@keyframes trai-v5-draw {
  from { stroke-dashoffset: 1200; opacity: .1; }
  to { stroke-dashoffset: 0; opacity: 1; }
}
@keyframes trai-v5-node {
  from { opacity: .45; transform: scale(.75); transform-box: fill-box; transform-origin: center; }
  to { opacity: 1; transform: scale(1.35); transform-box: fill-box; transform-origin: center; }
}
@keyframes trai-v5-internal {
  0% { opacity: 0; transform: scale(.98); }
  36% { opacity: 1; }
  100% { opacity: 0; transform: scale(1.025); }
}

/* v5.3 cinematic transport: finite source -> destination morphs. */
.trai-v5-transition[data-phase="departure"],
.trai-v5-transition[data-phase="arrival"] {
  animation: none;
}
.trai-v5-transition {
  background:
    radial-gradient(circle at 50% 50%,
      color-mix(in srgb, var(--accent) 16%, transparent),
      transparent 31%),
    radial-gradient(circle at 18% 18%,
      color-mix(in srgb, var(--secondary) 10%, transparent),
      transparent 26%),
    linear-gradient(145deg, #020407, #080d15 52%, #010203);
  will-change: opacity, clip-path, filter, transform;
}
.trai-v5-transition__veil {
  position: absolute;
  inset: -15%;
  z-index: 0;
  opacity: .78;
  background:
    repeating-radial-gradient(circle at 50% 50%,
      transparent 0 22px,
      color-mix(in srgb, var(--accent) 6%, transparent) 23px 24px,
      transparent 25px 46px),
    conic-gradient(from 0deg at 50% 50%,
      transparent 0 11%,
      color-mix(in srgb, var(--secondary) 8%, transparent) 12% 13%,
      transparent 14% 37%,
      color-mix(in srgb, var(--accent) 7%, transparent) 38% 39%,
      transparent 40% 100%);
  filter: blur(.2px);
  transform: scale(1.08) rotate(-2deg);
  mix-blend-mode: screen;
  pointer-events: none;
}
.trai-v5-transition__axis {
  position: absolute;
  z-index: 3;
  left: 50%;
  top: 50%;
  width: min(78vw, 62rem);
  height: 1px;
  transform: translate(-50%, -50%);
  background:
    linear-gradient(90deg,
      transparent,
      color-mix(in srgb, var(--secondary) 42%, transparent) 14%,
      color-mix(in srgb, var(--accent) 82%, white) 50%,
      color-mix(in srgb, var(--secondary) 42%, transparent) 86%,
      transparent);
  box-shadow:
    0 0 18px color-mix(in srgb, var(--accent) 28%, transparent),
    0 0 64px color-mix(in srgb, var(--secondary) 14%, transparent);
  opacity: .6;
  pointer-events: none;
}
.trai-v5-transition__axis::before,
.trai-v5-transition__axis::after {
  content: "";
  position: absolute;
  top: 50%;
  width: .42rem;
  height: .42rem;
  border-radius: 50%;
  background: color-mix(in srgb, var(--accent) 72%, white);
  box-shadow: 0 0 22px var(--accent);
  transform: translateY(-50%);
}
.trai-v5-transition__axis::before { left: 0; }
.trai-v5-transition__axis::after { right: 0; }
.trai-v5-transition__field {
  position: absolute;
  inset: 0;
  z-index: 1;
  transform-origin:
    var(--trai-v5-origin-x, 50%)
    var(--trai-v5-origin-y, 50%);
  will-change: opacity, transform, filter;
}
.trai-v5-transition__field--source {
  opacity: .72;
}
.trai-v5-transition__field--destination {
  opacity: 0;
  transform: scale(1.18);
  filter: blur(8px) saturate(.8);
}
.trai-v5-transition__copy {
  will-change: opacity, transform, filter;
}
.trai-v5-transition__copy h2 {
  text-wrap: balance;
  text-shadow:
    0 6px 36px rgba(0,0,0,.72),
    0 0 44px color-mix(in srgb, var(--accent) 15%, transparent);
}
.trai-v5-transition__route {
  display: inline-flex;
  align-items: center;
  gap: .55rem;
  padding: .42rem .68rem;
  border: 1px solid color-mix(in srgb, var(--accent) 20%, transparent);
  border-radius: 999px;
  background: rgba(2,4,7,.34);
  backdrop-filter: blur(10px);
}
.trai-v5-transition__route::before {
  content: "";
  width: .34rem;
  height: .34rem;
  border-radius: 50%;
  background: var(--accent);
  box-shadow: 0 0 14px var(--accent);
}
.trai-v5-transition[data-phase="arrival"] .trai-v5-transition__copy {
  transform: translateY(0);
}
html[data-trai-v5-internal="true"]::view-transition-old(root) {
  animation: trai-v52-view-old .56s cubic-bezier(.2,.75,.2,1) both;
}
html[data-trai-v5-internal="true"]::view-transition-new(root) {
  animation: trai-v52-view-new .62s cubic-bezier(.16,1,.3,1) both;
}
.trai-v5-internal-pulse {
  background:
    radial-gradient(circle at var(--trai-v5-x, 50%) var(--trai-v5-y, 50%),
      color-mix(in srgb, var(--accent) 24%, transparent),
      color-mix(in srgb, var(--accent) 8%, transparent) 16%,
      transparent 34%),
    repeating-radial-gradient(circle at var(--trai-v5-x, 50%) var(--trai-v5-y, 50%),
      transparent 0 28px,
      color-mix(in srgb, var(--accent) 8%, transparent) 29px 30px,
      transparent 31px 58px);
  animation: trai-v52-internal .72s cubic-bezier(.16,1,.3,1) both;
}
@keyframes trai-v52-view-old {
  0% { opacity: 1; filter: blur(0); transform: scale(1); }
  100% { opacity: 0; filter: blur(7px); transform: scale(.985); }
}
@keyframes trai-v52-view-new {
  0% { opacity: 0; filter: blur(8px); transform: scale(1.018); }
  100% { opacity: 1; filter: blur(0); transform: scale(1); }
}
@keyframes trai-v52-internal {
  0% { opacity: 0; transform: scale(.965); }
  28% { opacity: 1; }
  72% { opacity: .78; }
  100% { opacity: 0; transform: scale(1.045); }
}

@media (max-width: 760px) {
  .trai-v5-body { grid-template-columns: 1fr; }
  .trai-v5-worlds { grid-template-columns: 1fr 1fr; }
  .trai-v5-detail { position: static; min-height: 0; }
}
@media (max-width: 480px) {
  .trai-v5-worlds { grid-template-columns: 1fr; }
  .trai-v5-launcher__world { display: none; }
}
@media (prefers-reduced-motion: reduce) {
  .trai-v5-launcher,
  .trai-v5-world,
  .trai-v5-close {
    transition-duration: .01ms !important;
  }
  .trai-v5-transition,
  .trai-v5-transition *,
  .trai-v5-internal-pulse {
    animation-duration: .01ms !important;
    animation-iteration-count: 1 !important;
  }
}
`;

  function injectCss() {
    if (document.getElementById("trai-organism-v5-css")) return;
    var style = document.createElement("style");
    style.id = "trai-organism-v5-css";
    style.textContent = CSS;
    document.head.appendChild(style);
  }

  function isLegacyHost(hostname) {
    var host = String(hostname || "").toLowerCase();
    return host === legacyHost || host.endsWith("." + legacyHost);
  }

  function normalizedPath(pathname) {
    var path = String(pathname || "/").replace(/\/+$/, "");
    return path || "/";
  }

  function matchWorldUrl(input) {
    var url;
    try {
      url = input instanceof URL ? input : new URL(input, window.location.href);
    } catch {
      return null;
    }

    if (isLegacyHost(url.hostname)) {
      return state.worlds.get("peoples") || null;
    }

    var worlds = Array.from(state.worlds.values());
    for (var i = 0; i < worlds.length; i += 1) {
      var world = worlds[i];
      if (!world.url) continue;
      try {
        var canonical = new URL(world.url);
        if (canonical.origin !== url.origin) continue;

        var canonicalPath = normalizedPath(canonical.pathname);
        var candidatePath = normalizedPath(url.pathname);

        if (
          canonicalPath === "/" ||
          candidatePath === canonicalPath ||
          candidatePath.startsWith(canonicalPath + "/")
        ) {
          return world;
        }
      } catch {
        continue;
      }
    }

    return null;
  }

  function updateAnchor(anchor) {
    if (!(anchor instanceof HTMLAnchorElement)) return;

    var raw = anchor.getAttribute("href");
    if (!raw) return;

    var url;
    try {
      url = new URL(raw, window.location.href);
    } catch {
      anchor.removeAttribute("href");
      anchor.setAttribute("aria-disabled", "true");
      return;
    }

    var protocol = url.protocol.toLowerCase();
    if (protocol === "mailto:" || protocol === "tel:") {
      return;
    }
    if (protocol !== "http:" && protocol !== "https:") {
      anchor.removeAttribute("href");
      anchor.setAttribute("aria-disabled", "true");
      return;
    }

    if (isLegacyHost(url.hostname)) {
      var peoples = state.worlds.get("peoples");
      if (peoples && peoples.url) {
        anchor.href = peoples.url;
        anchor.dataset.traiWorld = "peoples";
        anchor.dataset.traiLegacyRewritten = "true";
      }
      return;
    }

    var world = matchWorldUrl(url);
    if (world) {
      anchor.dataset.traiWorld = world.id;
      if (world.url && world.id !== SELF) {
        var canonical = new URL(world.url);
        if (
          normalizedPath(url.pathname) === normalizedPath(canonical.pathname) &&
          !url.search &&
          !url.hash
        ) {
          anchor.href = world.url;
        }
      }
    }
  }

  function rewriteAnchors(root) {
    if (!root || !root.querySelectorAll) return;
    if (root instanceof HTMLAnchorElement) updateAnchor(root);
    root.querySelectorAll("a[href]").forEach(updateAnchor);
  }

  function preconnectWorlds() {
    var origins = new Set();
    state.worlds.forEach(function (world) {
      if (!world.url || world.id === SELF) return;
      try {
        origins.add(new URL(world.url).origin);
      } catch {
        return;
      }
    });

    origins.forEach(function (origin) {
      if (document.head.querySelector('link[data-trai-v5-preconnect="' + window.CSS.escape(origin) + '"]')) return;
      var link = document.createElement("link");
      link.rel = "preconnect";
      link.href = origin;
      link.crossOrigin = "anonymous";
      link.dataset.traiV5Preconnect = origin;
      document.head.appendChild(link);
    });
  }

  function setCurrentTheme() {
    if (!state.current) return;
    document.documentElement.style.setProperty(
      "--trai-v5-current",
      state.current.accent || "#d6a33a"
    );
    document.documentElement.style.setProperty(
      "--trai-v5-focus",
      state.current.secondary || "#f1ca72"
    );
  }

  function worldButton(world, index) {
    var button = document.createElement("button");
    button.type = "button";
    button.className = "trai-v5-world";
    button.dataset.worldId = world.id;
    button.dataset.current = String(world.id === SELF);
    button.style.setProperty("--world-accent", world.accent || "#d6a33a");
    button.innerHTML =
      '<span class="trai-v5-world__index">' +
      String(index + 1).padStart(2, "0") +
      (world.id === SELF ? " · CURRENT" : "") +
      "</span>" +
      "<strong>" +
      escapeHtml(world.name) +
      "</strong>" +
      "<span>" +
      escapeHtml(world.role || "") +
      "</span>";

    button.addEventListener("click", function () {
      selectWorld(world.id);
    });
    return button;
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function buildPortal() {
    var dialog = document.createElement("dialog");
    dialog.className = "trai-v5-dialog";
    dialog.setAttribute("aria-labelledby", "trai-v5-title");

    var shell = document.createElement("div");
    shell.className = "trai-v5-shell";
    shell.innerHTML =
      '<header class="trai-v5-head">' +
      "<div>" +
      '<div class="trai-v5-head__kicker">TRAI Organism Protocol · Six Worlds</div>' +
      '<h2 id="trai-v5-title">Choose the world you want to enter.</h2>' +
      "</div>" +
      '<button class="trai-v5-close" type="button" aria-label="Close world portal">✕</button>' +
      "</header>" +
      '<div class="trai-v5-body">' +
      '<div class="trai-v5-worlds" role="list"></div>' +
      '<section class="trai-v5-detail" aria-live="polite"></section>' +
      "</div>";

    dialog.appendChild(shell);
    document.body.appendChild(dialog);

    shell
      .querySelector(".trai-v5-close")
      .addEventListener("click", closePortal);

    dialog.addEventListener("click", function (event) {
      if (event.target === dialog) closePortal();
    });

    dialog.addEventListener("close", function () {
      document.body.style.removeProperty("overflow");
      if (state.previousFocus && document.contains(state.previousFocus)) {
        state.previousFocus.focus({ preventScroll: true });
      }
      state.previousFocus = null;
    });

    var list = shell.querySelector(".trai-v5-worlds");
    state.manifest.worlds
      .filter(function (world) {
        return world.id !== SELF;
      })
      .forEach(function (world, index) {
        list.appendChild(worldButton(world, index));
      });

    state.dialog = dialog;
    var firstOtherWorld = state.manifest.worlds.find(function (world) {
      return world.id !== SELF;
    });
    selectWorld(firstOtherWorld ? firstOtherWorld.id : SELF);
  }

  function buildLauncher() {
    var button = document.createElement("button");
    button.type = "button";
    button.className = "trai-v5-launcher";
    button.dataset.traiSelf = SELF;
    button.setAttribute("aria-haspopup", "dialog");
    button.setAttribute("aria-label", "Open TRAI worlds");
    button.innerHTML =
      '<span class="trai-v5-launcher__glyph" aria-hidden="true"></span>' +
      '<span class="trai-v5-launcher__copy">' +
      '<span class="trai-v5-launcher__eyebrow">WORLD PORTAL</span>' +
      '<span class="trai-v5-launcher__world">Switch connected realm</span>' +
      "</span>";

    button.addEventListener("click", function () {
      var firstOtherWorld = state.manifest.worlds.find(function (world) {
        return world.id !== SELF;
      });
      openPortal(firstOtherWorld ? firstOtherWorld.id : SELF, button);
    });

    document.body.appendChild(button);
    state.launcher = button;
  }

  function selectWorld(id) {
    var world = state.worlds.get(id) || state.current;
    if (!world || !state.dialog) return;

    state.selected = world;

    state.dialog.querySelectorAll(".trai-v5-world").forEach(function (button) {
      button.dataset.selected = String(button.dataset.worldId === world.id);
    });

    var detail = state.dialog.querySelector(".trai-v5-detail");
    detail.style.setProperty("--detail-accent", world.accent || "#d6a33a");

    var isCurrent = world.id === SELF;
    var actions = isCurrent
      ? '<div class="trai-v5-current-note">You are already inside this world. Use its native navigation for deeper sections, or choose another world in the organism.</div>'
      : '<div class="trai-v5-actions">' +
        '<button type="button" class="trai-v5-enter">Enter world <span aria-hidden="true">→</span></button>' +
        '<a class="trai-v5-newtab" target="_blank" rel="noopener noreferrer">Open in new tab ↗</a>' +
        "</div>";

    detail.innerHTML =
      '<div class="trai-v5-detail__role">' +
      escapeHtml(world.role || "TRAI world") +
      "</div>" +
      "<h3>" +
      escapeHtml(world.name) +
      "</h3>" +
      '<p class="trai-v5-detail__thesis">' +
      escapeHtml(world.thesis || "") +
      "</p>" +
      "<details open>" +
      "<summary>Brief synopsis</summary>" +
      "<p>" +
      escapeHtml(world.synopsis || world.thesis || "") +
      "</p>" +
      "</details>" +
      actions;

    if (!isCurrent) {
      var enter = detail.querySelector(".trai-v5-enter");
      var newTab = detail.querySelector(".trai-v5-newtab");
      newTab.href = world.url;
      enter.addEventListener("click", function () {
        transitionToWorld(world, enter);
      });
    }
  }

  function openPortal(id, source) {
    if (!state.dialog) return;
    state.previousFocus =
      source instanceof HTMLElement ? source : document.activeElement;
    selectWorld(id || SELF);

    if (!state.dialog.open) {
      document.body.style.overflow = "hidden";
      state.dialog.showModal();
    }

    var preferred = state.dialog.querySelector(
      '[data-world-id="' + window.CSS.escape(id || SELF) + '"]'
    );
    if (preferred) preferred.focus({ preventScroll: true });
  }

  function closePortal() {
    if (state.dialog && state.dialog.open) state.dialog.close();
  }

  function geometryHtml(world) {
    var skin = world.skin || "orbit";

    if (skin === "lineage") {
      return (
        '<div class="trai-v5-lineage">' +
        Array.from({ length: 12 }, function (_, i) {
          return '<i style="--i:' + i + '"></i>';
        }).join("") +
        "</div>"
      );
    }

    if (skin === "phi") {
      var golden = Math.PI * (3 - Math.sqrt(5));
      var dots = [];
      var count = 78;
      for (var i = 0; i < count; i += 1) {
        var ratio = i / (count - 1);
        var radius = Math.sqrt(ratio) * 42;
        var angle = i * golden;
        var x = 50 + Math.cos(angle) * radius;
        var y = 50 + Math.sin(angle) * radius;
        var size = 2.4 + ratio * 7.6;
        var opacity = 0.24 + ratio * 0.7;
        dots.push(
          '<i style="--x:' +
            x.toFixed(2) +
            "%;--y:" +
            y.toFixed(2) +
            "%;--s:" +
            size.toFixed(2) +
            "px;--o:" +
            opacity.toFixed(2) +
            ";--n:" +
            i +
            '"></i>'
        );
      }
      return '<div class="trai-v5-phi">' + dots.join("") + "</div>";
    }

    if (skin === "crystal") {
      return '<div class="trai-v5-crystal"></div>';
    }

    if (skin === "command") {
      return '<div class="trai-v5-command"><div class="scan"></div></div>';
    }

    if (skin === "bridge") {
      return (
        '<div class="trai-v5-bridge" aria-hidden="true">' +
        '<svg viewBox="0 0 1000 420" role="presentation">' +
        '<path class="arch" d="M70 305 Q500 20 930 305"/>' +
        '<path class="deck" d="M55 307 H945"/>' +
        '<path class="support" d="M170 307 V222 M280 307 V150 M390 307 V102 M500 307 V86 M610 307 V102 M720 307 V150 M830 307 V222"/>' +
        '<circle cx="70" cy="305" r="5"/><circle cx="280" cy="150" r="5"/><circle cx="500" cy="86" r="6"/><circle cx="720" cy="150" r="5"/><circle cx="930" cy="305" r="5"/>' +
        "</svg>" +
        "</div>"
      );
    }

    return (
      '<div class="trai-v5-orbits">' +
      Array.from({ length: 5 }, function (_, i) {
        return '<i style="--i:' + i + '"></i>';
      }).join("") +
      "</div>"
    );
  }

  function sourceOrigin(source) {
    if (!(source instanceof Element)) return { x: 50, y: 50 };
    var rect = source.getBoundingClientRect();
    var x = ((rect.left + rect.width / 2) / window.innerWidth) * 100;
    var y = ((rect.top + rect.height / 2) / window.innerHeight) * 100;
    return {
      x: Math.max(0, Math.min(100, x)),
      y: Math.max(0, Math.min(100, y))
    };
  }

  function transitionNode(world, phase, fromWorld, source) {
    if (state.transitionNode) {
      state.transitionNode.remove();
      state.transitionNode = null;
    }

    var origin = sourceOrigin(source);
    var sourceWorld =
      fromWorld ||
      (phase === "departure" ? state.current : null) ||
      state.current ||
      world;
    var overlay = document.createElement("div");
    overlay.className = "trai-v5-transition";
    overlay.dataset.phase = phase;
    overlay.dataset.skin = world.skin || "orbit";
    overlay.dataset.sourceSkin = sourceWorld ? sourceWorld.skin || "orbit" : "orbit";
    overlay.style.setProperty("--accent", world.accent || "#d6a33a");
    overlay.style.setProperty("--secondary", world.secondary || "#5e86c9");
    overlay.style.setProperty("--trai-v5-origin-x", origin.x.toFixed(2) + "%");
    overlay.style.setProperty("--trai-v5-origin-y", origin.y.toFixed(2) + "%");

    overlay.setAttribute("aria-hidden", "true");
    overlay.innerHTML =
      '<div class="trai-v5-transition__veil" aria-hidden="true"></div>' +
      '<div class="trai-v5-transition__field trai-v5-transition__field--source" aria-hidden="true">' +
      geometryHtml(sourceWorld || world) +
      "</div>" +
      '<div class="trai-v5-transition__field trai-v5-transition__field--destination" aria-hidden="true">' +
      geometryHtml(world) +
      "</div>" +
      '<div class="trai-v5-transition__axis" aria-hidden="true"></div>';
    document.body.appendChild(overlay);
    state.transitionNode = overlay;
    return overlay;
  }

  function animateFinite(node, keyframes, options) {
    var duration = Number(options && options.duration) || 0;
    var wait = duration + Number(options && options.delay || 0);

    if (!node || typeof node.animate !== "function") {
      return delay(wait);
    }

    try {
      var animation = node.animate(keyframes, options);
      return animation.finished.catch(function () {
        return undefined;
      });
    } catch {
      return delay(wait);
    }
  }

  function nextPaint() {
    return new Promise(function (resolve) {
      window.requestAnimationFrame(function () {
        window.requestAnimationFrame(resolve);
      });
    });
  }

  async function playDeparture(overlay) {
    if (!overlay) return;

    var sourceField = overlay.querySelector(".trai-v5-transition__field--source");
    var destinationField = overlay.querySelector(".trai-v5-transition__field--destination");
    var copy = overlay.querySelector(".trai-v5-transition__copy");
    var veil = overlay.querySelector(".trai-v5-transition__veil");
    var axis = overlay.querySelector(".trai-v5-transition__axis");
    var ox = getComputedStyle(overlay).getPropertyValue("--trai-v5-origin-x").trim() || "50%";
    var oy = getComputedStyle(overlay).getPropertyValue("--trai-v5-origin-y").trim() || "50%";

    await nextPaint();

    var animations = [
      animateFinite(
        overlay,
        [
          { opacity: 0, clipPath: "circle(0.1% at " + ox + " " + oy + ")", filter: "brightness(.82)" },
          { opacity: 1, clipPath: "circle(44% at " + ox + " " + oy + ")", filter: "brightness(1.05)", offset: .42 },
          { opacity: 1, clipPath: "circle(150% at " + ox + " " + oy + ")", filter: "brightness(1)" }
        ],
        { duration: 1420, easing: "cubic-bezier(.16,1,.3,1)", fill: "forwards" }
      ),
      animateFinite(
        sourceField,
        [
          { opacity: .82, transform: "scale(1)", filter: "blur(0px) saturate(1)" },
          { opacity: .52, transform: "scale(.94)", filter: "blur(2px) saturate(.85)", offset: .48 },
          { opacity: 0, transform: "scale(.82)", filter: "blur(10px) saturate(.55)" }
        ],
        { duration: 1280, easing: "cubic-bezier(.22,.8,.24,1)", fill: "forwards" }
      ),
      animateFinite(
        destinationField,
        [
          { opacity: 0, transform: "scale(1.24) rotate(.8deg)", filter: "blur(12px) saturate(.72)" },
          { opacity: .18, transform: "scale(1.12) rotate(.2deg)", filter: "blur(7px) saturate(.88)", offset: .36 },
          { opacity: .88, transform: "scale(1)", filter: "blur(0px) saturate(1.08)" }
        ],
        { duration: 1560, delay: 120, easing: "cubic-bezier(.16,1,.3,1)", fill: "forwards" }
      ),
      animateFinite(
        copy,
        [
          { opacity: 0, transform: "translateY(24px) scale(.975)", filter: "blur(7px)" },
          { opacity: 1, transform: "translateY(0) scale(1)", filter: "blur(0px)", offset: .58 },
          { opacity: 1, transform: "translateY(-2px) scale(1)", filter: "blur(0px)" }
        ],
        { duration: 1320, delay: 180, easing: "cubic-bezier(.16,1,.3,1)", fill: "forwards" }
      ),
      animateFinite(
        veil,
        [
          { opacity: .15, transform: "scale(.92) rotate(-6deg)" },
          { opacity: .82, transform: "scale(1.08) rotate(2deg)", offset: .68 },
          { opacity: .58, transform: "scale(1.14) rotate(4deg)" }
        ],
        { duration: 1580, easing: "cubic-bezier(.16,1,.3,1)", fill: "forwards" }
      ),
      animateFinite(
        axis,
        [
          { opacity: 0, transform: "translate(-50%,-50%) scaleX(.12)" },
          { opacity: .82, transform: "translate(-50%,-50%) scaleX(1)", offset: .62 },
          { opacity: .38, transform: "translate(-50%,-50%) scaleX(1.08)" }
        ],
        { duration: 1380, delay: 120, easing: "cubic-bezier(.16,1,.3,1)", fill: "forwards" }
      )
    ];

    await Promise.allSettled(animations);
    await delay(180);
  }

  async function playArrival(overlay) {
    if (!overlay) return;

    var sourceField = overlay.querySelector(".trai-v5-transition__field--source");
    var destinationField = overlay.querySelector(".trai-v5-transition__field--destination");
    var copy = overlay.querySelector(".trai-v5-transition__copy");
    var veil = overlay.querySelector(".trai-v5-transition__veil");
    var axis = overlay.querySelector(".trai-v5-transition__axis");

    sourceField.style.opacity = ".34";
    destinationField.style.opacity = ".92";
    destinationField.style.transform = "scale(1)";
    destinationField.style.filter = "blur(0px) saturate(1.06)";
    overlay.style.opacity = "1";

    await nextPaint();

    document.documentElement.classList.remove("trai-v5-pending-arrival");
    if (pendingArrivalStyle) {
      pendingArrivalStyle.remove();
      pendingArrivalStyle = null;
    }

    var animations = [
      animateFinite(
        destinationField,
        [
          { opacity: .96, transform: "scale(.98)", filter: "blur(0px) saturate(1.12)" },
          { opacity: .72, transform: "scale(1.05)", filter: "blur(1px) saturate(1)", offset: .55 },
          { opacity: 0, transform: "scale(1.18)", filter: "blur(10px) saturate(.72)" }
        ],
        { duration: 1680, easing: "cubic-bezier(.16,1,.3,1)", fill: "forwards" }
      ),
      animateFinite(
        sourceField,
        [
          { opacity: .34, transform: "scale(.88)", filter: "blur(7px)" },
          { opacity: 0, transform: "scale(.72)", filter: "blur(13px)" }
        ],
        { duration: 820, easing: "ease-out", fill: "forwards" }
      ),
      animateFinite(
        copy,
        [
          { opacity: 1, transform: "translateY(0) scale(1)", filter: "blur(0px)" },
          { opacity: .92, transform: "translateY(-4px) scale(1)", filter: "blur(0px)", offset: .52 },
          { opacity: 0, transform: "translateY(-20px) scale(1.018)", filter: "blur(7px)" }
        ],
        { duration: 1420, delay: 120, easing: "cubic-bezier(.4,0,.2,1)", fill: "forwards" }
      ),
      animateFinite(
        axis,
        [
          { opacity: .7, transform: "translate(-50%,-50%) scaleX(1)" },
          { opacity: 0, transform: "translate(-50%,-50%) scaleX(1.24)" }
        ],
        { duration: 1260, delay: 160, easing: "ease-out", fill: "forwards" }
      ),
      animateFinite(
        veil,
        [
          { opacity: .68, transform: "scale(1.12) rotate(3deg)" },
          { opacity: 0, transform: "scale(1.26) rotate(8deg)" }
        ],
        { duration: 1560, easing: "cubic-bezier(.4,0,.2,1)", fill: "forwards" }
      ),
      animateFinite(
        overlay,
        [
          { opacity: 1, clipPath: "circle(150% at 50% 50%)" },
          { opacity: 1, clipPath: "circle(150% at 50% 50%)", offset: .36 },
          { opacity: .72, clipPath: "circle(82% at 50% 50%)", offset: .7 },
          { opacity: 0, clipPath: "circle(0% at 50% 50%)" }
        ],
        { duration: 1780, delay: 160, easing: "cubic-bezier(.4,0,.2,1)", fill: "forwards" }
      )
    ];

    await Promise.allSettled(animations);
  }

  function protocolUrl(world) {
    var url = new URL(world.url);
    url.searchParams.set("trai_v", "5.2");
    url.searchParams.set("trai_from", SELF);
    url.searchParams.set("trai_to", world.id);
    url.searchParams.set("trai_tx", Date.now().toString(36));
    return url.href;
  }

  async function transitionToWorld(world, source) {
    if (!world || !world.url || world.id === SELF || state.busy) return;

    state.busy = true;
    closePortal();

    if (reducedMotion) {
      await delay(90);
      window.location.assign(protocolUrl(world));
      return;
    }

    var overlay = transitionNode(world, "departure", state.current, source);

    try {
      await playDeparture(overlay);
    } catch (error) {
      console.error("[TRAI Organism v5.3] departure fallback", error);
      await delay(980);
    }
    window.location.assign(protocolUrl(world));
  }

  function cleanProtocolUrl(url) {
    ["trai_v", "trai_from", "trai_to", "trai_tx"].forEach(function (key) {
      url.searchParams.delete(key);
    });
    var clean =
      url.pathname +
      (url.searchParams.toString() ? "?" + url.searchParams.toString() : "") +
      url.hash;
    window.history.replaceState(window.history.state, "", clean);
  }

  async function maybeArrival() {
    var url = new URL(window.location.href);
    var protocolVersion = url.searchParams.get("trai_v");
    if (protocolVersion !== "5" && protocolVersion !== "5.2") {
      document.documentElement.classList.remove("trai-v5-pending-arrival");
      if (pendingArrivalStyle) {
        pendingArrivalStyle.remove();
        pendingArrivalStyle = null;
      }
      return;
    }
    if (url.searchParams.get("trai_to") !== SELF) return;

    var fromId = url.searchParams.get("trai_from");
    var fromWorld = state.worlds.get(fromId) || null;
    cleanProtocolUrl(url);

    if (reducedMotion || !state.current) {
      document.documentElement.classList.remove("trai-v5-pending-arrival");
      if (pendingArrivalStyle) {
        pendingArrivalStyle.remove();
        pendingArrivalStyle = null;
      }
      return;
    }

    var overlay = transitionNode(state.current, "arrival", fromWorld, null);

    try {
      await playArrival(overlay);
    } finally {
      if (overlay === state.transitionNode) state.transitionNode = null;
      overlay.remove();
      document.documentElement.classList.remove("trai-v5-pending-arrival");
      if (pendingArrivalStyle) {
        pendingArrivalStyle.remove();
        pendingArrivalStyle = null;
      }
    }
  }

  function pulseInternal(source) {
    if (reducedMotion || !state.current) return null;
    var point = sourceOrigin(source);
    var pulse = document.createElement("div");
    pulse.className = "trai-v5-internal-pulse";
    pulse.style.setProperty("--accent", state.current.accent || "#d6a33a");
    pulse.style.setProperty("--trai-v5-x", point.x.toFixed(2) + "%");
    pulse.style.setProperty("--trai-v5-y", point.y.toFixed(2) + "%");
    document.body.appendChild(pulse);
    window.setTimeout(function () {
      pulse.remove();
    }, 820);
    return pulse;
  }

  async function transitionInternal(callback, options) {
    if (typeof callback !== "function") return;
    options = options || {};
    var source = options.source || null;

    if (reducedMotion) {
      callback();
      return;
    }

    pulseInternal(source);
    document.documentElement.dataset.traiV5Internal = "true";

    if (typeof document.startViewTransition === "function") {
      var transition = document.startViewTransition(function () {
        callback();
      });
      try {
        await transition.finished;
      } catch {
        callback();
      } finally {
        delete document.documentElement.dataset.traiV5Internal;
      }
      return;
    }

    var veil = document.createElement("div");
    veil.className = "trai-v5-internal-pulse";
    veil.style.setProperty("--accent", state.current ? state.current.accent || "#d6a33a" : "#d6a33a");
    veil.style.setProperty("--trai-v5-x", sourceOrigin(source).x.toFixed(2) + "%");
    veil.style.setProperty("--trai-v5-y", sourceOrigin(source).y.toFixed(2) + "%");
    document.body.appendChild(veil);
    await delay(160);
    callback();
    await delay(460);
    veil.remove();
    delete document.documentElement.dataset.traiV5Internal;
  }

  function routeChanged(path) {
    var next = String(path || window.location.pathname);
    if (next === state.routePath) return;
    state.routePath = next;
    pulseInternal(null);
  }

  function rememberInternalArrival() {
    try {
      window.sessionStorage.setItem(
        "trai:v5.3:internal-arrival",
        JSON.stringify({ world: SELF, at: Date.now() })
      );
    } catch {
      return;
    }
  }

  async function maybeInternalArrival() {
    var payload = null;
    try {
      payload = JSON.parse(
        window.sessionStorage.getItem("trai:v5.3:internal-arrival") || "null"
      );
      window.sessionStorage.removeItem("trai:v5.3:internal-arrival");
    } catch {
      payload = null;
    }

    if (
      !payload ||
      payload.world !== SELF ||
      Date.now() - Number(payload.at || 0) > 8000 ||
      reducedMotion
    ) {
      return;
    }

    var pulse = pulseInternal(null);
    if (pulse) {
      pulse.style.opacity = "1";
      await delay(720);
    }
  }

  async function staticInternalNavigation(url, source) {
    if (state.busy) return;
    state.busy = true;

    if (reducedMotion) {
      window.location.assign(url.href);
      return;
    }

    rememberInternalArrival();
    var pulse = pulseInternal(source);
    if (pulse) {
      await animateFinite(
        pulse,
        [
          { opacity: 0, transform: "scale(.96)" },
          { opacity: 1, transform: "scale(1.02)", offset: .48 },
          { opacity: .94, transform: "scale(1.06)" }
        ],
        { duration: 620, easing: "cubic-bezier(.16,1,.3,1)", fill: "forwards" }
      );
    } else {
      await delay(420);
    }
    window.location.assign(url.href);
  }

  function isPlainPrimaryClick(event) {
    return (
      event.button === 0 &&
      !event.metaKey &&
      !event.ctrlKey &&
      !event.shiftKey &&
      !event.altKey
    );
  }

  function gateNavigationEvent(event) {
    event.preventDefault();
    event.stopPropagation();
    if (typeof event.stopImmediatePropagation === "function") {
      event.stopImmediatePropagation();
    }
  }

  function onDocumentClick(event) {
    var anchor = event.target && event.target.closest
      ? event.target.closest("a[href]")
      : null;

    if (!anchor) {
      var trigger = event.target && event.target.closest
        ? event.target.closest("[data-trai-world]")
        : null;
      if (trigger && trigger.dataset.traiWorld) {
        var triggeredWorld = state.worlds.get(trigger.dataset.traiWorld);
        if (triggeredWorld && triggeredWorld.id !== SELF) {
          if (!isPlainPrimaryClick(event)) return;
          gateNavigationEvent(event);
          openPortal(triggeredWorld.id, trigger);
        }
      }
      return;
    }

    updateAnchor(anchor);

    var raw = anchor.getAttribute("href");
    if (!raw) return;

    var url;
    try {
      url = new URL(raw, window.location.href);
    } catch {
      return;
    }

    var world = matchWorldUrl(url);

    if (world && world.id !== SELF) {
      if (!isPlainPrimaryClick(event)) return;
      gateNavigationEvent(event);
      openPortal(world.id, anchor);
      return;
    }

    if (
      url.origin === window.location.origin &&
      anchor.target !== "_blank" &&
      isPlainPrimaryClick(event)
    ) {
      if (STATIC_NAVIGATION && url.href !== window.location.href) {
        gateNavigationEvent(event);
        void staticInternalNavigation(url, anchor);
      } else {
        pulseInternal(anchor);
      }
    }
  }

  function delay(ms) {
    return new Promise(function (resolve) {
      window.setTimeout(resolve, ms);
    });
  }

  function observeAnchors() {
    var observer = new MutationObserver(function (records) {
      records.forEach(function (record) {
        record.addedNodes.forEach(function (node) {
          if (node.nodeType === Node.ELEMENT_NODE) {
            rewriteAnchors(node);
          }
        });
      });
    });
    observer.observe(document.documentElement, {
      subtree: true,
      childList: true
    });
  }

  function validateManifestIntegrity(manifest) {
    var seenIds = new Set();
    var seenNames = new Set();
    var seenUrls = new Set();

    manifest.worlds.forEach(function (world) {
      var id = String(world.id || "").trim();
      var name = String(world.name || "").trim();
      var url = String(world.url || "").trim();

      if (!id || !name || !url) {
        throw new Error("TRAI Organism world identity is incomplete.");
      }

      var normalizedId = id.toLowerCase();
      var normalizedName = name.toLowerCase();
      var normalizedUrl = new URL(url, window.location.href).href
        .replace(/[?#].*$/, "")
        .replace(/\/$/, "");

      if (seenIds.has(normalizedId)) {
        throw new Error("Duplicate TRAI Organism world id: " + id);
      }
      if (seenNames.has(normalizedName)) {
        throw new Error("Duplicate TRAI Organism world name: " + name);
      }
      if (seenUrls.has(normalizedUrl)) {
        throw new Error("Duplicate TRAI Organism world URL: " + url);
      }

      seenIds.add(normalizedId);
      seenNames.add(normalizedName);
      seenUrls.add(normalizedUrl);
    });
  }

  async function boot() {
    injectCss();

    var response = await fetch(manifestUrl, {
      cache: "no-store",
      credentials: "same-origin"
    });

    if (!response.ok) {
      throw new Error("TRAI Organism manifest failed: HTTP " + response.status);
    }

    var manifest = await response.json();
    if (!manifest || !Array.isArray(manifest.worlds)) {
      throw new Error("TRAI Organism manifest is invalid.");
    }

    validateManifestIntegrity(manifest);
    state.manifest = manifest;
    manifest.worlds.forEach(function (world) {
      state.worlds.set(world.id, world);
    });
    state.current = state.worlds.get(SELF) || null;

    if (!state.current) {
      throw new Error("TRAI Organism world is not registered: " + SELF);
    }

    setCurrentTheme();
    rewriteAnchors(document);
    buildPortal();
    buildLauncher();
    preconnectWorlds();
    observeAnchors();

    document.addEventListener("click", onDocumentClick, true);
    void maybeArrival();
    void maybeInternalArrival();

    window.TRAIOrganismV5 = {
      version: VERSION,
      world: SELF,
      manifest: manifest,
      open: function (id, source) {
        openPortal(id || SELF, source || null);
      },
      close: closePortal,
      navigate: function (id, source) {
        var world = state.worlds.get(id);
        if (world) void transitionToWorld(world, source || null);
      },
      transitionInternal: transitionInternal,
      routeChanged: routeChanged,
      rewriteAnchors: function () {
        rewriteAnchors(document);
      }
    };

    window.dispatchEvent(
      new CustomEvent("trai:organism-ready", {
        detail: {
          version: VERSION,
          world: SELF,
          manifest: manifest
        }
      })
    );
  }

  function start() {
    boot().catch(function (error) {
      console.error("[TRAI Organism v5.3]", error);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, { once: true });
  } else {
    start();
  }
})();

/* TRAI Organism v5.4 — silent holographic interaction field */
(function installTraiV54HolographicField() {
  if (window.__TRAI_ORGANISM_V54_HOLOGRAM__) return;
  window.__TRAI_ORGANISM_V54_HOLOGRAM__ = true;

  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const root = document.createElement("div");
  root.className = "trai-v54-hologram";
  root.setAttribute("aria-hidden", "true");
  root.innerHTML = `
    <div class="trai-v54-grid"></div>
    <div class="trai-v54-orbit trai-v54-orbit-a"></div>
    <div class="trai-v54-orbit trai-v54-orbit-b"></div>
    <div class="trai-v54-orbit trai-v54-orbit-c"></div>
    <div class="trai-v54-core"></div>
    <div class="trai-v54-beam"></div>
  `;

  const style = document.createElement("style");
  style.textContent = `
    .trai-v54-hologram{
      --v54-x:50vw;--v54-y:50vh;
      position:fixed;inset:0;z-index:2147482500;pointer-events:none;
      perspective:1100px;overflow:hidden;opacity:.42;
      mix-blend-mode:screen;
      transition:opacity .45s ease;
    }
    .trai-v54-grid{
      position:absolute;left:50%;top:50%;width:90vmax;height:90vmax;
      transform:translate(-50%,-50%) rotateX(68deg) translateZ(-180px);
      background:
        linear-gradient(rgba(80,220,255,.08) 1px,transparent 1px),
        linear-gradient(90deg,rgba(255,196,72,.07) 1px,transparent 1px);
      background-size:42px 42px;
      mask-image:radial-gradient(circle at center,black 0 24%,transparent 72%);
      animation:v54-grid-drift 18s linear infinite;
    }
    .trai-v54-orbit{
      position:absolute;left:var(--v54-x);top:var(--v54-y);
      border:1px solid rgba(103,232,249,.28);border-radius:50%;
      transform-style:preserve-3d;
      box-shadow:0 0 34px rgba(34,211,238,.12),inset 0 0 34px rgba(255,194,70,.05);
      transition:left .14s linear,top .14s linear;
    }
    .trai-v54-orbit-a{width:270px;height:270px;margin:-135px;animation:v54-orbit-a 11s linear infinite}
    .trai-v54-orbit-b{width:390px;height:190px;margin:-95px -195px;animation:v54-orbit-b 14s linear infinite}
    .trai-v54-orbit-c{width:180px;height:470px;margin:-235px -90px;border-color:rgba(255,190,70,.2);animation:v54-orbit-c 17s linear infinite}
    .trai-v54-core{
      position:absolute;left:var(--v54-x);top:var(--v54-y);width:12px;height:12px;margin:-6px;
      border-radius:50%;background:rgba(218,248,255,.95);
      box-shadow:0 0 14px #fff,0 0 34px rgba(34,211,238,.85),0 0 70px rgba(255,184,56,.45);
      transition:left .12s linear,top .12s linear,transform .28s ease;
    }
    .trai-v54-beam{
      position:absolute;left:var(--v54-x);top:0;width:1px;height:100%;
      background:linear-gradient(transparent,rgba(103,232,249,.13),rgba(255,193,65,.16),transparent);
      transform:translateX(-.5px);transition:left .12s linear;
    }
    .trai-v54-hologram[data-pulse="true"] .trai-v54-core{transform:scale(3.6)}
    .trai-v54-hologram[data-pulse="true"]{opacity:.78}
    @keyframes v54-grid-drift{to{transform:translate(-50%,-50%) rotateX(68deg) rotateZ(360deg) translateZ(-180px)}}
    @keyframes v54-orbit-a{to{transform:rotateX(72deg) rotateZ(360deg)}}
    @keyframes v54-orbit-b{from{transform:rotateY(66deg) rotateZ(0)}to{transform:rotateY(66deg) rotateZ(-360deg)}}
    @keyframes v54-orbit-c{from{transform:rotateX(18deg) rotateY(72deg) rotateZ(0)}to{transform:rotateX(18deg) rotateY(72deg) rotateZ(360deg)}}
    @media (prefers-reduced-motion:reduce){
      .trai-v54-grid,.trai-v54-orbit{animation:none!important}
      .trai-v54-hologram{opacity:.18}
    }
  `;

  document.head.appendChild(style);
  document.body.appendChild(root);

  if (!reduceMotion) {
    window.addEventListener("pointermove", (event) => {
      root.style.setProperty("--v54-x", `${event.clientX}px`);
      root.style.setProperty("--v54-y", `${event.clientY}px`);
    }, { passive: true });

    window.addEventListener("pointerdown", () => {
      root.dataset.pulse = "true";
      window.setTimeout(() => { root.dataset.pulse = "false"; }, 420);
    }, { passive: true });
  }
})();
