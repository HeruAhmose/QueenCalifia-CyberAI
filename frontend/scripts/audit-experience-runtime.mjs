import { spawn } from "node:child_process";
import fs from "node:fs/promises";

const PORT = 4189;
const ROOT = "/tmp/qc-experience-pages";
const BASE = `http://127.0.0.1:${PORT}/QueenCalifia-CyberAI/`;
const CDP_HTTP = process.env.QC_CDP_URL || "http://127.0.0.1:9239";
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function waitFor(url, attempts = 80) {
  for (let i = 0; i < attempts; i++) {
    try {
      const response = await fetch(url);
      if (response.ok) return response;
    } catch {}
    await sleep(250);
  }
  throw new Error(`timeout ${url}`);
}

class CDP {
  constructor(url) {
    this.url = url;
    this.id = 0;
    this.pending = new Map();
  }
  async open() {
    this.ws = new WebSocket(this.url);
    await new Promise((resolve, reject) => {
      this.ws.addEventListener("open", resolve, { once: true });
      this.ws.addEventListener("error", reject, { once: true });
    });
    this.ws.addEventListener("message", event => {
      const msg = JSON.parse(event.data);
      if (msg.id && this.pending.has(msg.id)) {
        const pending = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        msg.error
          ? pending.reject(new Error(JSON.stringify(msg.error)))
          : pending.resolve(msg.result);
      }
    });
  }
  send(method, params = {}) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }
  async eval(expression) {
    const result = await this.send("Runtime.evaluate", {
      expression,
      awaitPromise: true,
      returnByValue: true,
    });
    if (result.exceptionDetails) {
      throw new Error(result.exceptionDetails.text || "evaluation failed");
    }
    return result.result.value;
  }
  close() {
    this.ws?.close();
  }
}

await fs.rm(ROOT, { recursive: true, force: true });
await fs.mkdir(`${ROOT}/QueenCalifia-CyberAI`, { recursive: true });
await fs.cp("dist", `${ROOT}/QueenCalifia-CyberAI`, { recursive: true });
const server = spawn(
  "python3",
  ["-m", "http.server", String(PORT), "--directory", ROOT],
  { stdio: "ignore" }
);
let cdp;

try {
  await waitFor(BASE);
  await waitFor(`${CDP_HTTP}/json/version`);
  const targets = await (await fetch(`${CDP_HTTP}/json/list`)).json();
  const target = targets.find(item => item.type === "page");
  if (!target?.webSocketDebuggerUrl) throw new Error("no page target");

  cdp = new CDP(target.webSocketDebuggerUrl);
  await cdp.open();
  await cdp.send("Page.enable");
  await cdp.send("Runtime.enable");
  await cdp.send("Page.addScriptToEvaluateOnNewDocument", {
    source: `(() => {
      const Native = window.AudioContext || window.webkitAudioContext;
      window.__qcAudioProbe = { contexts: 0, oscillators: 0 };
      if (!Native) return;
      const Wrapped = new Proxy(Native, {
        construct(Target, args) {
          const ctx = new Target(...args);
          window.__qcAudioProbe.contexts++;
          const nativeOscillator = ctx.createOscillator.bind(ctx);
          ctx.createOscillator = (...oscArgs) => {
            window.__qcAudioProbe.oscillators++;
            return nativeOscillator(...oscArgs);
          };
          return ctx;
        }
      });
      window.AudioContext = Wrapped;
      if (window.webkitAudioContext) window.webkitAudioContext = Wrapped;
    })();`,
  });

  await cdp.send("Page.navigate", { url: BASE });
  await sleep(1200);
  await cdp.eval(`localStorage.removeItem('qc_audio_enabled'); location.reload(); true`);
  await sleep(1200);

  const initial = await cdp.eval(`(() => ({
    sound: document.querySelector('[data-qc-sound]')?.dataset.qcSound,
    pressed: document.querySelector('[data-qc-sound]')?.getAttribute('aria-pressed'),
    probe: window.__qcAudioProbe,
    phase: document.querySelector('.qc-sovereign-awakening')?.dataset.qcAwakeningPhase,
    scanTop: document.querySelector('.qc-awaken-holo-scan') ? getComputedStyle(document.querySelector('.qc-awaken-holo-scan')).top : null,
    favicons: [...document.querySelectorAll('link[rel~="icon"]')].map(link => link.href),
    manifest: document.querySelector('link[rel="manifest"]')?.href || null
  }))()`);
  if (
    initial.sound !== "off" ||
    initial.pressed !== "false" ||
    initial.probe.contexts !== 0 ||
    initial.probe.oscillators !== 0 ||
    initial.phase !== "sealed"
  ) {
    throw new Error(`initial audio contract failed ${JSON.stringify(initial)}`);
  }
  if (initial.favicons.length < 1 || !initial.manifest) {
    throw new Error("favicon/manifest binding missing");
  }
  if (!initial.scanTop) throw new Error("holographic scan line missing");

  await sleep(500);
  const scanTopAfter = await cdp.eval(
    `getComputedStyle(document.querySelector('.qc-awaken-holo-scan')).top`
  );
  if (scanTopAfter === initial.scanTop) {
    throw new Error(
      `holographic scan did not visibly move: ${initial.scanTop} -> ${scanTopAfter}`
    );
  }

  await cdp.eval(`([...document.querySelectorAll('button')].find(button => button.textContent.includes('AWAKEN SOVEREIGN INTELLIGENCE')))?.click(); true`);
  await sleep(350);
  const afterAwaken = await cdp.eval(`(() => ({
    sound: document.querySelector('[data-qc-sound]')?.dataset.qcSound,
    probe: window.__qcAudioProbe,
    phase: document.querySelector('.qc-sovereign-awakening')?.dataset.qcAwakeningPhase
  }))()`);
  if (
    afterAwaken.sound !== "off" ||
    afterAwaken.probe.contexts !== 0 ||
    afterAwaken.probe.oscillators !== 0 ||
    afterAwaken.phase !== "linking"
  ) {
    throw new Error(
      `awakening improperly changed audio consent ${JSON.stringify(afterAwaken)}`
    );
  }

  await cdp.eval(`document.querySelector('[data-qc-sound]')?.click(); true`);
  await sleep(350);
  const enabled = await cdp.eval(`(() => ({
    sound: document.querySelector('[data-qc-sound]')?.dataset.qcSound,
    probe: window.__qcAudioProbe
  }))()`);
  if (
    enabled.sound !== "on" ||
    enabled.probe.contexts < 1 ||
    enabled.probe.oscillators < 1
  ) {
    throw new Error(`explicit sound opt-in failed ${JSON.stringify(enabled)}`);
  }

  await cdp.eval(`document.querySelector('[data-qc-sound]')?.click(); true`);
  await sleep(300);
  const mutedBefore = await cdp.eval(`window.__qcAudioProbe.oscillators`);
  await sleep(1800);
  await cdp.eval(`([...document.querySelectorAll('button')].find(button => button.textContent.includes('ENTER COMMAND FIELD')))?.click(); true`);
  await sleep(250);
  const mutedAfter = await cdp.eval(`window.__qcAudioProbe.oscillators`);
  if (mutedAfter !== mutedBefore) {
    throw new Error(
      `mute failed to suppress command SFX ${mutedBefore}->${mutedAfter}`
    );
  }

  const layout = await cdp.eval(`(() => ({
    broken: [...document.images]
      .filter(image => image.complete && image.naturalWidth === 0)
      .map(image => image.src),
    overflow: Math.max(0, document.documentElement.scrollWidth - document.documentElement.clientWidth)
  }))()`);
  if (layout.broken.length || layout.overflow > 1) {
    throw new Error(`layout/assets failed ${JSON.stringify(layout)}`);
  }

  await cdp.send("Emulation.setEmulatedMedia", {
    features: [{ name: "prefers-reduced-motion", value: "reduce" }],
  });
  await cdp.send("Page.navigate", { url: BASE });
  await sleep(1200);
  const reduced = await cdp.eval(`(() => ({
    media: matchMedia('(prefers-reduced-motion: reduce)').matches,
    awakening: document.querySelectorAll('.qc-sovereign-awakening').length,
    scan: document.querySelectorAll('.qc-awaken-holo-scan').length,
    command: document.querySelectorAll('[data-qc-command-frame="prestige-v1"]').length,
    probe: window.__qcAudioProbe,
    overflow: Math.max(0, document.documentElement.scrollWidth - document.documentElement.clientWidth)
  }))()`);
  if (
    !reduced.media ||
    reduced.awakening !== 0 ||
    reduced.scan !== 0 ||
    reduced.command < 1 ||
    reduced.probe.contexts !== 0 ||
    reduced.probe.oscillators !== 0 ||
    reduced.overflow > 1
  ) {
    throw new Error(
      `reduced-motion/audio contract failed ${JSON.stringify(reduced)}`
    );
  }

  const report = {
    initial,
    motion: { before: initial.scanTop, after: scanTopAfter },
    afterAwaken,
    enabled,
    muted: { before: mutedBefore, after: mutedAfter },
    layout,
    reduced,
    failures: 0,
  };
  await fs.writeFile(
    "qc-experience-audit.json",
    JSON.stringify(report, null, 2)
  );
  console.log("QC_EXPERIENCE_AUDIO=PASS");
  console.log(JSON.stringify(report));
} finally {
  cdp?.close();
  if (!server.killed) server.kill("SIGTERM");
}
