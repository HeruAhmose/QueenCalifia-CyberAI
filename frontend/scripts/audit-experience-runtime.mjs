import { spawn } from "node:child_process";
import fs from "node:fs/promises";

const PORT = 4189;
const ROOT = "/tmp/qc-experience-pages";
const BASE = `http://127.0.0.1:${PORT}/QueenCalifia-CyberAI/`;
const CDP_HTTP = "http://127.0.0.1:9239";
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

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
    this.ws.addEventListener("message", (event) => {
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
  { stdio: "ignore" },
);
let cdp;

try {
  await waitFor(BASE);
  await waitFor(`${CDP_HTTP}/json/version`);
  const targets = await (await fetch(`${CDP_HTTP}/json/list`)).json();
  const target = targets.find((item) => item.type === "page");
  if (!target?.webSocketDebuggerUrl) throw new Error("no page target");

  cdp = new CDP(target.webSocketDebuggerUrl);
  await cdp.open();
  await cdp.send("Page.enable");
  await cdp.send("Runtime.enable");
  await cdp.send("Page.addScriptToEvaluateOnNewDocument", {
    source: `(() => {
      window.__qcLayoutProbe = { maxOverflow: 0, maxScrollX: 0, transformedShell: false };
      function sampleLayout() {
        const root = document.documentElement;
        if (root) {
          window.__qcLayoutProbe.maxOverflow = Math.max(window.__qcLayoutProbe.maxOverflow, root.scrollWidth - root.clientWidth);
          window.__qcLayoutProbe.maxScrollX = Math.max(window.__qcLayoutProbe.maxScrollX, Math.abs(window.scrollX));
          if (matchMedia('(prefers-reduced-motion: reduce)').matches) {
            for (const shell of document.querySelectorAll('[data-qc-shell-motion]')) {
              const style = getComputedStyle(shell);
              const scaled = style.transform !== 'none' && !new DOMMatrixReadOnly(style.transform).isIdentity;
              if (scaled || (style.filter !== 'none' && style.filter !== 'blur(0px)')) {
                window.__qcLayoutProbe.transformedShell = true;
              }
            }
          }
        }
        requestAnimationFrame(sampleLayout);
      }
      requestAnimationFrame(sampleLayout);
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
  await cdp.eval(
    `localStorage.removeItem('qc_audio_enabled');
     for (const storage of [localStorage, sessionStorage]) {
       storage.setItem('qc_api_key', 'legacy-test-credential');
       storage.setItem('qc_admin_key', 'legacy-test-admin');
     }
     location.reload(); true`,
  );
  await sleep(1200);

  const legacyCredentialsCleared = await cdp.eval(
    `[localStorage, sessionStorage].every(storage =>
      storage.getItem('qc_api_key') === null && storage.getItem('qc_admin_key') === null)`,
  );
  if (!legacyCredentialsCleared) throw new Error("legacy credentials remain in browser storage");

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
    `getComputedStyle(document.querySelector('.qc-awaken-holo-scan')).top`,
  );
  if (scanTopAfter === initial.scanTop) {
    throw new Error(
      `holographic scan did not visibly move: ${initial.scanTop} -> ${scanTopAfter}`,
    );
  }

  await cdp.eval(
    `([...document.querySelectorAll('button')].find(button => button.textContent.includes('AWAKEN SOVEREIGN INTELLIGENCE')))?.click(); true`,
  );
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
      `awakening improperly changed audio consent ${JSON.stringify(afterAwaken)}`,
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
  await cdp.eval(
    `([...document.querySelectorAll('button')].find(button => button.textContent.includes('ENTER COMMAND FIELD')))?.click(); true`,
  );
  let commandSettled = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    commandSettled = await cdp.eval(`(() => {
      const shell = document.querySelector('[data-qc-shell-motion="dashboard"]');
      if (!shell || !shell.querySelector('[data-qc-command-frame]')) return false;
      const style = getComputedStyle(shell);
      return style.opacity === '1' && (style.transform === 'none' || new DOMMatrixReadOnly(style.transform).isIdentity);
    })()`);
    if (commandSettled) break;
    await sleep(100);
  }
  if (!commandSettled)
    throw new Error("command field transition did not finish");
  const mutedAfter = await cdp.eval(`window.__qcAudioProbe.oscillators`);
  if (mutedAfter !== mutedBefore) {
    throw new Error(
      `mute failed to suppress command SFX ${mutedBefore}->${mutedAfter}`,
    );
  }

  const layout = await cdp.eval(`(() => ({
    transition: window.__qcLayoutProbe,
    broken: [...document.images]
      .filter(image => image.complete && image.naturalWidth === 0)
      .map(image => image.src),
    overflow: Math.max(0, document.documentElement.scrollWidth - document.documentElement.clientWidth)
  }))()`);
  if (
    layout.broken.length ||
    layout.overflow > 1 ||
    layout.transition.maxOverflow > 1 ||
    layout.transition.maxScrollX > 0
  ) {
    throw new Error(`layout/assets failed ${JSON.stringify(layout)}`);
  }

  await cdp.eval(`document.querySelector('#tab-vulns')?.click(); true`);
  let credentialInputReady = false;
  for (let attempt = 0; attempt < 50; attempt++) {
    credentialInputReady = await cdp.eval(`Boolean(document.querySelector('input[placeholder^="API key (X-QC-API-Key)"]'))`);
    if (credentialInputReady) break;
    await sleep(100);
  }
  if (!credentialInputReady) throw new Error("scanner credential input did not appear");
  await cdp.eval(`(() => {
    const input = document.querySelector('input[placeholder^="API key (X-QC-API-Key)"]');
    input.focus();
  })()`);
  await cdp.send("Input.insertText", { text: "memory-only-test-credential" });
  await sleep(100);
  const credentialsMemoryOnly = await cdp.eval(`(() => {
    const input = document.querySelector('input[placeholder^="API key (X-QC-API-Key)"]');
    return input.value === 'memory-only-test-credential' &&
      [localStorage, sessionStorage].every(storage =>
        storage.getItem('qc_api_key') === null && storage.getItem('qc_admin_key') === null);
  })()`);
  if (!credentialsMemoryOnly) throw new Error("scanner persisted an API credential");

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
    transition: window.__qcLayoutProbe,
    overflow: Math.max(0, document.documentElement.scrollWidth - document.documentElement.clientWidth)
  }))()`);
  if (
    !reduced.media ||
    reduced.awakening !== 0 ||
    reduced.scan !== 0 ||
    reduced.command < 1 ||
    reduced.probe.contexts !== 0 ||
    reduced.probe.oscillators !== 0 ||
    reduced.overflow > 1 ||
    reduced.transition.maxOverflow > 1 ||
    reduced.transition.maxScrollX > 0 ||
    reduced.transition.transformedShell
  ) {
    throw new Error(
      `reduced-motion/audio contract failed ${JSON.stringify(reduced)}`,
    );
  }

  const report = {
    initial,
    motion: { before: initial.scanTop, after: scanTopAfter },
    afterAwaken,
    enabled,
    muted: { before: mutedBefore, after: mutedAfter },
    layout,
    credentials: { legacyCredentialsCleared, credentialsMemoryOnly },
    reduced,
    failures: 0,
  };
  await fs.writeFile(
    "qc-experience-audit.json",
    JSON.stringify(report, null, 2),
  );
  console.log("QC_EXPERIENCE_AUDIO=PASS");
  console.log(JSON.stringify(report));
} finally {
  cdp?.close();
  if (!server.killed) server.kill("SIGTERM");
}
