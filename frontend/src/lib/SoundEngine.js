/**
 * Queen Califia CyberAI — Sovereign Sound Engine v4.1
 * Procedurally generated cinematic sounds via Web Audio API
 * 16 unique sound types for the digital goddess experience
 * 
 * Sound Types:
 *   sovereign_awaken   — Cinematic intro deep bass + golden shimmer
 *   tab_switch         — Navigation whoosh + click
 *   panel_hover        — Electromagnetic hum
 *   panel_click        — Crystalline tap
 *   threat_alert       — Critical threat alarm pulse
 *   scan_start         — Charging beam
 *   scan_complete      — Success chime
 *   data_tick          — Subtle tick
 *   avatar_transition  — Energy shift
 *   modal_open         — Portal sound
 *   modal_close        — Reverse portal
 *   prediction_reveal  — Oracle whisper
 *   incident_escalate  — Warning surge
 *   mesh_pulse         — Deep pulse
 *   ambient_drone      — Low frequency hum
 *   button_click       — Tactile snap
 */

let audioCtx = null;
let masterGain = null;
let ambientOsc = null;
let ambientGain = null;
let isAmbientPlaying = false;

function getCtx() {
  if (!audioCtx) {
    audioCtx = new AudioContext();
    masterGain = audioCtx.createGain();
    masterGain.gain.value = 0.3;
    masterGain.connect(audioCtx.destination);
  }
  if (audioCtx.state === 'suspended') {
    audioCtx.resume();
  }
  return audioCtx;
}

function getMaster() {
  getCtx();
  return masterGain;
}

export function setMasterVolume(v) {
  const g = getMaster();
  g.gain.setTargetAtTime(Math.max(0, Math.min(1, v)), getCtx().currentTime, 0.05);
}

export function startAmbient() {
  if (isAmbientPlaying) return;
  const ctx = getCtx();
  const master = getMaster();
  
  ambientGain = ctx.createGain();
  ambientGain.gain.value = 0;
  ambientGain.connect(master);
  
  ambientOsc = ctx.createOscillator();
  ambientOsc.type = 'sine';
  ambientOsc.frequency.value = 42;
  
  const filter = ctx.createBiquadFilter();
  filter.type = 'lowpass';
  filter.frequency.value = 80;
  filter.Q.value = 2;
  
  ambientOsc.connect(filter);
  filter.connect(ambientGain);
  ambientOsc.start();
  
  const lfo = ctx.createOscillator();
  lfo.type = 'sine';
  lfo.frequency.value = 0.08;
  const lfoGain = ctx.createGain();
  lfoGain.gain.value = 3;
  lfo.connect(lfoGain);
  lfoGain.connect(ambientOsc.frequency);
  lfo.start();
  
  ambientGain.gain.setTargetAtTime(0.06, ctx.currentTime, 2);
  isAmbientPlaying = true;
}

export function stopAmbient() {
  if (!isAmbientPlaying || !ambientGain || !ambientOsc) return;
  const ctx = getCtx();
  ambientGain.gain.setTargetAtTime(0, ctx.currentTime, 0.5);
  setTimeout(() => {
    try { ambientOsc?.stop(); } catch {}
    isAmbientPlaying = false;
  }, 2000);
}

export function playSound(type) {
  const ctx = getCtx();
  const master = getMaster();
  const t = ctx.currentTime;

  switch (type) {
    case 'sovereign_awaken': {
      const bassGain = ctx.createGain();
      bassGain.gain.setValueAtTime(0.4, t);
      bassGain.gain.exponentialRampToValueAtTime(0.01, t + 3);
      bassGain.connect(master);
      const bass = ctx.createOscillator();
      bass.type = 'sine';
      bass.frequency.setValueAtTime(35, t);
      bass.frequency.exponentialRampToValueAtTime(55, t + 2);
      bass.connect(bassGain);
      bass.start(t);
      bass.stop(t + 3);
      [880, 1320, 1760, 2200].forEach((freq, i) => {
        const g = ctx.createGain();
        g.gain.setValueAtTime(0, t + 0.3 + i * 0.15);
        g.gain.linearRampToValueAtTime(0.08, t + 0.5 + i * 0.15);
        g.gain.exponentialRampToValueAtTime(0.001, t + 2.5 + i * 0.1);
        g.connect(master);
        const osc = ctx.createOscillator();
        osc.type = 'sine';
        osc.frequency.value = freq;
        osc.connect(g);
        osc.start(t + 0.3 + i * 0.15);
        osc.stop(t + 3);
      });
      const impactGain = ctx.createGain();
      impactGain.gain.setValueAtTime(0.3, t);
      impactGain.gain.exponentialRampToValueAtTime(0.001, t + 0.8);
      impactGain.connect(master);
      const impact = ctx.createOscillator();
      impact.type = 'sine';
      impact.frequency.setValueAtTime(80, t);
      impact.frequency.exponentialRampToValueAtTime(20, t + 0.8);
      impact.connect(impactGain);
      impact.start(t);
      impact.stop(t + 1);
      break;
    }
    case 'tab_switch': {
      const bufferSize = ctx.sampleRate * 0.15;
      const buffer = ctx.createBuffer(1, bufferSize, ctx.sampleRate);
      const data = buffer.getChannelData(0);
      for (let i = 0; i < bufferSize; i++) data[i] = (Math.random() * 2 - 1) * (1 - i / bufferSize);
      const noise = ctx.createBufferSource();
      noise.buffer = buffer;
      const filter = ctx.createBiquadFilter();
      filter.type = 'bandpass';
      filter.frequency.setValueAtTime(3000, t);
      filter.frequency.exponentialRampToValueAtTime(800, t + 0.12);
      filter.Q.value = 1.5;
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.15, t);
      g.gain.exponentialRampToValueAtTime(0.001, t + 0.15);
      noise.connect(filter);
      filter.connect(g);
      g.connect(master);
      noise.start(t);
      const clickG = ctx.createGain();
      clickG.gain.setValueAtTime(0.12, t + 0.02);
      clickG.gain.exponentialRampToValueAtTime(0.001, t + 0.06);
      clickG.connect(master);
      const click = ctx.createOscillator();
      click.type = 'sine';
      click.frequency.value = 1200;
      click.connect(clickG);
      click.start(t + 0.02);
      click.stop(t + 0.08);
      break;
    }
    case 'panel_hover': {
      const g = ctx.createGain();
      g.gain.setValueAtTime(0, t);
      g.gain.linearRampToValueAtTime(0.04, t + 0.05);
      g.gain.linearRampToValueAtTime(0, t + 0.2);
      g.connect(master);
      const osc = ctx.createOscillator();
      osc.type = 'sine';
      osc.frequency.value = 440;
      osc.connect(g);
      osc.start(t);
      osc.stop(t + 0.25);
      break;
    }
    case 'panel_click': {
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.12, t);
      g.gain.exponentialRampToValueAtTime(0.001, t + 0.15);
      g.connect(master);
      const osc = ctx.createOscillator();
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(800, t);
      osc.frequency.exponentialRampToValueAtTime(400, t + 0.1);
      osc.connect(g);
      osc.start(t);
      osc.stop(t + 0.2);
      const g2 = ctx.createGain();
      g2.gain.setValueAtTime(0.06, t);
      g2.gain.exponentialRampToValueAtTime(0.001, t + 0.1);
      g2.connect(master);
      const osc2 = ctx.createOscillator();
      osc2.type = 'sine';
      osc2.frequency.value = 1600;
      osc2.connect(g2);
      osc2.start(t);
      osc2.stop(t + 0.12);
      break;
    }
    case 'threat_alert': {
      [0, 0.15, 0.3].forEach(offset => {
        const g = ctx.createGain();
        g.gain.setValueAtTime(0.2, t + offset);
        g.gain.exponentialRampToValueAtTime(0.001, t + offset + 0.12);
        g.connect(master);
        const osc = ctx.createOscillator();
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(880, t + offset);
        osc.frequency.exponentialRampToValueAtTime(440, t + offset + 0.1);
        const filter = ctx.createBiquadFilter();
        filter.type = 'lowpass';
        filter.frequency.value = 2000;
        osc.connect(filter);
        filter.connect(g);
        osc.start(t + offset);
        osc.stop(t + offset + 0.15);
      });
      break;
    }
    case 'scan_start': {
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.08, t);
      g.gain.linearRampToValueAtTime(0.15, t + 0.5);
      g.gain.exponentialRampToValueAtTime(0.001, t + 1.2);
      g.connect(master);
      const osc = ctx.createOscillator();
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(100, t);
      osc.frequency.exponentialRampToValueAtTime(2000, t + 0.8);
      const filter = ctx.createBiquadFilter();
      filter.type = 'lowpass';
      filter.frequency.setValueAtTime(200, t);
      filter.frequency.exponentialRampToValueAtTime(4000, t + 0.8);
      osc.connect(filter);
      filter.connect(g);
      osc.start(t);
      osc.stop(t + 1.2);
      break;
    }
    case 'scan_complete': {
      [523, 659, 784, 1047].forEach((freq, i) => {
        const g = ctx.createGain();
        g.gain.setValueAtTime(0.1, t + i * 0.08);
        g.gain.exponentialRampToValueAtTime(0.001, t + i * 0.08 + 0.4);
        g.connect(master);
        const osc = ctx.createOscillator();
        osc.type = 'sine';
        osc.frequency.value = freq;
        osc.connect(g);
        osc.start(t + i * 0.08);
        osc.stop(t + i * 0.08 + 0.5);
      });
      break;
    }
    case 'data_tick': {
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.04, t);
      g.gain.exponentialRampToValueAtTime(0.001, t + 0.04);
      g.connect(master);
      const osc = ctx.createOscillator();
      osc.type = 'sine';
      osc.frequency.value = 1800 + Math.random() * 400;
      osc.connect(g);
      osc.start(t);
      osc.stop(t + 0.05);
      break;
    }
    case 'avatar_transition': {
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.15, t);
      g.gain.exponentialRampToValueAtTime(0.001, t + 0.8);
      g.connect(master);
      const osc = ctx.createOscillator();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(200, t);
      osc.frequency.exponentialRampToValueAtTime(800, t + 0.3);
      osc.frequency.exponentialRampToValueAtTime(400, t + 0.7);
      osc.connect(g);
      osc.start(t);
      osc.stop(t + 0.8);
      const sg = ctx.createGain();
      sg.gain.setValueAtTime(0.06, t + 0.1);
      sg.gain.exponentialRampToValueAtTime(0.001, t + 0.6);
      sg.connect(master);
      const sosc = ctx.createOscillator();
      sosc.type = 'sine';
      sosc.frequency.value = 1200;
      sosc.connect(sg);
      sosc.start(t + 0.1);
      sosc.stop(t + 0.7);
      break;
    }
    case 'modal_open': {
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.12, t);
      g.gain.exponentialRampToValueAtTime(0.001, t + 0.5);
      g.connect(master);
      const osc = ctx.createOscillator();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(100, t);
      osc.frequency.exponentialRampToValueAtTime(600, t + 0.2);
      osc.connect(g);
      osc.start(t);
      osc.stop(t + 0.5);
      const bufSize = ctx.sampleRate * 0.1;
      const buf = ctx.createBuffer(1, bufSize, ctx.sampleRate);
      const d = buf.getChannelData(0);
      for (let i = 0; i < bufSize; i++) d[i] = (Math.random() * 2 - 1) * (1 - i / bufSize) * 0.3;
      const ns = ctx.createBufferSource();
      ns.buffer = buf;
      const ng = ctx.createGain();
      ng.gain.value = 0.06;
      ns.connect(ng);
      ng.connect(master);
      ns.start(t);
      break;
    }
    case 'modal_close': {
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.08, t);
      g.gain.exponentialRampToValueAtTime(0.001, t + 0.3);
      g.connect(master);
      const osc = ctx.createOscillator();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(600, t);
      osc.frequency.exponentialRampToValueAtTime(100, t + 0.25);
      osc.connect(g);
      osc.start(t);
      osc.stop(t + 0.35);
      break;
    }
    case 'prediction_reveal': {
      [330, 440, 550, 660].forEach((freq, i) => {
        const g = ctx.createGain();
        g.gain.setValueAtTime(0, t + i * 0.12);
        g.gain.linearRampToValueAtTime(0.06, t + i * 0.12 + 0.08);
        g.gain.exponentialRampToValueAtTime(0.001, t + i * 0.12 + 0.5);
        g.connect(master);
        const osc = ctx.createOscillator();
        osc.type = 'sine';
        osc.frequency.value = freq;
        osc.detune.value = Math.random() * 10 - 5;
        osc.connect(g);
        osc.start(t + i * 0.12);
        osc.stop(t + i * 0.12 + 0.6);
      });
      break;
    }
    case 'incident_escalate': {
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.15, t);
      g.gain.exponentialRampToValueAtTime(0.001, t + 0.6);
      g.connect(master);
      const osc = ctx.createOscillator();
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(200, t);
      osc.frequency.linearRampToValueAtTime(600, t + 0.4);
      const filter = ctx.createBiquadFilter();
      filter.type = 'lowpass';
      filter.frequency.value = 1500;
      osc.connect(filter);
      filter.connect(g);
      osc.start(t);
      osc.stop(t + 0.6);
      break;
    }
    case 'mesh_pulse': {
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.08, t);
      g.gain.exponentialRampToValueAtTime(0.001, t + 0.4);
      g.connect(master);
      const osc = ctx.createOscillator();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(60, t);
      osc.frequency.exponentialRampToValueAtTime(40, t + 0.3);
      osc.connect(g);
      osc.start(t);
      osc.stop(t + 0.5);
      break;
    }
    case 'button_click': {
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.08, t);
      g.gain.exponentialRampToValueAtTime(0.001, t + 0.06);
      g.connect(master);
      const osc = ctx.createOscillator();
      osc.type = 'square';
      osc.frequency.value = 600;
      const filter = ctx.createBiquadFilter();
      filter.type = 'lowpass';
      filter.frequency.value = 1200;
      osc.connect(filter);
      filter.connect(g);
      osc.start(t);
      osc.stop(t + 0.08);
      break;
    }
    case 'ambient_drone': {
      startAmbient();
      break;
    }
  }
}
