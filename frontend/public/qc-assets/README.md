# Queen Califia CyberAI — Asset Package v4.1

## Classification: SOVEREIGN

---

## Quick Start

```javascript
// Import the manifest
import manifest from './manifest.json';

// Get current state avatar
const getAvatar = (state, size = 'sm') => 
  manifest.states[state].assets[`avatar_${size}`];

// Example: chatbot avatar switching
const avatarSrc = isProcessing 
  ? getAvatar('active', 'sm')   // 200x200 active avatar
  : getAvatar('idle', 'sm');     // 200x200 idle avatar
```

## Directory Structure

```
QC_CyberAI_Assets/
├── manifest.json            # Full asset manifest with metadata
├── README.md                # This file
│
├── states/                  # Action state assets (organized by state)
│   ├── idle/                # QC::READY — Sentinel Mode
│   ├── active/              # QC::ACTIVE — Defense Active  
│   └── ascended/            # QC::ASCENDED — Ancestral Link
│
├── branding/                # Brand identity assets
│   ├── sigil/               # Sovereign Sigil (hex shield logo)
│   └── sovereign_circuitry/ # Full universe concept art + banners
│
├── panels/                  # Full branded panels (tall format)
├── avatars/                 # Square avatars (200/400/800px)
├── icons/                   # Icons (64/128/256/512px)
├── thumbnails/              # 300x300 preview thumbnails
└── raw_portraits/           # Original unbranded source images
```

## Action States

| State | Label | Accent | Trigger |
|-------|-------|--------|---------|
| `idle` | `QC::READY` | Gold (#D4AF37) | Default / monitoring |
| `active` | `QC::ACTIVE` | Cyan (#00DCFA) | Processing / defending |
| `ascended` | `QC::ASCENDED` | Warm Gold (#FFE178) | Critical / deep analysis |

## State Transitions

```
idle ──[user message]──▸ active
active ──[response done]──▸ idle
active ──[critical threat]──▸ ascended  
ascended ──[threat cleared]──▸ active
ascended ──[all clear]──▸ idle
```

## Asset Sizes

| Type | Size | Use Case |
|------|------|----------|
| `avatar_sm` | 200×200 | Chat widget avatar |
| `avatar_md` | 400×400 | Sidebar / profile |
| `avatar_lg` | 800×800 | Full-screen / hero |
| `icon_xs` | 64×64 | Favicon |
| `icon_sm` | 128×128 | Nav icon |
| `icon_md` | 256×256 | Feature icon |
| `icon_lg` | 512×512 | App store icon |
| `panel` | ~1224×1696 | Full branded display |
| `thumb` | 300×300 | Grid thumbnail |

## CSS Variables

```css
:root {
  --qc-gold: #D4AF37;
  --qc-bright-gold: #F5D241;
  --qc-cyan: #00DCFA;
  --qc-deep-cyan: #0096BE;
  --qc-void: #04020A;
  --qc-accent-idle: #D4AF37;
  --qc-accent-active: #00DCFA;
  --qc-accent-ascended: #FFE178;
}
```

## Next.js Integration Example

```jsx
// components/QueenCalifiaAvatar.jsx
import { useState, useEffect } from 'react';

const STATES = {
  idle: '/assets/qc/avatars/idle_avatar_sm.png',
  active: '/assets/qc/avatars/active_avatar_sm.png',
  ascended: '/assets/qc/avatars/ascended_avatar_sm.png',
};

export default function QueenCalifiaAvatar({ state = 'idle', size = 200 }) {
  return (
    <div className="qc-avatar" style={{ 
      width: size, height: size,
      borderRadius: size / 6,
      border: `2px solid var(--qc-accent-${state})`,
      overflow: 'hidden',
      transition: 'border-color 0.3s ease'
    }}>
      <img 
        src={STATES[state]} 
        alt={`Queen Califia — ${state}`}
        width={size} 
        height={size}
        style={{ transition: 'opacity 0.3s ease' }}
      />
    </div>
  );
}
```

## Branding Assets

### Sovereign Sigil
The hexagonal circuit shield — use as app icon, favicon, loading animation center, watermark.
Available in: 32/64/128/256/512px icons + 100/200/400/800px squares + full panel

### Sovereign Circuitry  
The complete Queen Califia universe showing Celestial Server Vault, Obsidian Archive, and Fractured Firewall.
Available in: Full image + square crops + 16:9 banners (800w/1200w/1920w)

---

*QC-CYBERAI v4.1 // CLASSIFICATION: SOVEREIGN*
*Guardian of the Digital Realm*
