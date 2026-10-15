# SupplyShield Frontend Architecture & Design System

SupplyShield features a professional, high-density SOC (Security Operations Center) dashboard paired with an intuitive **Beginner-Friendly UX** designed to give first-time viewers and evaluators a complete understanding of package security within 30 seconds.

---

## 1. Architectural Philosophy & Technology Stack

- **Core Engine**: Pure HTML5, CSS3 (Custom Design System with CSS Variables), and JavaScript (ES6+).
- **Zero Framework Bloat**: No React, Next.js, or Vue build step required. The entire frontend loads instantly from FastAPI's static file mount.
- **Strict Semantic Severity**: Severity colors (Red, Orange, Yellow, Blue, Green) are reserved **exclusively** for threat levels. No neon clutter or distracting emojis.
- **Accessibility & Contrast**: Built to exceed **WCAG AA** contrast requirements (>= 4.5:1 for normal text). Full keyboard accessibility, ARIA labels, focus indicators, and `prefers-reduced-motion` support.
- **Strict Stored XSS Defense**: All scanned content, code snippets, package filenames, and rule descriptions are passed through `escapeHtml()` prior to DOM rendering.

---

## 2. Design System Tokens (`frontend/styles.css`)

### Color Palette & Tokens
| Token | Dark Theme (Default) | Light Theme | Usage |
| :--- | :--- | :--- | :--- |
| `--color-accent` | `#0284c7` (Sky Blue) | `#0284c7` | Brand highlight, active links, primary CTA |
| `--color-critical` | `#ef4444` (Crimson) | `#ef4444` | Risk score >= 70, `CRITICAL_MALICIOUS` |
| `--color-high` | `#f97316` (Amber/Orange) | `#f97316` | High-severity findings, evasion attempts |
| `--color-medium` | `#eab308` (Yellow) | `#eab308` | Risk score 30–69, `SUSPICIOUS` |
| `--color-low` | `#3b82f6` (Blue) | `#3b82f6` | Informational / low-risk observations |
| `--color-clean` | `#10b981` (Emerald) | `#10b981` | Risk score 0–29, `CLEAN`, passed checks |
| `--bg-app` | `#090d16` (Deep Navy) | `#f8fafc` (Slate 50) | Overall viewport background |
| `--bg-surface` | `#111827` (Card Surface) | `#ffffff` (Pure White) | Panels, modals, elevated surfaces |

### Spacing & Layout Scale
- `--space-1`: 4px
- `--space-2`: 8px
- `--space-3`: 12px
- `--space-4`: 16px
- `--space-6`: 24px
- `--space-8`: 32px
- `--space-12`: 48px

### Typography
- **UI Font**: `Inter`, `-apple-system`, `BlinkMacSystemFont`, `sans-serif` (Optimal legibility at small sizes).
- **Code & Logs Font**: `JetBrains Mono`, `Fira Code`, `ui-monospace`, `monospace` (Fixed-pitch alignment for traces and code context).

---

## 3. Component Hierarchy

```
App Container
├── Top Navbar (Role: Banner)
│   ├── Brand Icon & Tagline
│   ├── Navigation Buttons (Scan | History | About)
│   ├── Simple / Technical Mode Radio Toggle
│   ├── API Health Status Pill (Live / Offline)
│   ├── Settings Drawer Button (API Key)
│   ├── First-Time Guided Tour Button
│   └── Theme Switcher (Dark ↔ Light)
│
├── Page 1: Scan View (#view-scan)
│   ├── Beginner Hero Strip (Clean state)
│   │   ├── Headline & Subtitle
│   │   ├── 3-Step "How It Works" Cards
│   │   ├── "Why this matters" Alert
│   │   └── Instant Preset CTAs ("Try safe package", "Try malicious package")
│   ├── Scanner Grid
│   │   ├── Source Code Input Panel
│   │   │   ├── Tabs (Paste Code / Upload .py file)
│   │   │   ├── Code Editor with Character Counter (Max 200,000 chars)
│   │   │   ├── Sample Preset Dropdown
│   │   │   └── Primary Scan Button (Loading & Error States)
│   │   └── Threat Assessment Panel
│   │       ├── 3-Stage Pipeline Stepper (AST → Sandbox → Risk Score)
│   │       ├── Verdict Banner (Plain English + Technical Badges)
│   │       ├── Radial SVG Risk Gauge (0–100 Animated Stroke)
│   │       └── "What should I do?" Concrete Guidance Box
│   └── Detected Findings Section
│       ├── Simple View Container (Top 3 human-readable finding cards)
│       └── Technical View Container (Full table, MITRE ATT&CK chips, Live terminal)
│
├── Page 2: Audit History View (#view-history)
│   ├── Persistent Scan Audit Table (from SQLite)
│   ├── Search Filter (Package name / Scan ID)
│   ├── Verdict Filter Dropdown
│   └── Detailed Scan Inspection Modal
│
├── Page 3: About & Glossary View (#view-about)
│   ├── Project Mission & Architecture Summary
│   ├── Interactive Jargon Glossary Grid (10 Security Terms)
│   └── Documented Architectural Limitations
│
└── Accessible Modals
    ├── Settings Modal (API Key configuration)
    ├── 5-Step Onboarding Tour Modal
    ├── "What Is This?" Supply-Chain Explainer Modal
    └── AI Secure Patch Remediation Modal
```

---

## 4. Dual View Modes: Simple vs. Technical

To solve the dual requirements of college viva defense (examiners looking for deep technical rigor) and immediate 30-second comprehension (recruiters/students), SupplyShield offers instant mode toggling:

### Simple View (Default)
- **Target Audience**: Students, junior developers, busy evaluators.
- **Layout**: Fits on a standard laptop screen without scrolling.
- **Key Elements**:
  - Big human sentence: *"Do not install this. It tries to steal secret files and connect to the internet."*
  - Plain English verdict labels beside technical ones:
    - `CRITICAL_MALICIOUS` → **"Dangerous: do not install"**
    - `SUSPICIOUS` → **"Needs a human review"**
    - `CLEAN` → **"Looks safe"**
  - **"What should I do?" Box**: 2–3 concrete action items.
  - **Top 3 Findings**: Plain title ("Runs hidden code"), "Why this is risky", and "What we saw". Rule IDs remain secondary.
  - Live terminal collapsed out of view to avoid cognitive overload.

### Technical View
- **Target Audience**: SOC analysts, security engineers, examiners asking deep viva questions.
- **Layout**: Complete security audit data grid.
- **Key Elements**:
  - Full findings data table with Rule IDs, line numbers, and code context.
  - **MITRE ATT&CK Chips**: Direct clickable links to `attack.mitre.org` technique definitions.
  - **Live WebSocket Telemetry Terminal**: Timestamped stage logs, color-coded severity levels, auto-scroll toggle, copy to clipboard.
  - **Export Tools**: One-click download of formal HTML audit report and CI/CD JSON artifact.

---

## 5. Security & XSS Hardening

Scanned Python dependencies must always be treated as untrusted, hostile input. SupplyShield implements strict browser-side defense:
1. **Zero Raw HTML Injection**: Untrusted code snippets, descriptions, filenames, and evidence are passed through `escapeHtml()`:
   ```javascript
   function escapeHtml(str) {
       if (str === null || str === undefined) return "";
       return String(str)
           .replace(/&/g, "&amp;")
           .replace(/</g, "&lt;")
           .replace(/>/g, "&gt;")
           .replace(/"/g, "&quot;")
           .replace(/'/g, "&#39;");
   }
   ```
2. **Safe Code Block Rendering**: Rendered inside `<pre class="code-snippet-pre">` elements with CSS wrapping to prevent horizontal layout break.
3. **API Key Security**: The API key is stored exclusively in `sessionStorage` (cleared immediately when the browser tab closes) and is never written to `localStorage` or logged to console.

---

## 6. How to Run Locally

### Start Backend Gateway & Dashboard
From the project root:
```powershell
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
Navigate to:
```
http://127.0.0.1:8000/dashboard
```

### Run Frontend Unit Tests
SupplyShield includes a standalone test suite with zero external npm dependencies using Node.js:
```powershell
node --test tests_frontend/frontend.test.js
```
Expected output:
```
# tests 10
# pass 10
# fail 0
```
