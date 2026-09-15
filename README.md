<p align="center">
  <h1 align="center">🛡️ SupplyShield</h1>
  <p align="center">
    <strong>Autonomous Software Supply-Chain Security Audit & Detonation Engine</strong>
  </p>
  <p align="center">
    <em>Real-time malicious package detection through AST taint analysis, sandboxed detonation, and composite risk scoring.</em>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Status-In%20Development-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-0.100+-00C853?style=for-the-badge&logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" />
</p>

---

> 🚧 **This project is under active development.** Features are being built and shipped incrementally. See the [Roadmap](#-roadmap) for current progress.

---

## 🚀 Overview

**SupplyShield** is a security tool designed to detect and neutralize malicious Python packages in the software supply chain. It combines multiple analysis engines to identify credential theft, code injection, obfuscation, and data exfiltration attempts — **before** a package is installed.

## ✨ Features Implemented So Far

### ✅ Backend — Security Analysis Pipeline
- **AST Static Analyzer** — Parses Python source into Abstract Syntax Trees to detect dangerous calls, credential theft, obfuscation, and Trojan Source attacks (7+ rule categories)
- **Dynamic Sandbox** — Isolated ephemeral execution environment with canary tripwire files, audit hooks, and 3-second watchdog timeout
- **Risk Scoring Engine** — Weighted composite scoring (40% static + 60% dynamic) with correlation bonuses and MITRE ATT&CK technique mapping
- **SQLite Audit Ledger** — Persistent scan history with full traceability
- **REST API** — FastAPI endpoints for code scanning, file uploads, and scan history
- **WebSocket Telemetry** — Real-time broadcast of scan events to connected clients

### ✅ Frontend — SOC Dashboard
- Dark-mode glassmorphism UI
- File upload & code editor with preset malicious samples
- Real-time WebSocket terminal feed
- Risk score gauge and findings table

### ✅ DevSecOps CLI Tool & CI/CD Pipeline Integration
- **DevSecOps CLI (`cli.py`)** — Terminal tool (`supplyshield scan`) with `--fail-on` build-blocking capabilities for security pipelines
- **GitHub Actions Workflow** — Ready-to-use `.github/workflows/supplyshield-security-audit.yml` for automated PR security gates
- **Executive Security Audit Reports** — Standardized JSON compliance reports and print-ready HTML audit reports (`/api/scan/{id}/report/html`)
- **Malware Preset Suite** — 7 pre-configured attack samples (reverse shell, DNS tunneling, typosquatting, cryptominer, obfuscated backdoor)

## 🗺️ Roadmap

| Phase | Feature | Status |
|-------|---------|--------|
| Phase 1 | AST Static Analysis Engine | ✅ Done |
| Phase 2 | Dynamic Sandbox with Canary Traps | ✅ Done |
| Phase 3 | Composite Risk Scoring & MITRE Mapping | ✅ Done |
| Phase 4 | REST API & WebSocket Telemetry | ✅ Done |
| Phase 5 | SOC Security Dashboard (Frontend) | ✅ Done |
| Phase 6 | Scan History & Audit Reports | ✅ Done |
| Phase 7 | Executive Audit Report Engine & Export APIs | ✅ Done |
| Phase 8 | DevSecOps CLI Tool & CI/CD Pipeline Integration | ✅ Done |
| Phase 9 | Multi-Language Support | 📋 Planned |
| Phase 10 | Cloud Deployment & Scaling | 📋 Planned |

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────┐
│              SupplyShield Gateway                 │
│               (FastAPI + CORS)                    │
├──────────┬──────────────┬───────────────────────-┤
│ REST API │  WebSocket   │  Static Dashboard       │
│ /api/*   │ /ws/telemetry│  / (HTML/CSS/JS)        │
├──────────┴──────────────┴───────────────────────-┤
│                                                   │
│  ┌────────────┐ ┌────────────┐ ┌──────────────┐  │
│  │    AST     │ │  Sandbox   │ │    Risk      │  │
│  │  Analyzer  │→│ Detonation │→│   Scorer     │  │
│  └────────────┘ └────────────┘ └──────────────┘  │
│                       │                           │
│                ┌──────┴──────┐                    │
│                │   SQLite    │                    │
│                │ Audit Ledger│                    │
│                └─────────────┘                    │
└──────────────────────────────────────────────────┘
```

## 📁 Project Structure

```
SupplyShield/
├── backend/
│   ├── main.py                 # FastAPI server entrypoint
│   ├── config.py               # Security policies & thresholds
│   ├── database.py             # SQLite audit ledger
│   ├── api/
│   │   ├── routes_scan.py      # Scanning pipeline & API routes
│   │   └── websocket_feed.py   # Real-time telemetry manager
│   ├── engine/
│   │   ├── ast_analyzer.py     # AST taint analysis (7+ rules)
│   │   ├── sandbox.py          # Ephemeral detonation sandbox
│   │   └── risk_scorer.py      # Composite risk scoring
│   └── samples/                # Test malicious samples
├── frontend/
│   ├── index.html              # SOC Dashboard
│   ├── styles.css              # Dark-mode design system
│   └── app.js                  # Dashboard logic & WebSocket
├── requirements.txt
└── README.md
```

## ⚡ Quick Start

### Prerequisites
- Python 3.10+

### Setup

```bash
# Clone the repo
git clone https://github.com/sakshisharma001/SupplyShield.git
cd SupplyShield

# Install dependencies
pip install -r requirements.txt

# Run the server
cd backend
python main.py
```

Then open `http://127.0.0.1:8000/` in your browser.

## 📄 License

This project is licensed under the MIT License.

---

<p align="center">
  <strong>Built with ❤️ for supply chain security</strong>
</p>
