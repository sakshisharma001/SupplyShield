<p align="center">
  <h1 align="center">🛡️ SupplyShield</h1>
  <p align="center">
    <strong>Autonomous Software Supply-Chain Security Audit & Detonation Engine</strong>
  </p>
  <p align="center">
    <em>Real-time malicious package detection through AST taint analysis, sandboxed detonation, custom policy rules, and multi-language npm/Python scanning.</em>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-v1.0.0%20Release-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Status-Production%20Ready-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-0.100+-00C853?style=for-the-badge&logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/Docker-Supported-2496ED?style=for-the-badge&logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/Tests-All%20Passing-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" />
</p>


---

## 🚀 Overview

**SupplyShield** is an enterprise-grade security engine designed to detect and neutralize malicious software packages across supply chains. It combines compiler AST static analysis, dynamic sandboxed execution, custom YARA-like policy rules, and multi-language (Python & Node.js/npm) manifest scanning to catch credential stealers, reverse shells, typosquatting, and obfuscated backdoors — **before** code reaches production.

---

## ✨ Key Capabilities & Feature Matrix

### ✅ Backend — Security Analysis Pipeline
- **AST Static Security Engine (`ast_analyzer.py`)** — Parses Python code into Abstract Syntax Trees to detect dangerous system calls (`os.system`, `subprocess`), network sockets, obfuscation (`base64`/`zlib`), credential theft, and Trojan Source attacks (CVE-2021-42574).
- **Dynamic Detonation Sandbox (`sandbox.py`)** — Ephemeral execution environment (`supplyshield_env_<uuid>`) with synthetic canary tripwires (`~/.aws/credentials`, `~/.ssh/id_rsa`), network audit hooks, and a 3-second watchdog SIGKILL timer.
- **Dynamic YARA & Custom Policy Rule Engine (`custom_rules.py`)** — Loads enterprise security policies from `rules.json` to evaluate `BANNED_IMPORT`, `FORBIDDEN_CALL`, `REGEX_PATTERN` (hardcoded secrets/keys), and `MAX_ENTROPY_THRESHOLD` rules.
- **Multi-Language Package Scanner (`javascript_analyzer.py`)** — Scans Node.js `package.json` manifests for dangerous `preinstall`/`postinstall` lifecycle hook abuse and inspects JavaScript code for `eval()`, `child_process.exec`, and obfuscation.
- **Composite Risk Scoring Engine (`risk_scorer.py`)** — Weighted 0-100 scoring model (40% static AST + 60% dynamic sandbox), correlation risk multipliers, SLSA provenance tiers, and MITRE ATT&CK technique mapping.
- **Executive Report Generator (`report_generator.py`)** — Generates standardized JSON audit reports and print-ready HTML compliance reports (`/api/scan/{id}/report/html`).

### ✅ Frontend — SOC Dashboard
- **Dark-Mode Glassmorphic Interface** — Modern responsive security operations dashboard.
- **Live Terminal Telemetry** — Real-time sub-millisecond WebSocket broadcast feed (`/ws/telemetry`).
- **Malware Preset Library** — 7 pre-configured attack samples (reverse shell, DNS exfiltration, typosquatting, cryptominer, obfuscated backdoor).
- **Interactive Risk Gauge & Report Export** — SVG animated risk meter and modal report preview/download.

### ✅ DevSecOps CLI Tool & CI/CD Pipeline Integration
- **Terminal CLI (`cli.py`)** — `python cli.py scan <target> --fail-on CRITICAL` for local terminal security audits and automated build-blocking in pipelines.
- **GitHub Actions Workflow** — Automated PR security gate (`.github/workflows/supplyshield-security-audit.yml`).

---

## 🗺️ Implementation Roadmap

| Phase | Feature | Component | Status |
|-------|---------|-----------|--------|
| **Phase 1** | AST Static Security Engine | `ast_analyzer.py` | ✅ Done |
| **Phase 2** | Dynamic Detonation Sandbox & Canary Traps | `sandbox.py` | ✅ Done |
| **Phase 3** | Composite Risk Scoring & MITRE ATT&CK Mapping | `risk_scorer.py` | ✅ Done |
| **Phase 4** | REST API & WebSocket Real-time Telemetry | `main.py`, `routes_scan.py` | ✅ Done |
| **Phase 5** | Glassmorphism SOC Security Dashboard | `frontend/` | ✅ Done |
| **Phase 6** | Audit Database Ledger & Scan History | `database.py` | ✅ Done |
| **Phase 7** | Executive Report Engine (JSON & HTML Export) | `report_generator.py` | ✅ Done |
| **Phase 8** | DevSecOps CLI Tool & GitHub Actions CI/CD | `cli.py`, `.github/workflows/` | ✅ Done |
| **Phase 9** | Multi-Language Package Support (Node.js/npm) | `javascript_analyzer.py` | ✅ Done |
| **Phase 10** | Dynamic YARA & Custom Policy Rule Engine | `custom_rules.py`, `rules.json` | ✅ Done |
| **Phase 11** | Production Docker Containerization & Multi-Container Setup | `Dockerfile`, `docker-compose` | ✅ Done |


---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        SupplyShield Gateway                            │
│                     (FastAPI + CORS + WebSockets)                      │
├───────────────────┬──────────────────────┬─────────────────────────────┤
│     REST API      │  WebSocket Feed      │  SOC Security Dashboard     │
│     /api/scan/*   │  /ws/telemetry       │  (HTML5 / CSS3 / Vanilla JS)│
├───────────────────┴──────────────────────┴─────────────────────────────┤
│                                                                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │
│  │ AST Static   │  │ Ephemeral    │  │ Custom Policy│  │ Risk       │  │
│  │ Analyzer     │→ │ Sandbox      │→ │ Rule Engine  │→ │ Scorer &   │  │
│  │ (Python/JS)  │  │ (Detonation) │  │ (rules.json) │  │ MITRE Tag  │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └────────────┘  │
│                           │                                  │         │
│                    ┌──────┴──────┐                    ┌──────┴──────┐  │
│                    │ SQLite      │                    │ Audit Report│  │
│                    │ Audit Ledger│                    │ Generator   │  │
│                    └─────────────┘                    └─────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
SupplyShield/
├── backend/
│   ├── main.py                     # FastAPI server entrypoint
│   ├── config.py                   # Security policies & thresholds
│   ├── database.py                 # SQLite audit ledger
│   ├── cli.py                      # DevSecOps terminal CLI tool
│   ├── rules.json                  # Enterprise custom security policy rules
│   ├── api/
│   │   ├── routes_scan.py          # REST API endpoints (Python & npm scans)
│   │   └── websocket_feed.py       # WebSocket real-time telemetry broadcaster
│   ├── engine/
│   │   ├── ast_analyzer.py         # AST static code analysis engine
│   │   ├── sandbox.py              # Ephemeral detonation sandbox
│   │   ├── risk_scorer.py          # Composite risk scoring & MITRE ATT&CK
│   │   ├── custom_rules.py         # Dynamic policy rule engine
│   │   ├── javascript_analyzer.py  # Node.js / npm package analyzer
│   │   └── report_generator.py     # JSON & HTML report engine
│   ├── samples/                    # Test malware sample suite
│   │   ├── safe_math_pkg.py
│   │   ├── obfuscated_backdoor.py
│   │   ├── credential_stealer.py
│   │   ├── reverse_shell.py
│   │   ├── dns_exfiltrator.py
│   │   ├── typosquat_package.py
│   │   ├── cryptominer_dropper.py
│   │   ├── npm_safe_package.json
│   │   └── npm_malicious_postinstall.json
│   ├── test_samples_suite.py       # 31 Pytest regression tests
│   ├── test_custom_rules.py        # 6 Custom rule engine tests
│   ├── test_js_engine.py           # Node.js / npm test suite
│   ├── test_report_engine.py       # Report generator tests
│   └── test_cli.py                 # CLI build-blocking tests
├── frontend/
│   ├── index.html                  # SOC Dashboard UI
│   ├── styles.css                  # Dark-mode design system
│   └── app.js                      # UI logic & WebSocket client
├── .github/
│   └── workflows/
│       └── supplyshield-security-audit.yml
├── requirements.txt
└── README.md
```

---

## ⚡ Quick Start

### 1. Prerequisites
- Python 3.10+ installed

### 2. Installation & Server Setup

```bash
# Clone the repository
git clone https://github.com/sakshisharma001/SupplyShield.git
cd SupplyShield

# Install Python dependencies
pip install -r requirements.txt

# Start the FastAPI server
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Open `http://127.0.0.1:8000/` in your browser to access the **SOC Dashboard**.

### 3. Run Security Scan via CLI

```bash
# Scan Python file
python backend/cli.py scan backend/samples/obfuscated_backdoor.py --fail-on CRITICAL

# Scan npm package.json
python backend/cli.py scan backend/samples/npm_malicious_postinstall.json
```

### 4. Run Automated Test Suite

```bash
python -m pytest backend/test_samples_suite.py backend/test_custom_rules.py backend/test_cli.py -v
```

---

## 📄 License

This project is licensed under the MIT License.

---

<p align="center">
  <strong>Built with ❤️ for Autonomous Software Supply Chain Security</strong>
</p>
