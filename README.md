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
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-0.100+-00C853?style=for-the-badge&logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/WebSocket-Real--Time-blueviolet?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" />
</p>

---

## 🚀 Overview

**SupplyShield** is an enterprise-grade security gateway designed to detect and neutralize malicious Python packages in the software supply chain. It combines three powerful analysis engines:

1. **🔬 Static AST Taint Analysis** — Deep Abstract Syntax Tree inspection with 7+ security rule categories
2. **💥 Dynamic Sandboxed Detonation** — Ephemeral execution environment with syscall & network monitoring
3. **📊 Composite Risk Scoring** — SLSA-aligned security level assessment with weighted multi-vector scoring

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| **Multi-Engine Pipeline** | 3-stage scan: AST → Sandbox → Risk Assessment |
| **Real-Time Telemetry** | WebSocket-powered live SOC dashboard |
| **7+ Security Rules** | Credential theft, network exfil, code injection, filesystem tampering, obfuscation, privilege escalation, persistence |
| **SLSA Compliance** | Security levels 0–4 based on composite risk scoring |
| **Audit Ledger** | SQLite-backed immutable scan history with full traceability |
| **Glassmorphism Dashboard** | Modern dark-mode SOC interface with risk gauges and terminal feed |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SupplyShield Gateway                       │
│                     (FastAPI + CORS)                          │
├──────────┬──────────────┬──────────────┬────────────────────┤
│  REST    │  WebSocket   │   Static     │   Swagger Docs     │
│  /api/*  │ /ws/telemetry│  Dashboard   │   /docs /redoc     │
├──────────┴──────────────┴──────────────┴────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────────┐  │
│  │ AST Security │  │   Sandbox     │  │  Risk Scoring    │  │
│  │   Analyzer   │──│  Detonation   │──│    Engine         │  │
│  │  (7+ Rules)  │  │  (Ephemeral)  │  │ (SLSA Levels)    │  │
│  └──────────────┘  └───────────────┘  └──────────────────┘  │
│                           │                                  │
│                    ┌──────┴──────┐                           │
│                    │   SQLite    │                           │
│                    │ Audit Ledger│                           │
│                    └─────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

## 📁 Project Structure

```
SupplyShield/
├── backend/
│   ├── main.py                 # FastAPI gateway entrypoint
│   ├── config.py               # Security policies & thresholds
│   ├── database.py             # SQLite audit ledger ORM
│   ├── api/
│   │   ├── routes_scan.py      # 3-stage scanning pipeline
│   │   └── websocket_feed.py   # Real-time telemetry manager
│   ├── engine/
│   │   ├── ast_analyzer.py     # AST taint analysis (7+ rules)
│   │   ├── sandbox.py          # Ephemeral detonation sandbox
│   │   └── risk_scorer.py      # Composite risk scoring engine
│   ├── samples/
│   │   └── credential_stealer.py   # Test malicious sample
│   └── test_*.py               # Unit & integration tests
├── frontend/
│   ├── index.html              # SOC Dashboard (glassmorphism UI)
│   ├── styles.css              # Dark-mode design system
│   └── app.js                  # Dashboard logic & WebSocket client
├── .gitignore
├── requirements.txt
└── README.md
```

## ⚡ Quick Start

### Prerequisites

- Python 3.10+
- pip (Python package manager)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/sakshisharma001/SupplyShield.git
cd SupplyShield

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start the server
cd backend
python main.py
```

### Access Points

| URL | Description |
|-----|-------------|
| `http://127.0.0.1:8000/` | SOC Security Dashboard |
| `http://127.0.0.1:8000/docs` | Swagger API Documentation |
| `http://127.0.0.1:8000/redoc` | ReDoc API Documentation |
| `ws://127.0.0.1:8000/ws/telemetry` | Real-time WebSocket Feed |

## 🔌 API Reference

### Scan a Package

```http
POST /api/scan
Content-Type: multipart/form-data

file: <python_file.py>
```

**Response:**
```json
{
  "scan_id": "uuid-v4",
  "filename": "suspicious.py",
  "composite_risk_score": 87.5,
  "recommended_action": "BLOCK_AND_QUARANTINE",
  "slsa_security_level": 0,
  "findings": {
    "ast": [...],
    "sandbox": {...},
    "risk_assessment": {...}
  }
}
```

### Scan History

```http
GET /api/scan/history?limit=50
```

## 🔒 Security Rules

| Rule ID | Category | Description |
|---------|----------|-------------|
| `SEC-CRED-005` | Credential Theft | Detects access to SSH keys, .env, AWS credentials |
| `SEC-NET-003` | Network Exfiltration | Flags HTTP/socket connections to external hosts |
| `SEC-INJ-001` | Code Injection | Catches eval(), exec(), compile() usage |
| `SEC-FS-002` | Filesystem Tampering | Monitors destructive file operations |
| `SEC-OBF-004` | Obfuscation | Detects base64/rot13 encoding of payloads |
| `SEC-PRIV-006` | Privilege Escalation | Flags setuid, chmod, sudo operations |
| `SEC-PERS-007` | Persistence | Identifies crontab, registry, startup modifications |

## 🧪 Running Tests

```bash
cd backend

# Run AST engine tests
python -m pytest test_ast_engine.py -v

# Run sandbox tests
python -m pytest test_sandbox.py -v

# Run risk scoring tests
python -m pytest test_risk_engine.py -v

# Run API integration tests
python -m pytest test_api.py -v

# Run all tests
python -m pytest -v
```

## 🛠️ Tech Stack

- **Backend:** Python 3.10+, FastAPI, Uvicorn, Pydantic
- **Analysis:** AST module, subprocess (sandboxed), tempfile
- **Database:** SQLite3 with audit ledger schema
- **Frontend:** Vanilla HTML/CSS/JS, WebSocket API
- **Design:** Glassmorphism dark-mode, CSS animations

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <strong>Built with ❤️ for supply chain security</strong>
</p>
