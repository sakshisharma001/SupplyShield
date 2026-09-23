<p align="center">
  <h1 align="center">🛡️ SupplyShield</h1>
  <p align="center">
    <strong>Autonomous Software Supply-Chain Security Audit and Detonation Engine</strong>
  </p>
  <p align="center">
    <em>Real-time malicious package detection through AST analysis, sandboxed detonation, canary tripwires, and MITRE ATT&CK mapping.</em>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-v1.0.0-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/Status-Production%20Ready-brightgreen?style=flat-square" />
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square" />
  <img src="https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat-square" />
  <img src="https://img.shields.io/badge/Tests-10%2F10%20Passing-brightgreen?style=flat-square" />
  <img src="https://img.shields.io/badge/Docker-Supported-2496ED?style=flat-square" />
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red?style=flat-square" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" />
</p>

---

## What is SupplyShield?

**SupplyShield** is a production-grade autonomous security engine that detects malicious packages in software supply chains **before** they reach production environments.

It combines three layers of threat detection:

| Layer | Technology | What It Catches |
|-------|-----------|-----------------|
| **Static Analysis** | Python AST Parser | Obfuscation, dangerous imports, credential theft patterns |
| **Dynamic Detonation** | Isolated Subprocess Sandbox | Runtime network exfiltration, file system escapes, real shell execution |
| **Policy Engine** | YARA-like Custom Rules | Hardcoded secrets, banned packages, entropy anomalies |

Every finding is automatically tagged to the **MITRE ATT&CK framework** and scored on a **0-100 composite risk scale** with SLSA provenance tiers (Level 0-4).

---

## Key Features

### Security Engines

- **AST Static Engine** — Parses Python into Abstract Syntax Trees. Detects `exec()`, `eval()`, `subprocess`, network sockets, base64/zlib obfuscation, Bidirectional text attacks (CVE-2021-42574), sleep-based logic bombs, and anti-forensic file deletion calls.
- **Dynamic Detonation Sandbox** — Runs untrusted code in an ephemeral isolated subprocess with:
  - Real network interception via `socket.socket.connect` monkey-patching (actual **blocking**, not just detection)
  - Filesystem isolation — `builtins.open()` blocked outside the sandbox root
  - Canary tripwires: `.ssh/id_rsa`, `.env`, `.aws/credentials` planted to detect credential harvesting
  - Host environment variable sanitization (AWS keys, GitHub tokens stripped before execution)
  - 3-second process watchdog hard-kill
- **JavaScript / npm Analyzer** — Scans `package.json` lifecycle hooks (`preinstall`, `postinstall`), base64 pipe-to-shell execution, hex/unicode obfuscation, DNS tunneling, and targeted `process.env` harvesting.
- **Custom Policy Rule Engine** — Loads enterprise security policies from `rules.json` supporting `BANNED_IMPORT`, `FORBIDDEN_CALL`, `REGEX_PATTERN`, and `MAX_ENTROPY_THRESHOLD` rules.
- **Composite Risk Scorer** — Weighted multi-vector scoring: `0.40 x AST score + 0.60 x Sandbox score` with correlation bonuses.

### SOC Dashboard

- Glassmorphic dark/light mode UI with one-click theme toggle
- Real-time SOC telemetry via WebSocket (`/ws/telemetry`)
- 7 pre-loaded malware presets (backdoor, credential stealer, reverse shell, DNS exfiltrator, cryptominer, typosquat)
- Animated risk gauge (0-100), verdict badges, SLSA tier display
- HTML and JSON report export

### Production Security

- **Rate Limiting** — Sliding-window 30 req/min per IP with `Retry-After` headers (HTTP 429)
- **Upload Validation** — File size limits (512KB Python / 64KB JSON), extension whitelist, binary rejection
- **Audit Logging** — Structured request logs (method, path, IP, status, duration_ms)
- **CORS Whitelist** — Configurable via `SUPPLYSHIELD_CORS_ORIGINS` environment variable
- **Production Mode** — Swagger docs auto-disabled when `SUPPLYSHIELD_ENV=production`

### DevSecOps Integration

- **CLI Tool** — `python cli.py scan <file> --fail-on CRITICAL` for CI/CD pipeline build blocking
- **GitHub Actions** — Automated security gate on every PR (`.github/workflows/`)
- **Docker** — `docker-compose up --build` for containerized deployment

---

## Implementation Phases

| Phase | Feature | Status |
|-------|---------|--------|
| Phase 1 | AST Static Security Engine | ✅ Complete |
| Phase 2 | Dynamic Detonation Sandbox + Canary Tripwires | ✅ Complete |
| Phase 3 | Composite Risk Scoring + MITRE ATT&CK Mapping | ✅ Complete |
| Phase 4 | REST API + WebSocket Real-time Telemetry | ✅ Complete |
| Phase 5 | Glassmorphic SOC Dashboard (Dark/Light Mode) | ✅ Complete |
| Phase 6 | SQLite Audit Ledger + Scan History | ✅ Complete |
| Phase 7 | HTML and JSON Executive Report Generator | ✅ Complete |
| Phase 8 | DevSecOps CLI + GitHub Actions CI/CD Gate | ✅ Complete |
| Phase 9 | Node.js / npm Multi-Language Scanner | ✅ Complete |
| Phase 10 | YARA-style Custom Policy Rule Engine | ✅ Complete |
| Phase 11 | Production Hardening (Rate Limiting, Upload Validation, Audit Logs) | ✅ Complete |
| Phase 12 | Docker Containerization + Health Probes | ✅ Complete |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│              SupplyShield Security Gateway                    │
│         FastAPI + RateLimitMiddleware + CORS                  │
├──────────────┬──────────────────┬────────────────────────────┤
│  REST API    │  WebSocket Feed  │     SOC Dashboard           │
│ /api/scan/*  │  /ws/telemetry   │     /dashboard              │
├──────────────┴──────────────────┴────────────────────────────┤
│  ┌──────────┐  ┌────────────┐  ┌──────────┐  ┌───────────┐  │
│  │   AST    │→ │ Ephemeral  │→ │  Custom  │→ │  Risk     │  │
│  │  Static  │  │  Sandbox   │  │  Policy  │  │  Scorer   │  │
│  │ Analyzer │  │(Detonation)│  │  Engine  │  │ +MITRE    │  │
│  └──────────┘  └────────────┘  └──────────┘  └───────────┘  │
│                      │                             │          │
│               ┌──────┴──────┐              ┌───────┴──────┐  │
│               │   SQLite    │              │   Report     │  │
│               │ Audit Ledger│              │  Generator   │  │
│               └─────────────┘              └──────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
SupplyShield/
├── backend/
│   ├── main.py                     # FastAPI gateway + middleware
│   ├── config.py                   # Environment-based configuration
│   ├── database.py                 # SQLite audit ledger
│   ├── cli.py                      # DevSecOps CLI tool
│   ├── rules.json                  # Custom security policy rules
│   ├── run_tests.py                # Master test runner (all 10 suites)
│   ├── api/
│   │   ├── routes_scan.py          # REST endpoints + upload validation
│   │   └── websocket_feed.py       # WebSocket telemetry broadcaster
│   ├── engine/
│   │   ├── ast_analyzer.py         # Python AST static engine (14 rules)
│   │   ├── sandbox.py              # Isolated detonation sandbox
│   │   ├── risk_scorer.py          # Composite scoring + MITRE mapping
│   │   ├── custom_rules.py         # Policy rule evaluator
│   │   ├── javascript_analyzer.py  # npm / JS analyzer (11 rules)
│   │   └── report_generator.py     # JSON and HTML report engine
│   ├── samples/                    # 9 malware test samples
│   └── test_*.py                   # 10 automated test suites (100% passing)
├── frontend/
│   ├── index.html                  # SOC Dashboard UI
│   ├── styles.css                  # Dark/Light theme design system
│   └── app.js                      # WebSocket client + theme toggle
├── .github/
│   └── workflows/
│       └── supplyshield-security-audit.yml
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## Quick Start

**Prerequisites:** Python 3.10+

```bash
# 1. Clone the repository
git clone https://github.com/sakshisharma001/SupplyShield.git
cd SupplyShield

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the server
cd backend
python main.py
```

Open **http://127.0.0.1:8000/dashboard** in your browser.

**Scan via CLI:**
```bash
python backend/cli.py scan backend/samples/obfuscated_backdoor.py --fail-on CRITICAL
python backend/cli.py scan backend/samples/npm_malicious_postinstall.json
```

**Run Full Test Suite:**
```bash
cd backend
python run_tests.py
# Expected: RESULTS: 10 PASSED, 0 FAILED
```

**Docker Deployment:**
```bash
docker-compose up --build -d
```

---

## Detection Rules Reference

### Python AST Rules

| Rule ID | Severity | Detection |
|---------|----------|-----------|
| `SEC-DYN-001` | CRITICAL | `eval()`, `exec()`, `compile()`, `__import__()` |
| `SEC-SYS-002` | HIGH | `os.system()`, `subprocess.Popen/run/call` |
| `SEC-NET-003` | MEDIUM | `socket.socket()`, `requests.get/post()` |
| `SEC-OBF-004` | CRITICAL | Base64 strings decoding to executable code |
| `SEC-CRED-005` | HIGH | `.ssh/id_rsa`, `.env`, `.aws/credentials` paths |
| `SEC-ENT-006` | MEDIUM | Shannon entropy > 4.8 (encrypted/obfuscated strings) |
| `SEC-BIDI-007` | CRITICAL | Bidirectional Unicode text attack (CVE-2021-42574) |
| `SEC-IMP-002` | MEDIUM | `requests`, `httpx`, `urllib`, `paramiko` imports |
| `SEC-SYS-003` | HIGH | `os.remove`, `os.unlink`, `shutil.rmtree` (anti-forensic) |
| `SEC-OBF-007` | CRITICAL | `zlib.decompress`, `gzip.decompress` (double obfuscation) |
| `SEC-TIME-008` | HIGH | `time.sleep(N >= 30)` logic bomb |

### Dynamic Sandbox Findings

| Finding ID | Severity | Trigger |
|-----------|----------|---------|
| `DYN-CANARY-001` | CRITICAL | SSH private key (`~/.ssh/id_rsa`) access |
| `DYN-CANARY-002` | HIGH | `.env` credentials file access |
| `DYN-CANARY-003` | CRITICAL | AWS credentials (`~/.aws/credentials`) access |
| `DYN-NET-002` | CRITICAL | Real outbound network connection blocked |
| `DYN-FS-001` | HIGH | Filesystem escape beyond sandbox root |
| `DYN-TIMEOUT-001` | CRITICAL | Process watchdog hard-kill (> 3s timeout) |

---

## Risk Scoring Model

```
Composite Score = (0.40 x Static AST Score) + (0.60 x Dynamic Sandbox Score)

Correlation Bonuses:
  Obfuscation + Network Call detected  -> +20 bonus
  Credential Access + Network Call     -> +15 bonus

Verdicts:
  0  - 15   -> CLEAN              -> SLSA Level 4 (Fully Verified)
  16 - 69   -> SUSPICIOUS         -> SLSA Level 1 (Partial Verification)
  70 - 100  -> CRITICAL_MALICIOUS -> SLSA Level 0 (Compromised)
```

---

## License

This project is licensed under the **MIT License**.

---

<p align="center">
  <strong>SupplyShield — Detect threats before they reach production.</strong>
</p>
