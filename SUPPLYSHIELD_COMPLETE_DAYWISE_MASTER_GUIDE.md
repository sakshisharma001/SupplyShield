# 🛡️ SupplyShield — Complete Day-by-Day Master Implementation Guide & Roadmap

> **Author / Maintainer:** Sakshi Sharma  
> **Project:** Autonomous Software Supply-Chain Security Audit & Detonation Engine  
> **Repository:** [https://github.com/sakshisharma001/SupplyShield.git](https://github.com/sakshisharma001/SupplyShield.git)  
> **Last Updated:** Day 9 Completed | 41/41 Automated Pytest Tests Passing

---

## 📋 Document Overview

This master guide serves as a complete blueprint for the entire **SupplyShield** project. It contains:
1. **Part 1: Completed Work Log (Day 1 to Day 9)** — Detailed explanation of every component, file, design decision, test suite, and command implemented so far.
2. **Part 2: Future Step-by-Step Roadmap (Day 10 to Project Completion)** — Exact day-by-day implementation plan, code structure, commands, and features to complete the project independently.

---

# 📑 PART 1: COMPLETED WORK LOG (DAY 1 TO DAY 9)

## 📌 Day 1: AST Static Analysis Engine & Security Rule Base
* **Core Goal:** Detect malicious Python syntax patterns without running the code.
* **Files Created:** `backend/engine/ast_analyzer.py`, `backend/test_ast_engine.py`
* **Key Features:**
  - Standard Python `ast` module parsing.
  - Shannon Entropy calculation for string literals (detects Base64 / Encrypted blobs).
  - Trojan Source detection (Unicode Bidi control characters like `\u202A`).
  - 7 Rule Categories: `SEC-SYS-002` (System Commands), `SEC-NET-003` (Network Sockets), `SEC-DYN-001` (eval/exec/compile), `SEC-CRED-005` (AWS/SSH credential harvesting), `SEC-OBF-001` (Base64/zlib obfuscation).
* **Commands to Run:** `python -m pytest backend/test_ast_engine.py`

---

## 📌 Day 2: Ephemeral Dynamic Sandbox & Canary Tripwires
* **Core Goal:** Safely detonate unknown code inside an isolated subprocess sandbox to monitor runtime behavior.
* **Files Created:** `backend/engine/sandbox.py`, `backend/test_sandbox.py`
* **Key Features:**
  - Ephemeral execution directory (`supplyshield_env_<uuid>`).
  - Synthetic canary tripwire files (`~/.aws/credentials`, `~/.ssh/id_rsa`).
  - Strict 3.0-second SIGKILL watchdog timeout (prevents infinite loops / cryptominers).
  - Dynamic file access and network hook detection.
* **Commands to Run:** `python -m pytest backend/test_sandbox.py`

---

## 📌 Day 3: Composite Risk Scoring Engine & MITRE ATT&CK Mapping
* **Core Goal:** Combine static AST findings and dynamic sandbox telemetry into a 0-100 risk score, verdict, and SLSA provenance tier.
* **Files Created:** `backend/engine/risk_scorer.py`, `backend/test_risk_engine.py`
* **Key Features:**
  - Weighted composite scoring: **40% Static AST + 60% Dynamic Sandbox**.
  - Correlation bonuses (e.g. Obfuscation + Network call = +20 risk boost).
  - Verdict Classification: `CLEAN` (0-15), `SUSPICIOUS` (16-69), `CRITICAL_MALICIOUS` (70-100).
  - SLSA Provenance Tiers (`SLSA-Level-4` down to `SLSA-Level-0`).
  - MITRE ATT&CK Technique Mapping (T1059.004, T1552.001, T1071.004).
* **Commands to Run:** `python -m pytest backend/test_risk_engine.py`

---

## 📌 Day 4: REST API, SQLite Audit Database & Real-time SOC Dashboard UI
* **Core Goal:** Build FastAPI backend endpoints, persistent database storage, live WebSocket telemetry, and a dark-mode glassmorphism frontend dashboard.
* **Files Created:**
  - `backend/main.py`, `backend/database.py`
  - `backend/api/routes_scan.py`, `backend/api/websocket_feed.py`
  - `frontend/index.html`, `frontend/styles.css`, `frontend/app.js`
* **Key Features:**
  - `POST /api/scan/code` & `POST /api/scan/package` API endpoints.
  - `WebSocket /ws/telemetry` for live sub-millisecond SOC terminal feeds.
  - SQLite persistent audit ledger (`supplyshield_audit.db`).
  - Glassmorphism dark-mode frontend dashboard with SVG risk score gauge.
* **Commands to Run:** `cd backend; python -m uvicorn main:app --host 127.0.0.1 --port 8000`

---

## 📌 Day 5: Real-World Malware Sample Library (7 Attack Vectors)
* **Core Goal:** Create a comprehensive repository of real-world supply chain attack vectors for testing and demonstration.
* **Files Created in `backend/samples/`:**
  1. `safe_math_pkg.py` — Clean utility code (0 risk, CLEAN).
  2. `obfuscated_backdoor.py` — Base64 + zlib + exec payload.
  3. `credential_stealer.py` — AWS key harvesting & socket exfiltration.
  4. `reverse_shell.py` — Reverse shell via `os.system` / `subprocess`.
  5. `dns_exfiltrator.py` — DNS query tunneling via `socket.gethostbyname`.
  6. `typosquat_package.py` — Hidden `eval()` / `compile()` payload disguised as string library.
  7. `cryptominer_dropper.py` — Subprocess downloader executing crypto miner binaries.

---

## 📌 Day 6: Automated Pytest Regression Test Suite
* **Core Goal:** Build 31 automated tests ensuring zero false positives on clean code and 100% detection on malicious samples.
* **Files Created:** `backend/test_samples_suite.py`
* **Commands to Run:** `python -m pytest backend/test_samples_suite.py -v` (31/31 PASSED).

---

## 📌 Day 7: Frontend Presets Update & Study Notes
* **Core Goal:** Connect all 7 malware samples to the frontend dashboard UI preset buttons and update interview defense study notes.
* **Files Modified:** `frontend/app.js`, `frontend/index.html`, `frontend/styles.css`, `PLACEMENT_STUDY_NOTES.md`.

---

## 📌 Day 8: Executive Security Audit Report Engine & Export REST APIs
* **Core Goal:** Generate enterprise compliance reports in JSON and print-ready HTML formats.
* **Files Created:** `backend/engine/report_generator.py`, `backend/test_report_engine.py`
* **Files Modified:** `backend/api/routes_scan.py`, `frontend/app.js`
* **Key Features:**
  - `generate_json_report()` & `generate_html_report()` functions.
  - `GET /api/scan/{id}/report` & `GET /api/scan/{id}/report/html` endpoints.
  - Dashboard Modal buttons to view/download JSON & HTML reports.
* **Commands to Run:** `python -m pytest backend/test_report_engine.py -v` (4/4 PASSED).

---

## 📌 Day 9: DevSecOps CLI Tool & GitHub Actions CI/CD Pipeline
* **Core Goal:** Shift-left security — scan packages directly in terminal CLI and block malicious Pull Requests in CI/CD pipelines.
* **Files Created:**
  - `backend/cli.py` — Terminal CLI tool (`python cli.py scan <target> --fail-on CRITICAL`).
  - `.github/workflows/supplyshield-security-audit.yml` — Automated GitHub Actions workflow.
  - `backend/test_cli.py` — 6 Pytest tests verifying CLI flags and build blocking (exit code 1).
* **Commands to Run:** `python -m pytest backend/test_cli.py -v` (6/6 PASSED).

---

# 🚀 PART 2: FUTURE STEP-BY-STEP ROADMAP (DAY 10 TO COMPLETION)

If you ever need to continue building or complete the remaining phases on your own, follow these exact day-by-day instructions:

---

## 📌 DAY 10: Multi-Language Package Support (Node.js `package.json` & npm Scanner)

### **Goal:**
Extend SupplyShield beyond Python to analyze Node.js / JavaScript package manifests (`package.json`) and detect malicious `preinstall` / `postinstall` lifecycle scripts, obfuscated JavaScript, and dangerous `child_process.exec` calls.

### **Step-by-Step Implementation:**
1. **Create `backend/engine/javascript_analyzer.py`**:
   - Write a function `analyze_javascript_package(manifest_json_str: str, js_code: str = "") -> Dict[str, Any]`.
   - Parse `scripts` object in `package.json` for suspicious lifecycle hooks (`preinstall`, `postinstall`, `prepare`).
   - Check JS code for `eval()`, `child_process.exec`, `net.connect`, and `Buffer.from(..., 'base64')`.

2. **Add API Endpoint in `backend/api/routes_scan.py`**:
   - Add `POST /api/scan/javascript` accepting `package.json` content or JS files.

3. **Create Automated Test Suite `backend/test_js_engine.py`**:
   - Test safe vs malicious npm `package.json` files.

---

## 📌 DAY 11: Dynamic YARA & Custom Policy Rule Engine

### **Goal:**
Allow security analysts to define custom detection policies (regex patterns, banned module imports, custom risk weights) dynamically via JSON configuration without changing backend Python code.

### **Step-by-Step Implementation:**
1. **Create `backend/engine/custom_rules.py`**:
   - Write `CustomRuleEngine` class that reads rules from `backend/rules.json`.
   - Support rule types: `BANNED_IMPORT`, `REGEX_PATTERN`, `MAX_ENTROPY_THRESHOLD`.

2. **Create `backend/rules.json`**:
   ```json
   [
     {
       "rule_id": "CUSTOM-001",
       "name": "Banned Crypto Library",
       "type": "BANNED_IMPORT",
       "target": "pycryptodome",
       "severity": "HIGH",
       "risk_score_boost": 25
     }
   ]
   ```

3. **Integrate into `ast_analyzer.py`**:
   - Call `CustomRuleEngine.evaluate(ast_tree, source_code)` inside `analyze_source_ast()`.

4. **Create `backend/test_custom_rules.py`**:
   - Test adding and triggering custom rules.

---

## 📌 DAY 12: Production Docker Containerization & Multi-Container Setup

### **Goal:**
Package the entire SupplyShield application (FastAPI backend + Static Frontend + Ephemeral Subprocess Sandbox) into production-ready Docker containers.

### **Step-by-Step Implementation:**
1. **Create Root `Dockerfile`**:
   ```dockerfile
   FROM python:3.10-slim
   WORKDIR /app
   COPY requirements.txt .
   RUN pip install --no-cache-dir -r requirements.txt
   COPY . .
   EXPOSE 8000
   CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
   ```

2. **Create `docker-compose.yml`**:
   ```yaml
   version: '3.8'
   services:
     supplyshield-app:
       build: .
       ports:
         - "8000:8000"
       environment:
         - PYTHONUNBUFFERED=1
       restart: always
   ```

3. **Test Docker Build**:
   - `docker build -t supplyshield .`
   - `docker run -p 8000:8000 supplyshield`

---

## 📌 DAY 13: Final Polish, Production Documentation & Presentation Package

### **Goal:**
Perform final system verification, freeze the repository, and prepare the complete project presentation & viva defense package.

### **Step-by-Step Implementation:**
1. **Run Full Test Suite**:
   - `python -m pytest backend/ -v` (Ensure 100% tests pass).
2. **Update Project `README.md`**:
   - Ensure all 10 roadmap phases are marked as `✅ Done`.
   - Verify CLI usage examples and API documentation.
3. **Commit & Tag Release**:
   - `git add -A`
   - `git commit -m "v1.0.0: Final Release of SupplyShield Production Engine"`
   - `git push origin main`

---

# 🛠️ QUICK COMMAND CHEATSHEET

| Action | Command |
|--------|---------|
| Start Backend Server | `cd backend; python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload` |
| Open Frontend Dashboard | Open `frontend/index.html` in browser or visit `http://127.0.0.1:8000` |
| Run All Test Suites | `python -m pytest backend/test_samples_suite.py backend/test_report_engine.py backend/test_cli.py -v` |
| Run CLI Local Scan | `python backend/cli.py scan backend/samples/safe_math_pkg.py` |
| Run CLI Build Block Test | `python backend/cli.py scan backend/samples/obfuscated_backdoor.py --fail-on CRITICAL` |
| Git Status & Push | `git status` -> `git add -A` -> `git commit -m "..."` -> `git push origin main` |

---
*End of SupplyShield Master Implementation Guide & Roadmap.*
