# SupplyShield Threat Model

> **Document Version:** 1.0.0  
> **Target System:** SupplyShield Autonomous Software Supply-Chain Security Engine  
> **Audience:** Security Architects, Academic Evaluators, Senior Code Reviewers  

---

## 1. System Overview & Scope

SupplyShield analyzes third-party Python packages and source snippets prior to installation to identify software supply-chain attacks (malicious code injected via dependency confusion, typosquatting, compromised maintainer accounts, or malicious package versions).

The system accepts untrusted source code and subjects it to multi-vector static and dynamic analysis:
1. **Static Analysis (AST & Regex):** Syntactic inspection, alias deobfuscation, constant evaluation, entropy measurement, and Trojan Source character detection.
2. **Dynamic Detonation Sandbox:** Execution in an isolated environment (Docker container with strict cgroups/namespaces, or subprocess sandbox with PEP 578 audit hooks and synthetic canaries).
3. **Risk Scoring & MITRE ATT&CK Mapping:** Unified heuristic risk evaluation yielding a composite score (0–100), SLSA assurance tier, and MITRE TTP taxonomy.

---

## 2. Protected Assets

| Asset ID | Description | Impact of Compromise |
| :--- | :--- | :--- |
| **A-1: Developer Workstation** | Host operating system running SupplyShield or developer IDE. | System compromise, persistent backdoor, malware infection. |
| **A-2: Cloud & Host Credentials** | Sensitive files (`~/.ssh/id_rsa`, `~/.aws/credentials`, `.env`, tokens). | Lateral movement, cloud resource compromise, secret exfiltration. |
| **A-3: CI/CD Build Pipeline** | GitHub Actions runner or internal build server executing automated scans. | Poisoned build artifacts, compromised release pipeline. |
| **A-4: Audit Integrity** | SQLite audit database containing scan reports and compliance logs. | Tampering with security records, hiding malicious package detections. |

---

## 3. Adversary Profile & Threat Actors

| Actor Tier | Capabilities | Motives |
| :--- | :--- | :--- |
| **Script Kiddie / Opportunist** | Public reverse shell payloads, basic base64 encoding, copy-pasted stealers. | Low-effort credential harvesting, botnet enlistment. |
| **Targeted Supply-Chain Adversary** | Dynamic callable resolution (`getattr`, `__import__`), multi-layer nested encoding, logic bomb time delays, homoglyph substitution, setup install hooks. | Stealthy exfiltration of proprietary credentials, persistent backdoors in corporate networks. |
| **Nation-State / Advanced Actor** | Kernel exploits, 0-day sandbox breakouts, ctypes-based native memory manipulation, compiler-level trojans. | High-value espionage, critical infrastructure disruption. |

---

## 4. Attack Surfaces & Entrypoints

```
[Attacker Controlled]
        │
        ▼
  +──────────────────────────────────────────────+
  │ REST API Gate: /api/scan/code, /api/scan/package │
  │ CLI Tool: supplyshield scan <pkg>            │
  +──────────────────────┬───────────────────────+
                         │
         ┌───────────────┴───────────────┐
         ▼                               ▼
  [AST Parser]                  [Detonation Sandbox]
  • Input Size Bomb              • Syscall / OS Escapes
  • ReDoS in Regex Patterns      • Canary Tampering
  • Recursion Bombs              • Watchdog Evasion (Sleep Loops)
```

1. **REST Endpoints (`/api/scan/code`, `/api/scan/package`):**
   - Untrusted file payloads up to 512KB.
   - Malicious package names containing directory traversal sequences (`../../etc/passwd`).
   - Stored XSS via malicious strings in code comments or finding titles rendered in HTML reports.
2. **Static AST Traversal:**
   - Deeply nested abstract syntax trees designed to cause stack overflow (RecursionError).
   - Massive Base64 strings triggering quadratic memory allocation during recursive decoding.
3. **Dynamic Detonation Environment:**
   - Untrusted sample execution attempting host filesystem escape, subprocess spawning, and outbound socket connections.

---

## 5. Security Boundaries & Countermeasures

### 5.1 Ingestion Gate
- **Payload Size Enforcement:** `/api/scan/code` rejects strings exceeding `MAX_CODE_LENGTH_CHARS` (200,000 characters) with HTTP 413.
- **Path Traversal Sanitization:** All incoming filenames and target names are sanitized using `os.path.basename()` before file creation or report archival.
- **API Key Authentication:** If `SUPPLYSHIELD_API_KEY` is configured, requests must provide `X-API-Key` or `Authorization: Bearer <token>`.
- **Stored XSS Prevention:** Every field in `report_generator.py` and `frontend/app.js` is sanitized using strict HTML entity escaping (`html.escape` in Python, DOM-safe replacement in JS).

### 5.2 Sandbox Isolation Boundary
- **Tier 1: Docker Sandbox (Preferred Production Mode)**
  - Docker container running `python:3.12-slim` as non-root UID 1000:1000.
  - `--network none`: zero outbound network interface access.
  - `--read-only` root filesystem; only `/tmp` writable as temporary `tmpfs` (64MB max, `noexec`, `nosuid`).
  - `--cap-drop ALL`, `--security-opt no-new-privileges`.
  - Resource limits: `--pids-limit 50`, `--memory 128m`, `--cpus 0.5`.
  - Watchdog: 10.0-second timeout followed by forced container removal (`docker rm -f`).
- **Tier 2: Host Subprocess Sandbox (Fallback Mode)**
  - Activated only when Docker is absent and `SUPPLYSHIELD_ALLOW_WEAK_SANDBOX=True`.
  - Emits explicit warning finding `SANDBOX-MODE-WEAK` (Severity: LOW).
  - Environment variable purging: scrubs `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, and personal paths.
  - Synthetic Canary Tripwires: plants dummy `.ssh/id_rsa`, `.aws/credentials`, and `.env` files in isolated temp directory.
  - Runtime Python Audit Hooks (PEP 578): monitors `open`, `socket.connect`, `subprocess.Popen`, `os.system`.
  - Sleep-Skipping Harness: dynamically patches `time.sleep` to 0.05s max to eliminate time-based sandbox delays.
  - Process Tree Termination: uses `taskkill /F /T /PID` (Windows) and `os.killpg` (Unix) to prevent orphan child processes.

---

## 6. Threat Matrix: What SupplyShield Protects Against vs Cannot

| Threat Scenario | Protected? | Defense Mechanism |
| :--- | :---: | :--- |
| **Credential Harvesting (.aws, .ssh, .env)** | ✅ YES | AST `SEC-CRED-005` detects literal paths; Sandbox canaries catch dynamic file read attempts. |
| **Reverse Shells (sh, bash, python socket, powershell)** | ✅ YES | AST `SEC-SYS-002` flags subprocess calls; Sandbox audit hook intercepts `socket.connect` & `subprocess.Popen`. |
| **Obfuscated / Multi-Layer Payloads** | ✅ YES | Recursive AST decoding (up to depth 3) extracts inner Python payloads from base64/zlib. |
| **Trojan Source (CVE-2021-42574)** | ✅ YES | Bidirectional unicode overrides (RLI, LRI, RLO) detected before AST compilation (`SEC-BIDI-000`). |
| **Typosquatting Homoglyphs** | ✅ YES | AST `SEC-HOMOGLYPH-001` flags non-ASCII Cyrillic/Greek homoglyphs in module identifiers. |
| **Logic Bomb Time Evasion (`time.sleep`)** | ✅ YES | AST `SEC-TIME-008` flags delays >= 30s; Sandbox sleep-skipping bypasses sleep calls. |
| **Stored XSS in Reports / Dashboard** | ✅ YES | Complete HTML entity encoding on all user-controlled variables in reports and UI. |
| **Denial of Service via Payload Size** | ✅ YES | HTTP 413 size limits enforced at gateway level. |
| **Native C-Extension / ctypes Bypasses in Host Mode** | ❌ NO | Host subprocess mode cannot intercept direct C syscalls or `ctypes` without kernel containerization. |
| **Busy-Wait Time Evasion (`while time.time() < t: pass`)** | ⚠️ PARTIAL | Sleep-skipping cannot fast-forward CPU-bound busy loops; the 10.0s watchdog kills the process with `TIMEOUT_KILLED`. |
| **Zero-Day Logic Flaws in Python Parser** | ❌ NO | Out of scope. Python `ast` syntax crashes result in `SYNTAX_ERROR` alert. |
