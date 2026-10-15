# SupplyShield Security & Architecture Audit Report (Phase 0)

**Date:** 2026-10-15  
**Auditor:** Senior Security Engineer & Code Reviewer  
**Scope:** SupplyShield Core Detection Engines, Dynamic Sandbox, API Gateways, Frontend SOC Dashboard, and Documentation  
**Target:** College Placement & Technical Viva Defense Readiness

---

## Executive Summary

SupplyShield is designed as an autonomous multi-layer software supply-chain security auditing system combining Python AST static analysis, dynamic subprocess execution, risk scoring, and a real-time web dashboard.

While the project features a structured modular layout and real AST parsing rules, the audit identified **critical architectural gaps, safety illusions, security vulnerabilities, and classification inaccuracies** that would fail a rigorous technical viva or senior code review. 

This document provides a factual, line-by-line verification of the 7 core audit questions, documenting what is real, what is flawed, and what must be addressed.

---

## 1. Audit Findings: Verification of Core Questions

### Q1: Does `subprocess.Popen` get a `timeout=` argument anywhere?
* **Status:** **Partially Correct, but Process Watchdog is Flawed.**
* **Analysis:**
  - In [backend/engine/sandbox.py:172-186](file:///c:/Users/saksh/OneDrive/Apps/Designer/Desktop/Personal/backend/engine/sandbox.py#L172-L186), `subprocess.Popen` is instantiated without a `timeout=` argument (correct, as `Popen` constructor does not take `timeout`), and the timeout is passed to `process.communicate(timeout=self.timeout_seconds)`.
  - **The Flaw:** When `subprocess.TimeoutExpired` is caught, the code calls `process.kill()`:
    ```python
    except subprocess.TimeoutExpired:
        process.kill()
        stdout_output, stderr_output = process.communicate()
    ```
  - On both Linux and Windows, `process.kill()` only terminates the top-level Python parent process. If the untrusted sample spawned any child processes (e.g. `subprocess.Popen(["xmrig", ...])` or background sockets), those child processes are **orphaned and continue running indefinitely on the host machine**.
* **Remediation Required:** Process tree termination or container lifecycle termination.

---

### Q2: Is the sandbox only tempfile + env-var redirection?
* **Status:** **TRUE — There is ZERO real isolation.**
* **Analysis:**
  - In [backend/engine/sandbox.py:134-175](file:///c:/Users/saksh/OneDrive/Apps/Designer/Desktop/Personal/backend/engine/sandbox.py#L134-L175):
    ```python
    temp_dir = tempfile.mkdtemp(prefix=settings.TEMP_DIR_PREFIX)
    env["HOME"] = temp_dir
    env["USERPROFILE"] = temp_dir
    env["PYTHONPATH"] = temp_dir
    ```
  - The process is executed using `sys.executable` directly on the **host operating system**, with the **full privileges of the user running SupplyShield**.
  - There are:
    - **No Linux namespaces or cgroups**
    - **No chroot or restricted filesystem mount**
    - **No network namespace** (the host's network stack is directly accessible)
    - **No capability drops**
  - Any code running `os.system("whoami")`, invoking PowerShell, compiling C extensions, or using `ctypes` can execute arbitrary commands, delete files outside the temp directory, or infect the host machine.
* **Remediation Required:** Implement containerized detonation via Docker (`--network none`, `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--memory`, `--cpus`) with an explicit "WEAK MODE" fallback.

---

### Q3: Does `sitecustomize.py` actually load, and does it trip?
* **Status:** **Loads successfully, but TRIVIALLY BYPASSABLE.**
* **Analysis:**
  - **Loading:** Verified experimentally. Because `PYTHONPATH` includes `temp_dir`, CPython's standard startup imports `site.py`, which loads `sitecustomize.py`.
  - **Tripping & Interception Flaw:**
    In [backend/engine/sandbox.py:30-70](file:///c:/Users/saksh/OneDrive/Apps/Designer/Desktop/Personal/backend/engine/sandbox.py#L30-L70), the hook only overrides `builtins.open`:
    ```python
    builtins.open = _hooked_open
    ```
    Testing verified that:
    1. Direct `open()` calls are intercepted.
    2. **Bypasses:** Calls to `io.open()`, `os.open()`, `pathlib.Path.read_text()`, and shell commands like `subprocess.run(["cat", ".env"])` or `type` completely bypass `builtins.open`.
    3. Socket hooking only wraps `socket.socket.connect`, leaving `socket.socket.sendto` (UDP), raw sockets, `asyncio` transports, and C-level extensions unmonitored.
* **Remediation Required:** Integrate `sys.addaudithook` for kernel/interpreter-level event logging and hook `os.open`, `io.open`.

---

### Q4: Is scanned-code content rendered into HTML without escaping (Stored XSS)?
* **Status:** **TRUE — Active Stored DOM XSS Vulnerability in Frontend.**
* **Analysis:**
  - In [frontend/app.js:531-532](file:///c:/Users/saksh/OneDrive/Apps/Designer/Desktop/Personal/frontend/app.js#L531-L532):
    ```javascript
    <div class="finding-desc"><strong>${f.category || "Security Finding"}:</strong> ${f.description}</div>
    ${f.snippet ? `<div class="finding-snippet"><code>${f.snippet}</code></div>` : ""}
    ```
    This string is directly injected into the DOM via `container.innerHTML = ...`.
  - If scanned code contains a string literal or comment such as `<img src=x onerror=alert(document.cookie)>`, the AST extractor extracts the raw line as `f.snippet`, which executes arbitrary JavaScript in the user's browser.
  - In [frontend/app.js:648](file:///c:/Users/saksh/OneDrive/Apps/Designer/Desktop/Personal/frontend/app.js#L648), `item.target_file` is also interpolated without escaping.
  - In [backend/engine/report_generator.py:69-70](file:///c:/Users/saksh/OneDrive/Apps/Designer/Desktop/Personal/backend/engine/report_generator.py#L69-L70), while `html.escape` is used for `f.get("description")`, `description` doesn't match the AST key `"message"`, leaving descriptions blank.
* **Remediation Required:** Implement context-aware HTML escaping for all finding fields, snippets, target names, and reports.

---

### Q5: Are there hardcoded scores or sample names in the codebase?
* **Status:** **Heuristic Hardcoded Constants & Sample Demonstrations Present.**
* **Analysis:**
  - **Scores:** In [backend/engine/risk_scorer.py:59-67](file:///c:/Users/saksh/OneDrive/Apps/Designer/Desktop/Personal/backend/engine/risk_scorer.py#L59-L67):
    `correlation_bonus += 35` and `correlation_bonus += 30` are hardcoded heuristics rather than empirically calibrated weights.
    In [backend/engine/sandbox.py:243-248](file:///c:/Users/saksh/OneDrive/Apps/Designer/Desktop/Personal/backend/engine/sandbox.py#L243-L248), dynamic score increments (+40, +25, +15) are hardcoded.
  - **Engine Decoupling:** Core engines (`ast_analyzer.py` and `sandbox.py`) do NOT check filenames or hardcode verdicts for specific packages. Detection logic is AST- and hook-driven.
  - **Presets:** [frontend/app.js:17-174](file:///c:/Users/saksh/OneDrive/Apps/Designer/Desktop/Personal/frontend/app.js#L17-L174) contains pre-baked code presets for demo purposes.
  - **Report IDs:** [backend/engine/report_generator.py:37](file:///c:/Users/saksh/OneDrive/Apps/Designer/Desktop/Personal/backend/engine/report_generator.py#L37) uses prefix `REP-`.
* **Remediation Required:** Transparently document scoring weights as empirical heuristics and calibrate them using a real benchmark evaluation corpus.

---

### Q6: Do documentation and architecture claims contradict each other? Is T1499 used wrongly?
* **Status:** **TRUE — Significant Contradictions & MITRE Misclassification.**
* **Analysis:**
  - **Sandbox Contradiction:** [README.md:17](file:///c:/Users/saksh/OneDrive/Apps/Designer/Desktop/Personal/README.md#L17) claims `Docker-Supported` and highlights "Sandboxed Detonation Engine". In reality, Docker is only used to run the FastAPI web server (`uvicorn main:app`). Untrusted code detonation runs via host subprocesses.
  - **T1499 Misclassification:**
    In [backend/engine/sandbox.py:198](file:///c:/Users/saksh/OneDrive/Apps/Designer/Desktop/Personal/backend/engine/sandbox.py#L198) and [backend/engine/risk_scorer.py:22](file:///c:/Users/saksh/OneDrive/Apps/Designer/Desktop/Personal/backend/engine/risk_scorer.py#L22):
    ```python
    "mitre_tag": "T1499 Endpoint Denial of Service / Reverse Shell Wait"
    ```
    MITRE ATT&CK technique **T1499 is Endpoint Denial of Service** (e.g. OS resource exhaustion, crashing network services). A script sleeping, hanging, or waiting on a socket is **NOT** T1499. It is either **T1497 (Virtualization/Sandbox Evasion: Time Based Evasion)** or **T1059 (Execution)**.
* **Remediation Required:** Align documentation to state exact detonation mechanics honestly and correct MITRE ATT&CK taxonomy mappings with technical justifications.

---

### Q7: Do `/api/scan/code` and `/api/scan/package` have Auth, Rate Limiting, and Size Limits?
* **Status:** **Partially Implemented; Major DoS Vulnerabilities Exist.**
* **Analysis:**
  | Security Control | `/api/scan/package` | `/api/scan/code` | Vulnerability / Gap |
  |---|---|---|---|
  | **Authentication** | ❌ None | ❌ None | Any client can invoke resource-heavy detonation without credentials. |
  | **Rate Limiting** | ⚠️ In-memory (30/min) | ⚠️ In-memory (30/min) | Ephemeral IP-based window; resets on restart, bypassable via IP spoofing. |
  | **Size Limit** | ✅ 512 KB (`validate_upload`) | ❌ **NONE** | `ScanCodeRequest.code` has `min_length=1` with no upper bound. Submitting a 50MB string causes CPU denial of service in the AST parser. |
* **Remediation Required:** Add API key enforcement (configurable via env), strict string length limits on `ScanCodeRequest`, and request timeout bounds.

---

## 2. Additional Deficiencies Identified

1. **AST Alias Evasion:**
   - [backend/engine/ast_analyzer.py:270-274](file:///c:/Users/saksh/OneDrive/Apps/Designer/Desktop/Personal/backend/engine/ast_analyzer.py#L270-L274) resolves callables only by looking at `ast.Name` and simple `ast.Attribute`.
   - Aliases such as `from os import system as s; s(...)`, `import subprocess as sp; sp.Popen(...)`, `__import__('os').system(...)`, and `getattr(os, 'sys' + 'tem')(...)` completely evade AST detection.
2. **Shannon Entropy False Positives:**
   - Any string literal > 40 chars with high variety (e.g. long documentation strings, license headers, URL query parameters) triggers `SEC-ENT-006` without verifying if it actually decodes to valid Python bytecode.
3. **No Recursive Unpacking:**
   - Base64 strings that decode to executable Python code are flagged as strings, but the inner payload is never recursively parsed or inspected.
4. **Lack of Benchmark Corpus:**
   - Detection numbers and performance claims lack automated reproducibility against real public datasets (e.g. DataDog malicious packages dataset, Backstabber's Knife Collection, top PyPI packages).

---

## 3. Recommended Remediation Roadmap

- **Phase 1:** Implement true Docker containerized detonation (`--network none`, read-only, non-root, drop-caps, cgroups) with a labeled "WEAK MODE" fallback, and fix MITRE mappings (replace T1499).
- **Phase 2:** Harden canary file traps with `sys.addaudithook`, `os.open`, and `io.open` interception; document ctypes/native bypass limitations honestly.
- **Phase 3:** Upgrade AST engine with alias tracking, constant folding, recursive decoding (depth <= 3), and context-aware scoring.
- **Phase 4:** Harden REST APIs with API Key authentication, request size bounds, and context-aware HTML escaping for report generation and dashboard feeds.
- **Phase 5:** Build `benchmarks/` evaluation suite measuring real false-positive and detection rates across real benign and malicious packages.
- **Phase 6:** Modernize automated test suites and CI pipeline.
- **Phase 7:** Revamp documentation (`THREAT_MODEL.md`, `LIMITATIONS.md`, `VIVA_PREP.md`, `README.md`) with zero unverified claims.
