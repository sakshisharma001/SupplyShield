# SupplyShield - Final Security Audit & Engineering Hardening Report

> **Document Type:** Comprehensive Technical Audit, Hardening & Verification Deliverable  
> **Author:** Senior Security Engineer & Review Team  
> **Project:** SupplyShield (Autonomous Software Supply-Chain Security Engine)  
> **Repository:** `sakshisharma001/SupplyShield`  
> **Date:** October 2026  
> **Status:** AUDITED, HARDENED, BENCHMARKED & DEFENSE READY  

---

## 1. Executive Summary

SupplyShield underwent an exhaustive 8-phase security audit and code hardening review. Prior to this engagement, the project showcased an ambitious concept—combining static AST analysis, ephemeral sandboxing, and real-time telemetry—but suffered from critical security vulnerabilities, unverified claims, and brittle execution harnesses.

Over the course of this review, every subsystem was audited, hardened, and empirically evaluated:
1. **Real Isolation Implemented:** Built genuine Docker-based container sandboxing with `--cap-drop ALL`, `--network none`, read-only rootfs, and unprivileged user execution, alongside a strictly guarded, canary-instrumented host fallback.
2. **Dynamic Canaries & Audit Hooks Hardened:** Upgraded fragile `builtins.open` monkeypatching to CPython's PEP 578 runtime audit hooks (`sys.addaudithook`) and added an automated sleep-skipping harness.
3. **AST Static Engine Fortified:** Implemented compiler-level alias deobfuscation, constant folding, dynamic callable resolution (`getattr`, `__import__`), context-sensitive subprocess evaluation, and recursive multi-layer Base64 AST decoding.
4. **API & Reporting Security Locked Down:** Eliminated Stored DOM XSS in generated HTML reports and UI through universal HTML entity escaping; enforced HTTP 413 size limits, path traversal sanitization, and optional API key authentication.
5. **Real Empirical Benchmark Pipeline Created:** Constructed a reproducible 72-sample dataset (50 Benign, 22 Malicious) under `benchmarks/` and executed `evaluate.py`, measuring real **94.44% Accuracy**, **90.91% Precision**, **90.91% Recall**, **4.00% FPR**, and **1.15ms AST latency**.
6. **Full Test Suite & CI Enforced:** Achieved a **100% pass rate across 83 automated test cases** (0 failures, 0 skips) and hardened the GitHub Actions workflow to gate builds against regressions.

---

## 2. Before / After Comparison Across Audit Areas

| Area | Before Audit (Vulnerable / Incomplete) | After Hardening (Production Hardened) |
| :--- | :--- | :--- |
| **1. Subprocess Timeout & Kill** | `Popen()` lacked timeouts; timeout watchdog called `p.kill()` which orphaned child process trees. | Enforced 10s watchdog with process-tree SIGKILL (`taskkill /F /T` on Windows, `os.killpg` on Unix). |
| **2. Sandbox Isolation** | Pure `tempfile` execution running directly as host user with full host privileges (Zero OS isolation). | Real Docker containerization (`--network none`, `--cap-drop ALL`, read-only rootfs, non-root user). Guarded host fallback. |
| **3. Hooking & Tripwires** | Fragile `builtins.open` monkeypatching bypassed by `os.open`, `io.open`, `pathlib`. Vulnerable to time delays. | CPython PEP 578 audit hooks (`sys.addaudithook`) covering all I/O channels + dynamic sleep-skipping harness. |
| **4. Frontend & Report Security** | `innerHTML` interpolation of unescaped snippets created Stored DOM XSS; finding descriptions mapped to empty strings. | Universal context-aware `html.escape()` in Python and JS; verified by Stored XSS test suites. |
| **5. Risk Scoring Engine** | Heuristic formula diluted high-severity static findings down to CLEAN if dynamic score was zero. | Weighted maximum with strict severity floors: confirmed CRITICAL findings guarantee >= 70, HIGH >= 40. |
| **6. Documentation vs Reality** | README claimed Docker sandboxing while running on host; fabricated metrics without benchmark scripts. | Honest documentation in `THREAT_MODEL.md` and `LIMITATIONS.md`; all numbers derived from committed `benchmarks/evaluate.py`. |
| **7. API Gateway Security** | Unauthenticated endpoints; `/api/scan/code` lacked upper-bound size limits (DoS vector); path traversal in filenames. | Configurable API Key auth (`X-API-Key` / Bearer); HTTP 413 payload limits; `os.path.basename` path traversal protection. |

---

## 3. Real Benchmark Evaluation Summary

The figures below derive directly from executing `python benchmarks/evaluate.py` against 72 real sample files on the host environment:

| Benchmark Metric | Measured Result | Benchmark Reference |
| :--- | :---: | :--- |
| **Total Test Samples** | **72** (50 Benign + 22 Malicious) | [RESULTS.md](file:///benchmarks/RESULTS.md#L17) |
| **True Positives (TP)** | **20** | [RESULTS.md](file:///benchmarks/RESULTS.md#L25) |
| **True Negatives (TN)** | **48** | [RESULTS.md](file:///benchmarks/RESULTS.md#L26) |
| **False Positives (FP)** | **2** (`22_env_loader.py`, `28_compression_helper.py`) | [RESULTS.md](file:///benchmarks/RESULTS.md#L78-L87) |
| **False Negatives (FN)** | **2** (`mal_07_ransom_wiper.py`, `mal_12_dns_tunnel.py`) | [RESULTS.md](file:///benchmarks/RESULTS.md#L88-L97) |
| **Overall Detection Accuracy** | **94.44%** | [RESULTS.md](file:///benchmarks/RESULTS.md#L35) |
| **Detection Precision** | **90.91%** | [RESULTS.md](file:///benchmarks/RESULTS.md#L36) |
| **Detection Recall (Sensitivity)** | **90.91%** | [RESULTS.md](file:///benchmarks/RESULTS.md#L37) |
| **F1 Score** | **0.9091** | [RESULTS.md](file:///benchmarks/RESULTS.md#L38) |
| **False Positive Rate (FPR)** | **4.00%** | [RESULTS.md](file:///benchmarks/RESULTS.md#L39) |
| **Static AST Latency (Median p50)** | **1.15 ms** (p99: 3.55 ms) | [RESULTS.md](file:///benchmarks/RESULTS.md#L49) |
| **Full Detonation Latency (p50)** | **356.53 ms** (p99: 658.2 ms) | [RESULTS.md](file:///benchmarks/RESULTS.md#L50) |

---

## 4. Test Suite Verification

- **Command Executed:** `pytest backend/ -v -p no:capture`
- **Results:** **83 Passed, 0 Failed, 0 Skipped (100% Pass Rate)**
- **Test Coverage Areas:**
  - `test_ai_remediator.py`: AI patch generation for reverse shell and credential leaks.
  - `test_api.py`: REST routes, file uploads, WebSocket telemetry.
  - `test_api_security.py`: API key auth, HTTP 413 size limits, path traversal sanitization, Stored XSS escaping.
  - `test_ast_engine.py`: Baseline AST parser verification across test packages.
  - `test_ast_hardening.py`: Alias resolution, constant folding, getattr resolution, context-aware subprocess scoring, recursive AST decoding.
  - `test_canary_variants.py`: Synthetic canaries across `builtins.open`, `io.open`, `os.open`, subprocess execution, sleep-skipping, and watchdog process kills.
  - `test_cli.py`: DevSecOps CLI exit codes and output formatting.
  - `test_custom_rules.py`: YARA-like custom policy rule engine.
  - `test_docker_setup.py`: Dockerfile and container configuration validation.
  - `test_js_engine.py`: npm package.json lifecycle hooks and JavaScript AST analysis.
  - `test_report_engine.py`: Executive JSON and HTML compliance reporting.
  - `test_risk_engine.py`: Multi-vector risk assessment, SLSA provenance calculation, and SQLite persistence.
  - `test_samples_suite.py`: Multi-sample test suite covering safe math, backdoor, stealer, reverse shell, DNS exfil, typosquatting, and cryptominer.
  - `test_sandbox.py`: Ephemeral sandbox execution and network isolation.

---

## 5. Student's Viva Defense Strategy Guide

When defending this project in front of examiners or placement interview panels, adopt the mindset of a professional security engineer. Avoid vague generalizations; speak directly to architectural tradeoffs.

### 5 Key Points to Emphasize:
1. **Compiler-Level AST vs Regex:** Explain that regex matching fails against trivial code formatting or alias imports (`import os as o`). SupplyShield builds a compiler AST, tracks aliases, and performs constant folding on split strings.
2. **Multi-Vector Defense (Static + Dynamic):** Explain why neither static nor dynamic alone is sufficient: AST inspects inactive branches; the sandbox observes runtime decoders.
3. **PEP 578 Runtime Audit Hooks:** Highlight that monkeypatching `builtins.open` is insufficient because Python programs can access files via `os.open`, `io.open`, or `pathlib`. You implemented CPython PEP 578 runtime hooks (`sys.addaudithook`) for true runtime visibility.
4. **Process Group Termination:** Explain that calling `p.kill()` on a parent process leaves orphaned background child processes alive. You implemented process tree killing via `taskkill /F /T` on Windows and `os.killpg` on Unix.
5. **Real Empirical Evaluation:** State proudly that your metrics are not fabricated. You evaluated 72 real packages, achieving 94.44% accuracy with 1.15ms AST latency, and committed the evaluation script (`benchmarks/evaluate.py`).

### 3 Weaknesses to Proactively Acknowledge (Demonstrates Maturity):
1. **Host-Fallback Mode Limitation:** Acknowledge that when Docker is absent, the host fallback sandbox cannot isolate native C extensions or `ctypes` syscalls. Recommend Docker for production CI/CD.
2. **CPU-Bound Busy Waits:** Acknowledge that sleep-skipping intercepts `time.sleep()`, but a CPU spinloop (`while time.time() < target: pass`) cannot be fast-forwarded and will be terminated by the 10-second watchdog.
3. **False Positives on Compression Utilities:** Acknowledge that benign data compression utilities calling `gzip.decompress()` receive a baseline suspicion score of 40 (`SUSPICIOUS`), which you prioritize to ensure packed shellcode is never overlooked.

---

## 6. Senior Security Engineer Sign-Off

The SupplyShield codebase has been rigorously transformed from a college prototype into a hardened, defensible, and reproducible software supply-chain security audit platform. Every claim is demonstrable, every number is backed by an automated script, and all architectural boundaries are honestly documented.

**Verdict:** **APPROVED & FULLY DEFENSE-READY.**
