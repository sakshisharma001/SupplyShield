# SupplyShield - Placement & Viva Defense Master Guide

> **Prepared for:** Final Year Engineering Project / Campus Placement Security Technical Interviews  
> **Repository:** SupplyShield (Autonomous Software Supply-Chain Security Audit & Detonation Engine)  
> **Key Rule for Viva:** Never recite buzzwords. Give precise, technically honest answers backed by specific lines of code.

---

## Section 1: Architecture & High-Level Design

### Q1: What problem does SupplyShield solve, and why can't standard antivirus or package managers solve it?
**Answer:** Standard package managers (`pip`, `npm`) are designed for dependency resolution, not security auditing. When you run `pip install <pkg>`, Python executes arbitrary code during installation via `setup.py` hooks. Traditional antivirus looks for known file hashes (signatures) and is blind to newly published typosquatted packages or zero-day script backdoors. SupplyShield solves this by performing autonomous, multi-vector pre-installation analysis: combining compiler AST static analysis, isolated dynamic detonation, and heuristic risk scoring to detect malicious behaviors before the package reaches production.
- **Code Reference:** Pipeline coordinator in [routes_scan.py](file:///backend/api/routes_scan.py#L118-L216).

### Q2: What is the 3-stage scanning architecture of SupplyShield?
**Answer:**
1. **Stage 1 (AST Static Engine):** Compiles source code into Python's Abstract Syntax Tree. Evaluates dangerous function calls, alias imports, string entropy, Trojan Source bidi chars, and decodes nested Base64 payloads.
2. **Stage 2 (Dynamic Detonation Sandbox):** Executes untrusted code inside an isolated environment (Docker container or subprocess sandbox with PEP 578 audit hooks, synthetic canaries, and sleep-skipping).
3. **Stage 3 (Composite Risk Scorer):** Synthesizes telemetry from Stages 1 and 2, applies correlation rules, maps findings to MITRE ATT&CK techniques, and assigns an SLSA compliance tier.
- **Code Reference:** [risk_scorer.py](file:///backend/engine/risk_scorer.py#L40-L122).

### Q3: Why is FastAPI chosen over Flask or Django for the gateway?
**Answer:**
1. **Asynchronous I/O (`async/await`):** Detonation pipelines and WebSocket feeds are I/O bound. FastAPI natively handles hundreds of concurrent telemetry connections without blocking the main event loop.
2. **Built-in Schema Validation:** Pydantic provides strict runtime type checking, request bounds (e.g. `max_length`), and automated 422/413 handling.
3. **High Performance:** Built on Starlette and Uvicorn with ASGI architecture, delivering sub-millisecond route latency.
- **Code Reference:** Gateway initialization in [main.py](file:///backend/main.py#L133-L160).

### Q4: How does the real-time SOC dashboard receive telemetry?
**Answer:** Over WebSockets (`/ws/telemetry`). As the backend executes each stage (AST analysis, sandbox setup, canary alerts, risk scoring), the `ConnectionManager` broadcasts JSON telemetry packets directly to connected frontend clients, rendering live SOC terminal logs.
- **Code Reference:** [websocket_feed.py](file:///backend/api/websocket_feed.py#L18-L45) and frontend receiver in [app.js](file:///frontend/app.js#L340-L365).

---

## Section 2: Static vs. Dynamic Analysis Trade-offs

### Q5: What are the fundamental trade-offs between static (AST) and dynamic (sandbox) analysis?
**Answer:**
- **Static Analysis (AST):**
  - *Pros:* Extremely fast (p50: 1.15ms), inspects 100% of code branches (even conditional/dead code), zero risk of host infection.
  - *Cons:* Susceptible to dynamic obfuscation (`getattr(__import__('os'), 'system')`), string encryption, and dynamic runtime loading.
- **Dynamic Analysis (Sandbox):**
  - *Pros:* Observes real runtime behavior regardless of how heavily obfuscated or encrypted the payload is on disk.
  - *Cons:* Slower (p50: 356ms), only inspects paths actually executed during the run, and can be evaded by logic bombs or environment guardrails.
- **Why Both:** Combining them eliminates individual blind spots: AST catches inactive backdoors; the sandbox catches dynamic runtime decoders.
- **Code Reference:** Benchmark data in [RESULTS.md](file:///benchmarks/RESULTS.md#L43-L53).

### Q6: Why did you parse Python's AST instead of using regular expressions (Regex)?
**Answer:** Regular expressions match raw text without understanding language grammar. An adversary can easily evade regex with line breaks, string concatenation (`"os." + "system"`), or alias imports (`import os as o; o.system()`). Python's AST (`ast.parse`) builds a syntactic compiler tree where nodes represent semantic operations (`ast.Call`, `ast.Import`, `ast.Constant`). This allows alias tracking, constant folding, and contextual argument analysis that regex cannot achieve.
- **Code Reference:** AST Visitor class in [ast_analyzer.py](file:///backend/engine/ast_analyzer.py#L66-L135).

### Q7: How does your AST engine resolve alias imports like `import subprocess as sp; sp.Popen(...)`?
**Answer:** The AST visitor implements `visit_Import` and `visit_ImportFrom`. It maintains an internal alias dictionary `self.aliases = {}`. When it encounters `import subprocess as sp`, it maps `self.aliases["sp"] = "subprocess"`. When traversing an `ast.Call` on `sp.Popen`, `_resolve_callable_name()` checks the alias map and translates `sp.Popen` back to its canonical name `subprocess.Popen`.
- **Code Reference:** Alias resolution in [ast_analyzer.py](file:///backend/engine/ast_analyzer.py#L90-L112,L140-L175).

### Q8: What is constant folding and why is it implemented in SupplyShield?
**Answer:** Malware authors evade static string matching by breaking strings into pieces: `"sys" + "tem"`. SupplyShield's `_evaluate_constant_str()` recursively evaluates binary addition operations (`ast.BinOp` with `ast.Add`) on string constants at analysis time, collapsing `"sys" + "tem"` into `"system"`. When combined with `getattr()`, it resolves `getattr(os, "sys" + "tem")` to `os.system`.
- **Code Reference:** Constant folding logic in [ast_analyzer.py](file:///backend/engine/ast_analyzer.py#L177-L198).

### Q9: How does recursive payload decoding work in your AST engine?
**Answer:** When the AST visitor encounters a Base64 string literal, it decodes it and attempts to parse the decoded text with `ast.parse()`. If valid Python code is discovered, it recursively invokes `analyze_source_ast()` on the inner code, prefixing findings with `[Decoded Layer X]`. To prevent parser denial-of-service from infinite recursion bombs, recursion is strictly capped at `current_depth = 3`.
- **Code Reference:** Recursive decoding in [ast_analyzer.py](file:///backend/engine/ast_analyzer.py#L346-L387).

### Q10: What is the Trojan Source attack (CVE-2021-42574) and how do you detect it?
**Answer:** Trojan Source exploits Unicode Bidirectional (Bidi) override control characters (e.g. `\u202e` Right-to-Left Override, `\u2066` Left-to-Right Isolate). These characters alter how source code is rendered by text editors and code review tools, making executable code look like a benign comment. SupplyShield scans raw source bytes before AST parsing with `BIDI_OVERRIDE_CHARS` to flag any bidirectional control characters (`SEC-BIDI-000`).
- **Code Reference:** Bidi detection in [ast_analyzer.py](file:///backend/engine/ast_analyzer.py#L22-L33,L455-L476).

---

## Section 3: Sandbox Isolation, Safety & Canaries

### Q11: Why is executing untrusted packages on the host machine dangerous?
**Answer:** Untrusted packages run with the full permissions of the executing user. A malicious `setup.py` or script can read private SSH keys, steal AWS credentials from environment variables, delete files, spawn reverse shells, or deploy ransomware. Running detonation on a developer workstation without isolation is catastrophic.
- **Code Reference:** Audit findings documented in [AUDIT.md](file:///AUDIT.md#L40-L65).

### Q12: How does SupplyShield isolate untrusted code in Docker mode?
**Answer:** In Docker mode, detonation executes inside an ephemeral `python:3.12-slim` container with:
- `--network none`: No network access to prevent outbound exfiltration.
- `--read-only`: Root filesystem is read-only.
- `--tmpfs /tmp:rw,noexec,nosuid,size=64m`: In-memory scratch space that cannot execute binaries.
- `--cap-drop ALL` and `--security-opt no-new-privileges`: Drops all Linux kernel capabilities.
- Resource limits: `--pids-limit 50`, `--memory 128m`, `--cpus 0.5`.
- Non-root user: `--user 1000:1000`.
- **Code Reference:** Container invocation in [sandbox.py](file:///backend/engine/sandbox.py#L75-L135).

### Q13: What happens when Docker is not installed on the system?
**Answer:** SupplyShield falls back to `WEAK_HOST_SUBPROCESS` mode only if `SUPPLYSHIELD_ALLOW_WEAK_SANDBOX=True`. If set to `False`, it immediately raises a `RuntimeError` refusing to detonate on host. When fallback is permitted, it emits finding `SANDBOX-MODE-WEAK` (Severity: LOW), sanitizes environment variables, redirects `HOME`, installs synthetic canaries, monitors PEP 578 audit hooks, and enforces a hard watchdog timer.
- **Code Reference:** Fallback logic in [sandbox.py](file:///backend/engine/sandbox.py#L137-L215).

### Q14: How does the process watchdog prevent orphan child processes on timeout?
**Answer:** Malicious scripts can spawn background child processes or double-fork (`os.fork()`) to evade standard process termination. On Windows, SupplyShield executes `taskkill /F /T /PID <pid>`, which forcefully kills the entire process tree (/T flag). On Unix, it assigns the child to a new process group via `preexec_fn=os.setsid` and terminates the entire group with `os.killpg(p.pid, signal.SIGKILL)`.
- **Code Reference:** Hard kill implementation in [sandbox.py](file:///backend/engine/sandbox.py#L235-L260).

### Q15: What is PEP 578 (Python Audit Hooks) and how does SupplyShield use it?
**Answer:** Introduced in Python 3.8, PEP 578 provides runtime hooks (`sys.addaudithook`) directly embedded in CPython's runtime. Unlike monkeypatching `builtins.open` (which can be bypassed by `os.open`, `io.open`, or `pathlib`), an audit hook is called by CPython whenever core events happen: `open`, `socket.connect`, `subprocess.Popen`, `os.system`, `exec`. SupplyShield injects an audit hook into `sitecustomize.py` during detonation to log all low-level system events.
- **Code Reference:** Injected audit hook in [sandbox.py](file:///backend/engine/sandbox.py#L275-L320).

### Q16: What are synthetic canaries and how do they detect credential harvesting?
**Answer:** Canaries are decoy credential files and environment variables planted in the sandbox environment:
- Files: `~/.ssh/id_rsa`, `~/.aws/credentials`, `.env` containing unique dummy tokens.
- Env Var: `SUPPLYSHIELD_CANARY_TOKEN=ss_canary_secret_xxx`.
When untrusted code attempts to read these decoys, the file hook or audit hook immediately fires `DYN-CANARY-001`, confirming unauthorized credential harvesting.
- **Code Reference:** Canary setup in [sandbox.py](file:///backend/engine/sandbox.py#L325-L355).

### Q17: What is sleep-skipping and why is it needed?
**Answer:** Malware authors use logic bombs: `time.sleep(60)` before detonating to exceed short analysis watchdogs (e.g. 5 or 10 seconds). SupplyShield's `sitecustomize.py` patches `time.sleep()` to execute a maximum delay of 0.05 seconds while logging finding `DYN-SLEEP-001` (MITRE T1497.003). This allows the sandbox to fast-forward through evasion delays and observe the actual payload.
- **Code Reference:** Sleep patch in [sandbox.py](file:///backend/engine/sandbox.py#L290-L305).

---

## Section 4: Risk Scoring, MITRE ATT&CK & Evaluation

### Q18: What is your composite risk scoring formula?
**Answer:**
```python
base_score = max(static_score, dynamic_score) * 0.75 + min(static_score, dynamic_score) * 0.25
```
It applies severity floors: if any finding is CRITICAL, minimum score is 70; if HIGH, minimum score is 40.
Multi-vector correlation bonuses are applied when static and dynamic indicators align (e.g. static obfuscation + dynamic canary access adds +35 correlation bonus). The final score is clamped between 0 and 100.
- **Code Reference:** Risk formula in [risk_scorer.py](file:///backend/engine/risk_scorer.py#L52-L74).

### Q19: Why not use a simple average: `(static_score + dynamic_score) / 2`?
**Answer:** Simple averaging creates severe false negatives. If an offline sandbox executes code without network access, its dynamic score is 0. If static AST detects a confirmed backdoor (`score = 100`), averaging them yields 50, diluting a critical threat to medium risk. Our weighted maximum formula (`max * 0.75 + min * 0.25`) ensures a critical finding in either domain guarantees a malicious verdict.
- **Code Reference:** [risk_scorer.py](file:///backend/engine/risk_scorer.py#L52-L65).

### Q20: What are the exact evaluation metrics from your real benchmark run?
**Answer:** Tested against 72 real samples (50 Benign, 22 Malicious):
- **Detection Accuracy:** **94.44%**
- **Precision:** **90.91%**
- **Recall (Sensitivity):** **90.91%**
- **F1 Score:** **0.9091**
- **False Positive Rate (FPR):** **4.00%** (48/50 benign passed as clean)
- **AST Scan Latency:** Median (p50): **1.15 ms**, p99: **3.55 ms**
- **Full Pipeline Latency:** Median (p50): **356.53 ms**, p99: **658.2 ms**
- **Code Reference:** [RESULTS.md](file:///benchmarks/RESULTS.md#L21-L53) and script [evaluate.py](file:///benchmarks/evaluate.py).

### Q21: What caused the 2 false positives in the benchmark evaluation?
**Answer:**
1. `22_env_loader.py`: A legitimate .env file parser triggered `SEC-CRED-005` because it contained the string literal `".env"`.
2. `28_compression_helper.py`: A legitimate gzip utility triggered `SEC-OBF-007` because it called `gzip.decompress()`.
Both received a score of 40 (`SUSPICIOUS`). This demonstrates the classic security tradeoff: strict heuristics catch obfuscated unpackers but require manual review for benign data compression utilities.
- **Code Reference:** Failure analysis in [RESULTS.md](file:///benchmarks/RESULTS.md#L78-L87).

### Q22: What caused the 2 false negatives in the benchmark evaluation?
**Answer:**
1. `mal_07_ransom_wiper.py`: Overwrote user documents without invoking recognized deletion APIs or triggering network canaries.
2. `mal_12_dns_tunnel_exfiltration.py`: Exfiltrated data via DNS query (`socket.getaddrinfo`), which in offline/weak sandbox mode returned non-zero socket errors without establishing a TCP socket connection.
- **Code Reference:** Failure analysis in [RESULTS.md](file:///benchmarks/RESULTS.md#L88-L97).

### Q23: Why did you map findings to the MITRE ATT&CK framework?
**Answer:** MITRE ATT&CK provides an industry-standard ontology for cyber adversary tactics, techniques, and procedures (TTPs). Rather than presenting arbitrary alert strings, mapping to techniques like `T1059.006 (Python Execution)`, `T1552.001 (Credentials in Files)`, and `T1027 (Obfuscated Information)` enables SOC analysts to correlate supply-chain telemetry with enterprise SIEM alerts.
- **Code Reference:** MITRE map in [risk_scorer.py](file:///backend/engine/risk_scorer.py#L12-L38).

---

## Section 5: Comparative Analysis & Attack Scenarios

### Q24: How does SupplyShield compare to Bandit?
**Answer:** Bandit is a pure static linter. It cannot execute code, cannot detonate packages in a sandbox, cannot detect runtime network exfiltration, and is completely blind to dynamic code loading (`eval(base64.b64decode(...))`). SupplyShield combines AST with dynamic sandbox detonation and canary tripwires.

### Q25: How does SupplyShield compare to Semgrep or Snyk?
**Answer:** Semgrep excels at static AST pattern matching for known vulnerability patterns (CVEs) in application code. Snyk primarily checks dependency manifests (`requirements.txt`) against known CVE vulnerability databases. Neither tool detonates unknown packages in an isolated dynamic sandbox with synthetic canaries to detect novel, unindexed zero-day supply-chain backdoors.

### Q26: How does SupplyShield compare to VirusTotal?
**Answer:** VirusTotal aggregates signature-based antivirus engines and sandbox detonations tailored for compiled PE/ELF executable binaries. Python source packages (`setup.py`, `.whl`) are frequently marked 0/70 clean on VirusTotal because standard AV engines lack semantic understanding of Python AST constructs, alias deobfuscation, and synthetic canary tripwires.

### Q27: How would an attacker try to evade SupplyShield, and how would you counter them in v2?
**Answer:**
1. **CPU-bound busy wait:** Instead of `time.sleep()`, use a `while time.time() < target: pass` spinloop. *Counter in v2:* Bytecode rewriting to patch `time.time()` or inject execution count limits.
2. **Native C-Extensions:** Packaging malicious logic inside a compiled `.so` or `.pyd` wheel. *Counter in v2:* Enforce mandatory Docker container isolation and integrate native ELF/PE binary analysis (e.g., YARA and syscall tracing via eBPF).
3. **Environment-Conditional triggers:** Checking specific production hostnames before detonating. *Counter in v2:* Symbolic execution / multi-path execution to explore conditional branches dynamically.
