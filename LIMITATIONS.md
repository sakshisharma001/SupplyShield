# SupplyShield Architectural Limitations & Known Weaknesses

> **Author:** Senior Security Engineer & Review Team  
> **Integrity Principle:** Every security claim must be verifiable. Known limitations are stated honestly rather than concealed.

---

## Executive Summary

Security tools that overpromise create dangerous blind spots. SupplyShield provides advanced static AST taint inspection, dynamic canary detonation, and composite risk scoring for Python packages. However, like all analysis engines, it operates under distinct technical boundaries.

Below is an honest, comprehensive documentation of SupplyShield's known limitations, edge cases, and architectural constraints.

---

## 1. Host Subprocess Sandbox vs Docker Container Isolation

### The Limitation
When Docker is unavailable in the environment (e.g., Windows workstations without Docker Desktop or lightweight cloud VMs without container runtimes), SupplyShield falls back to `WEAK_HOST_SUBPROCESS` mode if `SUPPLYSHIELD_ALLOW_WEAK_SANDBOX=True`.

### Why It Matters
In host fallback mode:
- The sample runs as the current host operating system user.
- Although SupplyShield scrubs sensitive environment variables (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`), redirects `HOME`, plants synthetic canary tripwires, and registers PEP 578 Python audit hooks (`sys.addaudithook`), it **does not provide OS kernel namespace or cgroup isolation**.
- If a malicious sample invokes native code via `ctypes` (e.g. `ctypes.cdll.msvcrt` or raw Linux syscalls), it can bypass Python-level monkeypatching and interact directly with the host kernel.

### Recommended Mitigation
In production CI/CD environments, ensure Docker is running and set `SUPPLYSHIELD_ALLOW_WEAK_SANDBOX=False`. This forces SupplyShield to reject detonations unless executed inside the hardened container with `--network none`, `--cap-drop ALL`, and a read-only root filesystem.

---

## 2. Time-Bomb Evasion & Busy-Wait Loops

### The Limitation
SupplyShield implements an automatic sleep-skipping harness (`ENABLE_SLEEP_SKIPPING=True`) that monkeypatches `time.sleep` in the detonation environment, capping delays at 0.05 seconds while recording finding `DYN-SLEEP-001`.

### The Edge Case
If an attacker uses a CPU-bound busy-wait loop instead of `time.sleep`:
```python
import time
start = time.time()
while time.time() - start < 60:
    pass  # CPU-bound spinloop
os.system("malicious_command")
```
The sleep-skipping hook will not trigger. The sample will spin until the 10.0-second sandbox watchdog expires, triggering process termination (`TIMEOUT_KILLED`). While SupplyShield correctly maps this watchdog kill to MITRE ATT&CK `T1497.003 (Sandbox Evasion: Time Based Evasion)`, the secondary payload (`malicious_command`) is never executed or dynamically observed.

---

## 3. Environment-Conditional & Targeted Triggers

### The Limitation
SupplyShield detonates code in an automated, standardized sandbox environment. Malware designed with target-specific guardrails will stay benign during detonation:
- **Target Hostname Guard:** `if socket.gethostname() != "finance-prod-01": return`
- **Delayed Activation Date:** `if datetime.date.today() < datetime.date(2027, 1, 1): return`
- **User Activity Checks:** Waiting for real user mouse movements or active GUI interaction before detonating.

### Why Static AST Helps
Even if dynamic detonation fails to trigger conditional malware, SupplyShield's static AST engine scans all branches of the code regardless of execution conditions. If the inactive branch contains dangerous subprocess calls, obfuscated strings, or sensitive paths, AST analysis still flags the threat.

---

## 4. Pre-Compiled Bytecode (.pyc) & Native Binaries

### The Limitation
SupplyShield is built specifically to analyze Python source code (`.py`) and JSON/JS manifests (`package.json`, `.js`). It does not decompile pre-compiled bytecode (`.pyc` files) or reverse-engineer compiled native extensions (`.pyd` on Windows, `.so` on Linux).

If a supply-chain attack distributes malware entirely within a compiled native extension wheel, SupplyShield will not detect inner native instructions.

---

## 5. Multi-Layer Obfuscation Depth Limit

### The Limitation
To protect against decompression bombs and Denial of Service (DoS) attacks on the parser, SupplyShield sets:
```python
MAX_DECODE_DEPTH = 3
```
If an adversary wraps a payload in 5 nested layers of Base64/zlib encoding:
- Layers 1, 2, and 3 are successfully unpacked and analyzed recursively.
- Layers 4 and 5 remain encoded strings. While high Shannon entropy (`SEC-ENT-006`) will still alert on the presence of packed data, the inner logic at Layer 5 is not parsed into AST nodes.

---

## 6. Single-Node In-Memory Rate Limiter

### The Limitation
The gateway rate limiter (`RateLimitMiddleware`) uses an in-memory sliding window store keyed by client IP (`RATE_LIMIT_PER_MINUTE=30`).

### Impact
- In single-process deployments (default uvicorn worker), it is fast and effective.
- In multi-worker or horizontally scaled cluster deployments behind a load balancer, each worker maintains an independent rate limit dictionary unless backed by a distributed cache like Redis.

---

## 7. Summary Table: Limitations vs Defenses

| Limitation | Impact | SupplyShield Countermeasure | Status |
| :--- | :--- | :--- | :---: |
| **Weak Sandbox on Windows** | No kernel cgroup isolation | Audit hooks, env sanitization, warning flag `SANDBOX-MODE-WEAK` | ⚠️ Documented Fallback |
| **Busy Loop Time Bomb** | Dynamic stage 2 unexecuted | Watchdog hard kill + MITRE `T1497.003` alert | ⚠️ Partial Defense |
| **Targeted Environment Guard** | Dynamic execution evaded | AST static engine scans inactive branches | ✅ Covered by Static AST |
| **Native C Extensions** | Uninspected binary machine code | Out of scope for pure AST engine | ❌ Documented Limitation |
| **Deep Obfuscation (>3 layers)** | Inner AST recursion halted | High Shannon entropy detection alerts on packed data | ✅ Flagged via Entropy |
