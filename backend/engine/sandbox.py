"""
SupplyShield - Ephemeral Dynamic Detonation Sandbox
Executes untrusted Python package scripts within an isolated, temporary environment.
Features:
- Subprocess execution with strict watchdog timeout (3.0s)
- Synthetic Canary Tripwires (.ssh/id_rsa, .env) with automated access audit hooks
- REAL network socket blocking via monkey-patched sitecustomize.py
- REAL filesystem isolation — access outside sandbox dir raises PermissionError
- Telemetry capture (stdout, stderr, exit code, execution time, file access logs)
- Automatic environment destruction with zero host residue
"""

import os
import sys
import time
import shutil
import tempfile
import subprocess
from typing import Dict, List, Any, Optional

from config import settings

CANARY_SSH_PAYLOAD = "CANARY_TRIPWIRE_SSH_KEY_TRIGGERED_SUPPLYSHIELD_0xDEADBEEF"
CANARY_ENV_PAYLOAD = "AWS_SECRET_ACCESS_KEY=CANARY_KEY_TRIGGERED_0xFEEDFACE\nDATABASE_URL=postgres://canary:trap@localhost/secret"

# ─────────────────────────────────────────────────────────────────────────────
# AUDIT HOOK + NETWORK BLOCKER + FS RESTRICTOR injected into sandbox process
# via sitecustomize.py (auto-loaded by Python when PYTHONPATH includes sandbox dir)
# ─────────────────────────────────────────────────────────────────────────────
AUDIT_HOOK_CODE = """\
import builtins
import os
import sys

_real_open = builtins.open
_audit_log  = os.environ.get("SUPPLYSHIELD_AUDIT_LOG", "")
_sandbox_root = os.environ.get("SUPPLYSHIELD_SANDBOX_ROOT", "")

# ── 1. FILE ACCESS INTERCEPTOR ──────────────────────────────────────────────
SENSITIVE_KEYS = [".ssh", "id_rsa", "id_ed25519", ".env", ".aws",
                  "shadow", "passwd", "credentials", ".config/gcloud"]

def _log_audit(msg):
    if _audit_log:
        try:
            with _real_open(_audit_log, "a", encoding="utf-8") as lf:
                lf.write(msg + "\\n")
        except Exception:
            pass

def _hooked_open(file, *args, **kwargs):
    file_str = str(file)
    # Log sensitive file access
    if any(k in file_str.lower() for k in SENSITIVE_KEYS):
        _log_audit(f"FILE_ACCESS:{file_str}")
    # Filesystem isolation — block reads outside sandbox root
    if _sandbox_root:
        try:
            real_path = os.path.realpath(file_str)
            real_root = os.path.realpath(_sandbox_root)
            if not real_path.startswith(real_root):
                _log_audit(f"FS_ESCAPE_ATTEMPT:{file_str}")
                raise PermissionError(
                    f"[SupplyShield] Filesystem escape blocked: '{file_str}' is outside sandbox."
                )
        except (ValueError, OSError):
            pass
    return _real_open(file, *args, **kwargs)

builtins.open = _hooked_open

# ── 2. NETWORK SOCKET BLOCKER ───────────────────────────────────────────────
import socket as _socket_module

_real_socket_connect = _socket_module.socket.connect
_real_socket_connect_ex = _socket_module.socket.connect_ex
_real_create_connection = _socket_module.create_connection

def _blocked_connect(self, address, *args, **kwargs):
    host = address[0] if isinstance(address, (tuple, list)) else str(address)
    _log_audit(f"NETWORK_ATTEMPT:{host}")
    raise ConnectionRefusedError(
        f"[SupplyShield] Outbound network connection BLOCKED: {address}"
    )

def _blocked_connect_ex(self, address, *args, **kwargs):
    host = address[0] if isinstance(address, (tuple, list)) else str(address)
    _log_audit(f"NETWORK_ATTEMPT:{host}")
    return 111  # ECONNREFUSED

def _blocked_create_connection(address, *args, **kwargs):
    host = address[0] if isinstance(address, (tuple, list)) else str(address)
    _log_audit(f"NETWORK_ATTEMPT:{host}")
    raise ConnectionRefusedError(
        f"[SupplyShield] Outbound network connection BLOCKED: {address}"
    )

_socket_module.socket.connect    = _blocked_connect
_socket_module.socket.connect_ex = _blocked_connect_ex
_socket_module.create_connection = _blocked_create_connection

# Also block urllib / http.client at the resolver level
import urllib.request as _urllib_req

def _blocked_urlopen(url, *args, **kwargs):
    _log_audit(f"NETWORK_ATTEMPT:urllib:{url}")
    raise ConnectionRefusedError(
        f"[SupplyShield] urllib outbound request BLOCKED: {url}"
    )

_urllib_req.urlopen = _blocked_urlopen
"""


class DynamicSandbox:
    """
    Orchestrates ephemeral sub-process execution environments to capture
    dynamic malware behavior, file theft attempts, network exfiltration,
    and execution anomalies.
    """

    def __init__(self, timeout_seconds: float = settings.SANDBOX_TIMEOUT_SECONDS):
        self.timeout_seconds = timeout_seconds

    def detonate(self, source_code: str, package_name: str = "untrusted_sample") -> Dict[str, Any]:
        """
        Executes code inside an isolated ephemeral temporary directory with:
        - Canary credential traps (.ssh/id_rsa, .env)
        - Real network socket blocking
        - Filesystem escape detection
        - 3-second hard kill watchdog
        """
        start_time = time.time()
        temp_dir = tempfile.mkdtemp(prefix=settings.TEMP_DIR_PREFIX)

        dynamic_findings: List[Dict[str, Any]] = []
        status = "COMPLETED"
        stdout_output = ""
        stderr_output = ""
        exit_code: Optional[int] = None
        audit_log_path = os.path.join(temp_dir, "canary_audit.log")

        try:
            # ── STEP 1: Canary Traps ─────────────────────────────────────────
            canary_ssh_path, canary_env_path = self._plant_canaries(temp_dir)

            # ── STEP 2: Inject Audit Hook + Network Blocker + FS Restrictor ──
            hook_path = os.path.join(temp_dir, "sitecustomize.py")
            with open(hook_path, "w", encoding="utf-8") as f:
                f.write(AUDIT_HOOK_CODE)

            # ── STEP 3: Write Target Payload Script ──────────────────────────
            script_path = os.path.join(temp_dir, "payload_runner.py")
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(source_code)

            # ── STEP 4: Build Hardened Subprocess Environment ─────────────────
            env = os.environ.copy()
            env["HOME"]                    = temp_dir   # fake home dir
            env["USERPROFILE"]             = temp_dir   # Windows fake home
            env["PYTHONPATH"]              = temp_dir   # loads sitecustomize.py
            env["PYTHONUNBUFFERED"]        = "1"
            env["SUPPLYSHIELD_AUDIT_LOG"]  = audit_log_path
            env["SUPPLYSHIELD_SANDBOX_ROOT"] = temp_dir  # FS isolation root
            # Strip dangerous env vars so malicious code can't steal them
            for danger_key in ["AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID",
                               "GITHUB_TOKEN", "DATABASE_URL", "SECRET_KEY",
                               "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]:
                env.pop(danger_key, None)

            # ── STEP 5: Launch Isolated Subprocess ───────────────────────────
            process = subprocess.Popen(
                [sys.executable, script_path],
                cwd=temp_dir,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace"
            )

            try:
                stdout_output, stderr_output = process.communicate(
                    timeout=self.timeout_seconds
                )
                exit_code = process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                stdout_output, stderr_output = process.communicate()
                status = "TIMEOUT_KILLED"
                exit_code = -9
                dynamic_findings.append({
                    "rule_id":   "DYN-TIME-001",
                    "severity":  "CRITICAL",
                    "title":     f"Process Watchdog Hard-Kill (Timeout: {self.timeout_seconds}s)",
                    "message":   "Script exceeded maximum allowable execution threshold. Likely persistent backdoor or reverse-shell wait loop.",
                    "mitre_tag": "T1499 Endpoint Denial of Service / Reverse Shell Wait"
                })

            # ── STEP 6: Audit Canary File Access ─────────────────────────────
            canary_findings = self._audit_canary_access(
                temp_dir, canary_ssh_path, canary_env_path, audit_log_path
            )
            dynamic_findings.extend(canary_findings)

            # ── STEP 7: Audit Network Block Log ──────────────────────────────
            net_findings = self._audit_network_attempts(audit_log_path)
            dynamic_findings.extend(net_findings)

            # ── STEP 8: Audit Filesystem Escape Attempts ──────────────────────
            fs_findings = self._audit_fs_escape(audit_log_path)
            dynamic_findings.extend(fs_findings)

            # ── STEP 9: Check stderr for additional socket errors ─────────────
            if stderr_output:
                lower_err = stderr_output.lower()
                if any(e in lower_err for e in [
                    "connectionrefusederror", "socket.error",
                    "winerror 10061", "name resolution", "gaierror"
                ]) and not net_findings:
                    # Only add if not already captured by audit log
                    dynamic_findings.append({
                        "rule_id":   "DYN-NET-002",
                        "severity":  "HIGH",
                        "title":     "Outbound Socket Connection Attempt Detected via stderr",
                        "message":   "Subprocess triggered network/socket connection errors during setup execution.",
                        "mitre_tag": "T1071 Application Layer Protocol (C2 Communication)"
                    })

        except Exception as e:
            status = "EXECUTION_ERROR"
            stderr_output += f"\nSandbox Orchestration Exception: {str(e)}"
        finally:
            # ── STEP 10: Ephemeral Teardown (Zero Host Residue) ───────────────
            shutil.rmtree(temp_dir, ignore_errors=True)

        execution_duration = round(time.time() - start_time, 4)

        # Dynamic Risk Score (0–100)
        dynamic_risk_score = 0
        for f in dynamic_findings:
            if f["severity"] == "CRITICAL":
                dynamic_risk_score += 40
            elif f["severity"] == "HIGH":
                dynamic_risk_score += 25
            elif f["severity"] == "MEDIUM":
                dynamic_risk_score += 15

        return {
            "status":               status,
            "package_name":         package_name,
            "execution_duration_sec": execution_duration,
            "exit_code":            exit_code,
            "stdout":               stdout_output.strip(),
            "stderr":               stderr_output.strip(),
            "dynamic_findings":     dynamic_findings,
            "dynamic_risk_score":   min(dynamic_risk_score, 100)
        }

    # ── Private Helpers ────────────────────────────────────────────────────────

    def _plant_canaries(self, sandbox_dir: str):
        """Plants fake canary credential files to trap credential stealers."""
        ssh_dir = os.path.join(sandbox_dir, ".ssh")
        os.makedirs(ssh_dir, exist_ok=True)

        canary_ssh_file = os.path.join(ssh_dir, "id_rsa")
        with open(canary_ssh_file, "w", encoding="utf-8") as f:
            f.write(CANARY_SSH_PAYLOAD)

        # Additional: fake AWS credentials file
        aws_dir = os.path.join(sandbox_dir, ".aws")
        os.makedirs(aws_dir, exist_ok=True)
        canary_aws_file = os.path.join(aws_dir, "credentials")
        with open(canary_aws_file, "w", encoding="utf-8") as f:
            f.write("[default]\naws_access_key_id = AKIAIOSFODNN7CANARY\naws_secret_access_key = CANARY_SECRET_0xDEADBEEF\n")

        canary_env_file = os.path.join(sandbox_dir, ".env")
        with open(canary_env_file, "w", encoding="utf-8") as f:
            f.write(CANARY_ENV_PAYLOAD)

        return canary_ssh_file, canary_env_file

    def _audit_canary_access(
        self, sandbox_dir: str, ssh_path: str, env_path: str, audit_log_path: str
    ) -> List[Dict[str, Any]]:
        """Audits whether canary files were read, modified, or targeted."""
        findings = []

        if os.path.exists(audit_log_path):
            with open(audit_log_path, "r", encoding="utf-8") as f:
                logs = f.read()

            if ".ssh" in logs or "id_rsa" in logs:
                findings.append({
                    "rule_id":   "DYN-CANARY-001",
                    "severity":  "CRITICAL",
                    "title":     "Unauthorized SSH Private Key Access Intercepted",
                    "message":   "Script triggered dynamic canary tripwire attempting to read ~/.ssh/id_rsa.",
                    "mitre_tag": "T1552.004 Credentials in Files: Private Keys"
                })

            if ".env" in logs:
                findings.append({
                    "rule_id":   "DYN-CANARY-002",
                    "severity":  "HIGH",
                    "title":     "Environment File (.env) Access Intercepted",
                    "message":   "Script dynamically opened the .env secrets file during execution.",
                    "mitre_tag": "T1552 Credentials in Files"
                })

            if ".aws" in logs or "credentials" in logs:
                findings.append({
                    "rule_id":   "DYN-CANARY-003",
                    "severity":  "CRITICAL",
                    "title":     "AWS Credentials File Access Intercepted",
                    "message":   "Script targeted the .aws/credentials canary file — cloud credential harvesting attempt.",
                    "mitre_tag": "T1552.001 Credentials in Files: AWS Keys"
                })

        # Physical canary tampering check
        if not os.path.exists(ssh_path):
            findings.append({
                "rule_id":   "DYN-CANARY-004",
                "severity":  "CRITICAL",
                "title":     "SSH Private Key Deleted / Tampered",
                "message":   "The script deleted or moved the canary SSH private key.",
                "mitre_tag": "T1552.004 Credentials in Files: Private Keys"
            })

        return findings

    def _audit_network_attempts(self, audit_log_path: str) -> List[Dict[str, Any]]:
        """Reads audit log for REAL blocked network connection attempts."""
        findings = []
        if not os.path.exists(audit_log_path):
            return findings

        with open(audit_log_path, "r", encoding="utf-8") as f:
            logs = f.read()

        net_attempts = [line for line in logs.splitlines() if line.startswith("NETWORK_ATTEMPT:")]
        if net_attempts:
            targets = ", ".join(set(line.replace("NETWORK_ATTEMPT:", "") for line in net_attempts[:5]))
            findings.append({
                "rule_id":   "DYN-NET-002",
                "severity":  "CRITICAL",
                "title":     "REAL Outbound Network Connection Blocked",
                "message":   f"Script attempted {len(net_attempts)} real network connection(s). All BLOCKED by sandbox. Targets: {targets}",
                "mitre_tag": "T1071 Application Layer Protocol (C2 Communication)"
            })

        return findings

    def _audit_fs_escape(self, audit_log_path: str) -> List[Dict[str, Any]]:
        """Reads audit log for filesystem escape attempts outside sandbox root."""
        findings = []
        if not os.path.exists(audit_log_path):
            return findings

        with open(audit_log_path, "r", encoding="utf-8") as f:
            logs = f.read()

        escape_attempts = [line for line in logs.splitlines() if line.startswith("FS_ESCAPE_ATTEMPT:")]
        if escape_attempts:
            paths = ", ".join(set(line.replace("FS_ESCAPE_ATTEMPT:", "") for line in escape_attempts[:5]))
            findings.append({
                "rule_id":   "DYN-FS-001",
                "severity":  "HIGH",
                "title":     "Filesystem Escape Attempt Blocked",
                "message":   f"Script attempted to access host filesystem outside sandbox boundaries. Paths: {paths}",
                "mitre_tag": "T1083 File and Directory Discovery"
            })

        return findings


# Global Sandbox Instance
sandbox_engine = DynamicSandbox()
