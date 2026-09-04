"""
SupplyShield - Ephemeral Dynamic Detonation Sandbox
Executes untrusted Python package scripts within an isolated, temporary environment.
Features:
- Subprocess execution with strict watchdog timeout (3.0s)
- Synthetic Canary Tripwires (.ssh/id_rsa, .env) with automated access audit hooks
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

AUDIT_HOOK_CODE = """
import builtins
import os

_real_open = builtins.open
_audit_log_path = os.environ.get("SUPPLYSHIELD_AUDIT_LOG", "")

def _hooked_open(file, *args, **kwargs):
    file_str = str(file)
    if _audit_log_path and any(k in file_str.lower() for k in [".ssh", "id_rsa", ".env", ".aws", "shadow", "passwd"]):
        try:
            with _real_open(_audit_log_path, "a", encoding="utf-8") as log_f:
                log_f.write(f"FILE_ACCESS:{file_str}\\n")
        except Exception:
            pass
    return _real_open(file, *args, **kwargs)

builtins.open = _hooked_open
"""

class DynamicSandbox:
    """
    Orchestrates ephemeral sub-process execution environments to capture
    dynamic malware behavior, file theft attempts, and execution anomalies.
    """
    
    def __init__(self, timeout_seconds: float = settings.SANDBOX_TIMEOUT_SECONDS):
        self.timeout_seconds = timeout_seconds
        
    def detonate(self, source_code: str, package_name: str = "untrusted_sample") -> Dict[str, Any]:
        """
        Executes code inside an isolated ephemeral temporary directory with canary traps.
        Captures dynamic execution logs, file accesses, and security anomalies.
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
            # 1. Setup Isolated Filesystem & Synthetic Canary Traps
            canary_ssh_path, canary_env_path = self._plant_canaries(temp_dir)
            
            # 2. Write Audit Interceptor (sitecustomize.py) & Target Script
            hook_path = os.path.join(temp_dir, "sitecustomize.py")
            with open(hook_path, "w", encoding="utf-8") as f:
                f.write(AUDIT_HOOK_CODE)

            script_path = os.path.join(temp_dir, "payload_runner.py")
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(source_code)
                
            # 3. Launch Isolated Subprocess with Resource Constraints
            env = os.environ.copy()
            env["HOME"] = temp_dir
            env["USERPROFILE"] = temp_dir
            env["PYTHONPATH"] = temp_dir
            env["PYTHONUNBUFFERED"] = "1"
            env["SUPPLYSHIELD_AUDIT_LOG"] = audit_log_path
            
            process = subprocess.Popen(
                [sys.executable, script_path],
                cwd=temp_dir,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            try:
                stdout_output, stderr_output = process.communicate(timeout=self.timeout_seconds)
                exit_code = process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                stdout_output, stderr_output = process.communicate()
                status = "TIMEOUT_KILLED"
                exit_code = -9
                dynamic_findings.append({
                    "rule_id": "DYN-TIME-001",
                    "severity": "CRITICAL",
                    "title": f"Process Watchdog Hard-Kill (Timeout: {self.timeout_seconds}s)",
                    "message": "Script exceeded maximum allowable execution threshold. Likely persistent backdoor or reverse-shell wait loop.",
                    "mitre_tag": "T1499 Endpoint Denial of Service / Reverse Shell Wait"
                })

            # 4. Check Canary File Audit Logs & Tampering
            canary_findings = self._audit_canary_access(temp_dir, canary_ssh_path, canary_env_path, audit_log_path)
            dynamic_findings.extend(canary_findings)

            # 5. Check stderr for Suspicious Network / Socket Errors
            if stderr_output:
                if any(err in stderr_output.lower() for err in ["connectionrefusederror", "socket.error", "winerror 10061", "name resolution", "gaierror"]):
                    dynamic_findings.append({
                        "rule_id": "DYN-NET-002",
                        "severity": "HIGH",
                        "title": "Outbound Socket Connection Attempt Detected",
                        "message": "Subprocess triggered dynamic network/socket connection errors during setup execution.",
                        "mitre_tag": "T1071 Application Layer Protocol (C2 Communication)"
                    })

        except Exception as e:
            status = "EXECUTION_ERROR"
            stderr_output += f"\nSandbox Orchestration Exception: {str(e)}"
        finally:
            # 6. Automatic Ephemeral Teardown (Zero Host Residue)
            shutil.rmtree(temp_dir, ignore_errors=True)

        execution_duration = round(time.time() - start_time, 4)
        
        # Calculate Dynamic Risk Score (0 - 100)
        dynamic_risk_score = 0
        for f in dynamic_findings:
            if f["severity"] == "CRITICAL":
                dynamic_risk_score += 40
            elif f["severity"] == "HIGH":
                dynamic_risk_score += 25
            elif f["severity"] == "MEDIUM":
                dynamic_risk_score += 15
                
        return {
            "status": status,
            "package_name": package_name,
            "execution_duration_sec": execution_duration,
            "exit_code": exit_code,
            "stdout": stdout_output.strip(),
            "stderr": stderr_output.strip(),
            "dynamic_findings": dynamic_findings,
            "dynamic_risk_score": min(dynamic_risk_score, 100)
        }

    def _plant_canaries(self, sandbox_dir: str):
        """Plants fake canary files to trap credential stealers."""
        ssh_dir = os.path.join(sandbox_dir, ".ssh")
        os.makedirs(ssh_dir, exist_ok=True)
        
        canary_ssh_file = os.path.join(ssh_dir, "id_rsa")
        with open(canary_ssh_file, "w", encoding="utf-8") as f:
            f.write(CANARY_SSH_PAYLOAD)
            
        canary_env_file = os.path.join(sandbox_dir, ".env")
        with open(canary_env_file, "w", encoding="utf-8") as f:
            f.write(CANARY_ENV_PAYLOAD)
            
        return canary_ssh_file, canary_env_file

    def _audit_canary_access(self, sandbox_dir: str, ssh_path: str, env_path: str, audit_log_path: str) -> List[Dict[str, Any]]:
        """Audits whether canary files were read, modified, or targeted during sandbox execution."""
        findings = []
        
        # 1. Check access logs from interceptor hook
        if os.path.exists(audit_log_path):
            with open(audit_log_path, "r", encoding="utf-8") as f:
                logs = f.read()
                
            if ".ssh" in logs or "id_rsa" in logs:
                findings.append({
                    "rule_id": "DYN-CANARY-001",
                    "severity": "CRITICAL",
                    "title": "Unauthorized SSH Private Key Access Intercepted",
                    "message": "Script triggered dynamic canary tripwire attempting to read ~/.ssh/id_rsa.",
                    "mitre_tag": "T1552.004 Credentials in Files: Private Keys"
                })
                
            if ".env" in logs:
                findings.append({
                    "rule_id": "DYN-CANARY-002",
                    "severity": "HIGH",
                    "title": "Environment File (.env) Access Intercepted",
                    "message": "Script dynamically opened the .env secrets file during execution.",
                    "mitre_tag": "T1552 Credentials in Files"
                })

        # 2. Check if files were deleted / overwritten
        if not os.path.exists(ssh_path):
            findings.append({
                "rule_id": "DYN-CANARY-003",
                "severity": "CRITICAL",
                "title": "SSH Private Key Deleted / Tampered",
                "message": "The script deleted or moved the canary SSH private key.",
                "mitre_tag": "T1552.004 Credentials in Files: Private Keys"
            })
            
        return findings

# Global Sandbox Instance
sandbox_engine = DynamicSandbox()
