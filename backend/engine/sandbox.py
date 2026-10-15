"""
SupplyShield - Dynamic Detonation Sandbox Engine
Supports two execution modes:
1. Containerized Isolation (Primary): Docker container with --network none, --read-only,
   drop-capabilities, non-root user, memory/cpu bounds, and container cleanup.
2. WEAK MODE (Fallback): Ephemeral host subprocess execution with sys.addaudithook,
   io.open/os.open/builtins.open hooks, network blocking, and process tree watchdog.
   Enabled only if SUPPLYSHIELD_ALLOW_WEAK_SANDBOX=true.
"""

import os
import sys
import time
import shutil
import tempfile
import subprocess
import signal
import uuid
from typing import Dict, List, Any, Optional, Tuple

from config import settings

CANARY_SSH_PAYLOAD = "CANARY_TRIPWIRE_SSH_KEY_TRIGGERED_SUPPLYSHIELD_0xDEADBEEF"
CANARY_ENV_PAYLOAD = "AWS_SECRET_ACCESS_KEY=CANARY_KEY_TRIGGERED_0xFEEDFACE\nDATABASE_URL=postgres://canary:trap@localhost/secret"

# ─────────────────────────────────────────────────────────────────────────────
# AUDIT HOOK + NETWORK BLOCKER + MULTI-API CANARY TRAP injected into
# sandbox process via sitecustomize.py (auto-loaded by Python on startup)
# ─────────────────────────────────────────────────────────────────────────────
AUDIT_HOOK_CODE = """\
import builtins
import io
import os
import sys

_audit_log = os.environ.get("SUPPLYSHIELD_AUDIT_LOG", "")
_sandbox_root = os.environ.get("SUPPLYSHIELD_SANDBOX_ROOT", "")
_enable_sleep_skipping = os.environ.get("SUPPLYSHIELD_ENABLE_SLEEP_SKIPPING", "1") == "1"

_real_b_open = builtins.open
_real_io_open = io.open
_real_os_open = os.open

SENSITIVE_KEYS = [
    ".ssh", "id_rsa", "id_ed25519", ".env", ".aws",
    "shadow", "passwd", "credentials", ".config/gcloud"
]

def _log_audit(msg):
    if _audit_log:
        try:
            with _real_b_open(_audit_log, "a", encoding="utf-8") as lf:
                lf.write(msg + "\\n")
        except Exception:
            pass

# ── 1. C-LEVEL RUNTIME AUDIT HOOK (PEP 578) ──────────────────────────────────
def _audit_callback(event, args):
    try:
        if event == "open":
            path_str = str(args[0]) if args else ""
            if any(k in path_str.lower() for k in SENSITIVE_KEYS):
                _log_audit(f"FILE_ACCESS:{path_str}")
        elif event == "socket.connect":
            addr = str(args[1]) if len(args) > 1 else (str(args[0]) if args else "unknown")
            _log_audit(f"NETWORK_ATTEMPT:{addr}")
        elif event == "subprocess.Popen":
            cmd = str(args[1]) if len(args) > 1 else (str(args[0]) if args else "")
            _log_audit(f"SUBPROCESS_ATTEMPT:{cmd}")
        elif event == "os.system":
            cmd = str(args[0]) if args else ""
            _log_audit(f"OS_SYSTEM_ATTEMPT:{cmd}")
        elif event == "exec":
            _log_audit("DYNAMIC_EXEC_ATTEMPT")
        elif event == "compile":
            _log_audit("COMPILE_ATTEMPT")
    except Exception:
        pass

try:
    sys.addaudithook(_audit_callback)
except Exception:
    pass

# ── 2. MULTI-LEVEL FILE OPEN HOOKS ───────────────────────────────────────────
def _check_sensitive_access(file_obj):
    file_str = str(file_obj)
    if any(k in file_str.lower() for k in SENSITIVE_KEYS):
        _log_audit(f"FILE_ACCESS:{file_str}")
    if _sandbox_root:
        try:
            real_path = os.path.realpath(file_str)
            real_root = os.path.realpath(_sandbox_root)
            if not real_path.startswith(real_root):
                _log_audit(f"FS_ESCAPE_ATTEMPT:{file_str}")
        except (ValueError, OSError):
            pass

def _hooked_b_open(file, *args, **kwargs):
    _check_sensitive_access(file)
    return _real_b_open(file, *args, **kwargs)

def _hooked_io_open(file, *args, **kwargs):
    _check_sensitive_access(file)
    return _real_io_open(file, *args, **kwargs)

def _hooked_os_open(path, *args, **kwargs):
    _check_sensitive_access(path)
    return _real_os_open(path, *args, **kwargs)

builtins.open = _hooked_b_open
io.open = _hooked_io_open
os.open = _hooked_os_open

# ── 3. OPTIONAL SLEEP-SKIPPING MITIGATION ────────────────────────────────────
if _enable_sleep_skipping:
    import time as _time_mod
    _real_sleep = _time_mod.sleep
    def _fast_sleep(secs):
        try:
            s_val = float(secs)
            if s_val >= 2.0:
                _log_audit(f"SLEEP_ATTEMPT:{s_val}")
            # Bound real delay to 0.05s so cooperative yields work without timeout stalls
            _real_sleep(min(s_val, 0.05))
        except Exception:
            _real_sleep(0.05)
    _time_mod.sleep = _fast_sleep

# ── 4. REAL NETWORK SOCKET BLOCKING ──────────────────────────────────────────
import socket as _socket_module

def _blocked_connect(self, address, *args, **kwargs):
    host = address[0] if isinstance(address, (tuple, list)) else str(address)
    _log_audit(f"NETWORK_ATTEMPT:{host}")
    raise ConnectionRefusedError(f"[SupplyShield] Outbound network connection BLOCKED: {address}")

def _blocked_connect_ex(self, address, *args, **kwargs):
    host = address[0] if isinstance(address, (tuple, list)) else str(address)
    _log_audit(f"NETWORK_ATTEMPT:{host}")
    return 111  # ECONNREFUSED

def _blocked_create_connection(address, *args, **kwargs):
    host = address[0] if isinstance(address, (tuple, list)) else str(address)
    _log_audit(f"NETWORK_ATTEMPT:{host}")
    raise ConnectionRefusedError(f"[SupplyShield] Outbound connection BLOCKED: {address}")

_socket_module.socket.connect    = _blocked_connect
_socket_module.socket.connect_ex = _blocked_connect_ex
_socket_module.create_connection = _blocked_create_connection

import urllib.request as _urllib_req
def _blocked_urlopen(url, *args, **kwargs):
    _log_audit(f"NETWORK_ATTEMPT:urllib:{url}")
    raise ConnectionRefusedError(f"[SupplyShield] urllib request BLOCKED: {url}")
_urllib_req.urlopen = _blocked_urlopen
"""


def check_docker_available() -> bool:
    """Checks whether the docker CLI binary is present and the daemon is reachable."""
    try:
        res = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3
        )
        return res.returncode == 0
    except (FileNotFoundError, subprocess.SubprocessError, Exception):
        return False


class DynamicSandbox:
    """
    Executes untrusted packages in a controlled environment.
    Uses Docker container isolation when available; falls back to host-level
    weak mode with Python audit hooks when Docker is absent.
    """

    def __init__(self, timeout_seconds: float = settings.SANDBOX_TIMEOUT_SECONDS):
        self.timeout_seconds = timeout_seconds
        self.docker_available = check_docker_available()

    def detonate(self, source_code: str, package_name: str = "untrusted_sample") -> Dict[str, Any]:
        """
        Orchestrates detonation. Automatically chooses Docker isolation if available,
        or WEAK MODE if allowed by configuration.
        """
        if self.docker_available:
            return self._detonate_docker(source_code, package_name)
        else:
            if not settings.ALLOW_WEAK_SANDBOX:
                raise RuntimeError(
                    "Docker daemon is unavailable and SUPPLYSHIELD_ALLOW_WEAK_SANDBOX=false. "
                    "Refusing to execute untrusted code without container isolation."
                )
            return self._detonate_weak_host(source_code, package_name)

    # ─────────────────────────────────────────────────────────────────────────
    # DOCKER CONTAINER ISOLATION
    # ─────────────────────────────────────────────────────────────────────────
    def _detonate_docker(self, source_code: str, package_name: str) -> Dict[str, Any]:
        start_time = time.time()
        container_name = f"supplyshield-sbx-{uuid.uuid4().hex[:12]}"
        temp_dir = tempfile.mkdtemp(prefix="ss_docker_")
        dynamic_findings: List[Dict[str, Any]] = []
        status = "COMPLETED"
        stdout_output = ""
        stderr_output = ""
        exit_code: Optional[int] = None

        try:
            # Write payload to host temp directory to mount read-only
            payload_path = os.path.join(temp_dir, "payload.py")
            with open(payload_path, "w", encoding="utf-8") as f:
                f.write(source_code)

            # Security-hardened Docker invocation flags
            docker_cmd = [
                "docker", "run",
                "--name", container_name,
                "--network", "none",
                "--read-only",
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "--pids-limit", "50",
                "--memory", f"{settings.MAX_MEMORY_MB}m",
                "--cpus", "0.5",
                "--user", "1000:1000",
                "-v", f"{payload_path}:/app/payload.py:ro",
                settings.DOCKER_IMAGE,
                "python", "-u", "/app/payload.py"
            ]

            process = subprocess.Popen(
                docker_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace"
            )

            try:
                stdout_output, stderr_output = process.communicate(timeout=self.timeout_seconds)
                exit_code = process.returncode
            except subprocess.TimeoutExpired:
                status = "TIMEOUT_KILLED"
                exit_code = -9
                # Force kill container by name
                subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
                stdout_output, stderr_output = process.communicate()
                dynamic_findings.append({
                    "rule_id": "DYN-TIME-001",
                    "severity": "CRITICAL",
                    "title": f"Container Watchdog Hard-Kill (Timeout: {self.timeout_seconds}s)",
                    "message": f"Container execution exceeded {self.timeout_seconds}s threshold. Container killed.",
                    "mitre_tag": "T1497.003 Virtualization/Sandbox Evasion: Time Based Evasion",
                    "mitre_justification": "Malware delayed execution beyond sandbox analysis window to evade detection."
                })

            if exit_code != 0 and status != "TIMEOUT_KILLED":
                # Inspect stderr for network / permission denials
                if "PermissionError" in stderr_output or "Read-only file system" in stderr_output:
                    dynamic_findings.append({
                        "rule_id": "DYN-DOCKER-FS",
                        "severity": "HIGH",
                        "title": "Container Read-Only Filesystem Escape Blocked",
                        "message": "Attempted to write outside designated temporary storage in read-only container.",
                        "mitre_tag": "T1083 File and Directory Discovery",
                        "mitre_justification": "Detected attempts to tamper with read-only rootfs."
                    })

        except Exception as e:
            status = "EXECUTION_ERROR"
            stderr_output += f"\nDocker Detonation Exception: {str(e)}"
        finally:
            # Clean up container and host temp dir
            subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
            shutil.rmtree(temp_dir, ignore_errors=True)

        return self._build_result(
            package_name=package_name,
            status=status,
            start_time=start_time,
            exit_code=exit_code,
            stdout=stdout_output,
            stderr=stderr_output,
            findings=dynamic_findings,
            isolation_mode="DOCKER_CONTAINER"
        )

    # ─────────────────────────────────────────────────────────────────────────
    # WEAK MODE (HOST SUBPROCESS FALLBACK)
    # ─────────────────────────────────────────────────────────────────────────
    def _detonate_weak_host(self, source_code: str, package_name: str) -> Dict[str, Any]:
        start_time = time.time()
        temp_dir = tempfile.mkdtemp(prefix=settings.TEMP_DIR_PREFIX)
        dynamic_findings: List[Dict[str, Any]] = []
        status = "COMPLETED"
        stdout_output = ""
        stderr_output = ""
        exit_code: Optional[int] = None
        audit_log_path = os.path.join(temp_dir, "audit_events.log")

        # Explicit Weak Mode finding so the user/examiner knows isolation is degraded
        dynamic_findings.append({
            "rule_id": "SANDBOX-MODE-WEAK",
            "severity": "LOW",
            "title": "WEAK MODE Sandbox Active (No OS Isolation)",
            "message": "Detonation ran on host process without Docker isolation. Protection relies on Python audit hooks.",
            "mitre_tag": "T1497 Virtualization/Sandbox Evasion",
            "mitre_justification": "Host-level execution lacks kernel isolation (cgroups, namespaces, capabilities)."
        })

        try:
            canary_ssh_path, canary_env_path = self._plant_canaries(temp_dir)

            # Inject hardened sitecustomize.py
            hook_path = os.path.join(temp_dir, "sitecustomize.py")
            with open(hook_path, "w", encoding="utf-8") as f:
                f.write(AUDIT_HOOK_CODE)

            script_path = os.path.join(temp_dir, "payload_runner.py")
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(source_code)

            env = os.environ.copy()
            env["HOME"] = temp_dir
            env["USERPROFILE"] = temp_dir
            env["PYTHONPATH"] = temp_dir
            env["PYTHONUNBUFFERED"] = "1"
            env["SUPPLYSHIELD_AUDIT_LOG"] = audit_log_path
            env["SUPPLYSHIELD_SANDBOX_ROOT"] = temp_dir
            env["SUPPLYSHIELD_ENABLE_SLEEP_SKIPPING"] = "1" if settings.ENABLE_SLEEP_SKIPPING else "0"

            # Strip host credential keys
            for secret_key in [
                "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID",
                "GITHUB_TOKEN", "DATABASE_URL", "SECRET_KEY",
                "OPENAI_API_KEY", "ANTHROPIC_API_KEY"
            ]:
                env.pop(secret_key, None)

            # Subprocess launch
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
                stdout_output, stderr_output = process.communicate(timeout=self.timeout_seconds)
                exit_code = process.returncode
            except subprocess.TimeoutExpired:
                # Terminate entire process tree (avoiding orphaned background miners)
                self._terminate_process_tree(process.pid)
                stdout_output, stderr_output = process.communicate()
                status = "TIMEOUT_KILLED"
                exit_code = -9
                dynamic_findings.append({
                    "rule_id": "DYN-TIME-001",
                    "severity": "CRITICAL",
                    "title": f"Process Watchdog Hard-Kill (Timeout: {self.timeout_seconds}s)",
                    "message": f"Script execution exceeded threshold of {self.timeout_seconds}s. Process tree terminated.",
                    "mitre_tag": "T1497.003 Virtualization/Sandbox Evasion: Time Based Evasion",
                    "mitre_justification": "Malware stalled execution or entered infinite wait loop to outlast sandbox analysis."
                })

            # Audit findings from log file
            dynamic_findings.extend(self._parse_audit_log(audit_log_path, canary_ssh_path))

            # Stderr fallback checks
            if stderr_output and not any(f["rule_id"] == "DYN-NET-002" for f in dynamic_findings):
                lower_err = stderr_output.lower()
                if any(e in lower_err for e in ["connectionrefusederror", "socket.error", "winerror 10061"]):
                    dynamic_findings.append({
                        "rule_id": "DYN-NET-002",
                        "severity": "HIGH",
                        "title": "Outbound Socket Connection Attempt Detected via stderr",
                        "message": "Subprocess triggered socket network errors during execution.",
                        "mitre_tag": "T1071 Application Layer Protocol",
                        "mitre_justification": "Observed socket connection failure in process error stream."
                    })

        except Exception as e:
            status = "EXECUTION_ERROR"
            stderr_output += f"\nSandbox Execution Exception: {str(e)}"
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

        return self._build_result(
            package_name=package_name,
            status=status,
            start_time=start_time,
            exit_code=exit_code,
            stdout=stdout_output,
            stderr=stderr_output,
            findings=dynamic_findings,
            isolation_mode="WEAK_HOST_SUBPROCESS"
        )

    # ─────────────────────────────────────────────────────────────────────────
    # HELPERS & AUDIT PARSING
    # ─────────────────────────────────────────────────────────────────────────
    def _terminate_process_tree(self, pid: int):
        """Terminates process and all descendant child processes."""
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True)
        else:
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except Exception:
                try:
                    os.kill(pid, signal.SIGKILL)
                except Exception:
                    pass

    def _plant_canaries(self, sandbox_dir: str) -> Tuple[str, str]:
        ssh_dir = os.path.join(sandbox_dir, ".ssh")
        os.makedirs(ssh_dir, exist_ok=True)
        canary_ssh = os.path.join(ssh_dir, "id_rsa")
        with open(canary_ssh, "w", encoding="utf-8") as f:
            f.write(CANARY_SSH_PAYLOAD)

        aws_dir = os.path.join(sandbox_dir, ".aws")
        os.makedirs(aws_dir, exist_ok=True)
        canary_aws = os.path.join(aws_dir, "credentials")
        with open(canary_aws, "w", encoding="utf-8") as f:
            f.write("[default]\naws_access_key_id = AKIA_CANARY_TRAP\naws_secret_access_key = CANARY_TRAP_SECRET\n")

        canary_env = os.path.join(sandbox_dir, ".env")
        with open(canary_env, "w", encoding="utf-8") as f:
            f.write(CANARY_ENV_PAYLOAD)

        return canary_ssh, canary_env

    def _parse_audit_log(self, audit_log_path: str, canary_ssh_path: str) -> List[Dict[str, Any]]:
        findings = []
        if not os.path.exists(audit_log_path):
            return findings

        with open(audit_log_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [l.strip() for l in f if l.strip()]

        file_accesses = [l.replace("FILE_ACCESS:", "") for l in lines if l.startswith("FILE_ACCESS:")]
        net_attempts = [l.replace("NETWORK_ATTEMPT:", "") for l in lines if l.startswith("NETWORK_ATTEMPT:")]
        sleep_attempts = [l.replace("SLEEP_ATTEMPT:", "") for l in lines if l.startswith("SLEEP_ATTEMPT:")]
        subp_attempts = [l.replace("SUBPROCESS_ATTEMPT:", "") for l in lines if l.startswith("SUBPROCESS_ATTEMPT:")]

        # 1. Canary files targeted
        for path in file_accesses:
            lower = path.lower()
            if ".ssh" in lower or "id_rsa" in lower:
                findings.append({
                    "rule_id": "DYN-CANARY-001",
                    "severity": "CRITICAL",
                    "title": "Unauthorized SSH Private Key Access Intercepted",
                    "message": f"Script accessed SSH private key canary path: '{path}'.",
                    "mitre_tag": "T1552.004 Credentials in Files: Private Keys",
                    "mitre_justification": "Targeted private keys used for authentication and lateral movement."
                })
            elif ".env" in lower:
                findings.append({
                    "rule_id": "DYN-CANARY-002",
                    "severity": "HIGH",
                    "title": "Environment File (.env) Access Intercepted",
                    "message": f"Script accessed environment secrets file: '{path}'.",
                    "mitre_tag": "T1552 Credentials in Files",
                    "mitre_justification": "Attempted to discover application secrets stored in local .env files."
                })
            elif ".aws" in lower or "credentials" in lower:
                findings.append({
                    "rule_id": "DYN-CANARY-003",
                    "severity": "CRITICAL",
                    "title": "AWS Credentials File Access Intercepted",
                    "message": f"Script targeted cloud credentials path: '{path}'.",
                    "mitre_tag": "T1552.001 Credentials in Files: Local Credentials",
                    "mitre_justification": "Attempted to harvest cloud provider access tokens."
                })

        # Physical deletion of canary
        if not os.path.exists(canary_ssh_path):
            findings.append({
                "rule_id": "DYN-CANARY-004",
                "severity": "CRITICAL",
                "title": "SSH Private Key Deleted / Tampered",
                "message": "Canary private key file was deleted or moved during execution.",
                "mitre_tag": "T1552.004 Credentials in Files: Private Keys",
                "mitre_justification": "Attempted anti-forensic deletion of targeted credential artifact."
            })

        # 2. Network connection attempts
        if net_attempts:
            unique_targets = list(set(net_attempts))[:5]
            findings.append({
                "rule_id": "DYN-NET-002",
                "severity": "CRITICAL",
                "title": "REAL Outbound Network Connection Blocked",
                "message": f"Blocked {len(net_attempts)} outbound network connection attempt(s). Targets: {', '.join(unique_targets)}",
                "mitre_tag": "T1071 Application Layer Protocol",
                "mitre_justification": "Outbound network connection to command-and-control server or data exfiltration sink."
            })

        # 3. Sleep skipping detection
        if sleep_attempts:
            max_sleep = max([float(s) for s in sleep_attempts if s.replace('.', '', 1).isdigit()] or [0])
            findings.append({
                "rule_id": "DYN-SLEEP-001",
                "severity": "MEDIUM",
                "title": f"Logic Bomb Sleep Delay Evaded ({max_sleep}s)",
                "message": f"Script requested sleep of {max_sleep}s. Intercepted by sleep-skipping harness.",
                "mitre_tag": "T1497.003 Virtualization/Sandbox Evasion: Time Based Evasion",
                "mitre_justification": "Long sleep calls indicate deliberate evasion of time-limited sandboxes."
            })

        # 4. Subprocess execution
        if subp_attempts:
            findings.append({
                "rule_id": "DYN-SUBP-001",
                "severity": "HIGH",
                "title": "Subprocess Execution Intercepted by Audit Hook",
                "message": f"Attempted to spawn subprocess: {subp_attempts[0][:80]}",
                "mitre_tag": "T1059 Command Execution",
                "mitre_justification": "Spawning system shell commands during dependency installation."
            })

        # Deduplicate findings by rule_id
        unique_findings = []
        seen_rules = set()
        for f in findings:
            if f["rule_id"] not in seen_rules:
                seen_rules.add(f["rule_id"])
                unique_findings.append(f)

        return unique_findings

    def _build_result(
        self,
        package_name: str,
        status: str,
        start_time: float,
        exit_code: Optional[int],
        stdout: str,
        stderr: str,
        findings: List[Dict[str, Any]],
        isolation_mode: str
    ) -> Dict[str, Any]:
        execution_duration = round(time.time() - start_time, 4)

        # Dynamic risk score calculation based on observed severity
        dynamic_risk_score = 0
        for f in findings:
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
            "stdout": stdout.strip(),
            "stderr": stderr.strip(),
            "dynamic_findings": findings,
            "dynamic_risk_score": min(dynamic_risk_score, 100),
            "isolation_mode": isolation_mode
        }


# Global shared instance
sandbox_engine = DynamicSandbox()
