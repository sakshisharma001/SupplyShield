"""
SupplyShield - Canary & Dynamic Monitoring Verification Suite (Phase 1 & 2)
Tests canary tripwires across multiple I/O channels:
1. builtins.open()
2. io.open()
3. os.open()
4. subprocess command execution
5. Process watchdog timeout kill
6. Sleep-skipping harness mitigation
"""

import os
import sys
import pytest

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from engine.sandbox import DynamicSandbox

def test_canary_detection_via_builtins_open():
    sandbox = DynamicSandbox(timeout_seconds=5.0)
    code = """
import os
canary_path = os.path.expanduser("~/.ssh/id_rsa")
if os.path.exists(canary_path):
    with open(canary_path, "r") as f:
        data = f.read()
"""
    result = sandbox.detonate(code, "test_builtins_open")
    rule_ids = [f["rule_id"] for f in result["dynamic_findings"]]
    assert "DYN-CANARY-001" in rule_ids, "Should detect SSH key read via builtins.open"

def test_canary_detection_via_io_open():
    sandbox = DynamicSandbox(timeout_seconds=5.0)
    code = """
import os
import io
canary_path = os.path.expanduser("~/.env")
if os.path.exists(canary_path):
    with io.open(canary_path, "r", encoding="utf-8") as f:
        data = f.read()
"""
    result = sandbox.detonate(code, "test_io_open")
    rule_ids = [f["rule_id"] for f in result["dynamic_findings"]]
    assert "DYN-CANARY-002" in rule_ids, "Should detect .env read via io.open"

def test_canary_detection_via_os_open():
    sandbox = DynamicSandbox(timeout_seconds=5.0)
    code = """
import os
canary_path = os.path.expanduser("~/.aws/credentials")
if os.path.exists(canary_path):
    fd = os.open(canary_path, os.O_RDONLY)
    data = os.read(fd, 256)
    os.close(fd)
"""
    result = sandbox.detonate(code, "test_os_open")
    rule_ids = [f["rule_id"] for f in result["dynamic_findings"]]
    assert "DYN-CANARY-003" in rule_ids, "Should detect AWS credentials read via os.open"

def test_subprocess_hook_detection():
    sandbox = DynamicSandbox(timeout_seconds=5.0)
    code = """
import subprocess
try:
    subprocess.Popen(["python", "--version"])
except Exception:
    pass
"""
    result = sandbox.detonate(code, "test_subprocess")
    rule_ids = [f["rule_id"] for f in result["dynamic_findings"]]
    assert "DYN-SUBP-001" in rule_ids, "Should intercept subprocess execution via sys.addaudithook"

def test_sleep_skipping_mitigation():
    sandbox = DynamicSandbox(timeout_seconds=4.0)
    # A 20-second sleep that would normally exceed a 4s watchdog timeout
    code = """
import time
start = time.time()
time.sleep(20.0)
elapsed = time.time() - start
print(f"Elapsed: {elapsed:.2f}")
"""
    result = sandbox.detonate(code, "test_sleep_skipping")
    rule_ids = [f["rule_id"] for f in result["dynamic_findings"]]
    assert result["status"] == "COMPLETED", "Sleep-skipping should allow script to complete without timeout"
    assert "DYN-SLEEP-001" in rule_ids, "Should log DYN-SLEEP-001 time-based evasion finding"
    # Execution should take well under 2 seconds despite sleep(20.0)
    assert result["execution_duration_sec"] < 3.0

def test_timeout_watchdog_kills_process():
    sandbox = DynamicSandbox(timeout_seconds=2.0)
    # Busy-loop that cannot be sleep-skipped
    code = """
import time
target = time.time() + 10.0
while time.time() < target:
    pass
"""
    result = sandbox.detonate(code, "test_busy_timeout")
    assert result["status"] == "TIMEOUT_KILLED"
    rule_ids = [f["rule_id"] for f in result["dynamic_findings"]]
    assert "DYN-TIME-001" in rule_ids
    # Verify MITRE mapping is T1497.003 and NOT T1499
    timeout_finding = next(f for f in result["dynamic_findings"] if f["rule_id"] == "DYN-TIME-001")
    assert "T1497.003" in timeout_finding["mitre_tag"]
    assert "T1499" not in timeout_finding["mitre_tag"]
