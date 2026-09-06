"""
SupplyShield - Dynamic Sandbox Test Suite
Detonates benign, credential-stealing, and hanging backdoor scripts inside the isolated sandbox to test watchdog termination and canary detection.
"""
import os
import sys
import io
from engine.sandbox import sandbox_engine

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def test_dynamic_sandbox():
    print("=" * 70)
    print(" [SUPPLYSHIELD] DYNAMIC DETONATION SANDBOX - TEST SUITE")
    print("=" * 70)

    # Test 1: Safe Math Package
    with open(os.path.join(BASE_DIR, "samples", "safe_math_pkg.py"), "r", encoding="utf-8") as f:
        safe_code = f.read()
    
    print("\n[+] Detonating Sample 1: Safe Math Package...")
    res_safe = sandbox_engine.detonate(safe_code, "safe_math_pkg")
    print(f"    - Status: {res_safe['status']}")
    print(f"    - Execution Time: {res_safe['execution_duration_sec']}s")
    print(f"    - Stdout: {res_safe['stdout']}")
    print(f"    - Dynamic Risk Score: {res_safe['dynamic_risk_score']} / 100")
    print(f"    - Findings: {len(res_safe['dynamic_findings'])}")

    # Test 2: Credential Stealer (Hits .ssh & .env and tries network socket)
    with open(os.path.join(BASE_DIR, "samples", "credential_stealer.py"), "r", encoding="utf-8") as f:
        stealer_code = f.read() + "\nexfiltrate_credentials()"

    print("\n[+] Detonating Sample 2: Credential Stealer Backdoor...")
    res_stealer = sandbox_engine.detonate(stealer_code, "credential_stealer")
    print(f"    - Status: {res_stealer['status']}")
    print(f"    - Execution Time: {res_stealer['execution_duration_sec']}s")
    print(f"    - Stdout: {res_stealer['stdout']}")
    print(f"    - Dynamic Risk Score: {res_stealer['dynamic_risk_score']} / 100")
    print(f"    - Findings: {len(res_stealer['dynamic_findings'])}")
    for finding in res_stealer['dynamic_findings']:
        print(f"      -> [{finding['severity']}] {finding['title']}")
        print(f"         MITRE: {finding['mitre_tag']}")

    # Test 3: Hanging Reverse Shell (Tests 3.0s Hard Watchdog Termination)
    hanging_code = """
import time
print('[MaliciousPayload] Attempting persistent reverse shell connection to 194.26.29.112:4444...')
while True:
    time.sleep(1)
"""
    print("\n[+] Detonating Sample 3: Hanging Reverse-Shell (Watchdog Timeout Test)...")
    res_hanging = sandbox_engine.detonate(hanging_code, "hanging_shell_backdoor")
    print(f"    - Status: {res_hanging['status']}")
    print(f"    - Execution Time: {res_hanging['execution_duration_sec']}s")
    print(f"    - Stdout: {res_hanging['stdout']}")
    print(f"    - Dynamic Risk Score: {res_hanging['dynamic_risk_score']} / 100")
    print(f"    - Findings: {len(res_hanging['dynamic_findings'])}")
    for finding in res_hanging['dynamic_findings']:
        print(f"      -> [{finding['severity']}] {finding['title']}")
        print(f"         MITRE: {finding['mitre_tag']}")

    print("\n" + "=" * 70)
    print(" [*] ALL DYNAMIC SANDBOX TESTS COMPLETED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == "__main__":
    test_dynamic_sandbox()
