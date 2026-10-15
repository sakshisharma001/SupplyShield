import os
import sys
import subprocess
import glob

def main():
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    pattern = os.path.join(backend_dir, "test_*.py")
    test_paths = sorted(glob.glob(pattern))
    test_files = [os.path.basename(p) for p in test_paths]
    print(f"Found {len(test_files)} test suites in {backend_dir}:\n{test_files}\n")
    
    failed = []
    passed = []
    
    for tf in test_files:
        print(f"--- Running {tf} ---")
        if tf == "test_risk_engine.py":
            cmd = [sys.executable, tf]
        else:
            cmd = [sys.executable, "-m", "pytest", tf, "-v", "-p", "no:capture"]
            
        res = subprocess.run(cmd, cwd=backend_dir)
        if res.returncode == 0:
            passed.append(tf)
        else:
            failed.append(tf)
        print()

    print("=" * 60)
    print(f"TEST RESULTS: {len(passed)} PASSED, {len(failed)} FAILED out of {len(test_files)} suites")
    if failed:
        print(f"FAILED SUITES: {failed}")
        sys.exit(1)
    else:
        print(f"ALL {len(passed)} TEST SUITES PASSED SUCCESSFULLY (100% PASS RATE)!")

if __name__ == "__main__":
    main()

