"""
SupplyShield - AST Engine Test Suite
Runs the AST Static Engine against benign, obfuscated, and credential-stealer samples to verify detection accuracy.
"""
import sys
import io
from engine.ast_analyzer import analyze_source_ast

# Force UTF-8 stdout if needed
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

def test_samples():
    samples = [
        ("Safe Math Package", "samples/safe_math_pkg.py"),
        ("Obfuscated Backdoor", "samples/obfuscated_backdoor.py"),
        ("Credential Stealer", "samples/credential_stealer.py"),
    ]
    
    print("=" * 70)
    print(" [SUPPLYSHIELD] AST STATIC ENGINE - VERIFICATION SUITE")
    print("=" * 70)
    
    for label, filepath in samples:
        with open(filepath, "r", encoding="utf-8") as f:
            code = f.read()
            
        result = analyze_source_ast(code)
        
        print(f"\n[+] Testing Sample: {label} ({filepath})")
        print(f"    - Total Lines: {result['metrics']['total_lines']}")
        print(f"    - AST Node Count: {result['metrics']['ast_nodes_count']}")
        print(f"    - Risk Score: {result['static_risk_score']} / 100")
        print(f"    - Total Findings: {len(result['findings'])}")
        
        for idx, finding in enumerate(result['findings'], 1):
            print(f"      [{idx}] [{finding['severity']}] Line {finding['line']}: {finding['title']}")
            print(f"          -> MITRE Tag: {finding['mitre_tag']}")
            print(f"          -> Snippet: {finding['snippet']}")

    print("\n" + "=" * 70)
    print(" [*] ALL SAMPLES PROCESSED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == "__main__":
    test_samples()
