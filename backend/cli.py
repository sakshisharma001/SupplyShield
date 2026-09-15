"""
SupplyShield - DevSecOps Command Line Interface (CLI)
Allows security engineers and CI/CD pipelines (GitHub Actions, GitLab CI)
to scan Python files/directories, inspect threat scores, and block malicious builds.
"""

import os
import sys
import json
import argparse
import requests
from typing import Dict, Any

from engine.ast_analyzer import analyze_source_ast
from engine.sandbox import DynamicSandbox
from engine.risk_scorer import RiskScoringEngine
from engine.report_generator import generate_json_report, generate_html_report


def print_banner():
    """Prints ASCII banner for CLI execution."""
    banner = """
    ================================================================
      [SupplyShield DevSecOps Supply-Chain Security CLI]
      Autonomous AST Taint, Sandbox & Risk Scoring Engine
    ================================================================
    """
    print(banner)


def scan_file_local(file_path: str) -> Dict[str, Any]:
    """Runs local standalone 3-stage security scan on a target Python file."""
    if not os.path.exists(file_path):
        print(f"[FAIL] Error: Target file '{file_path}' does not exist.")
        sys.exit(2)

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        source_code = f.read()

    package_name = os.path.basename(file_path)

    # 1. AST Static Analysis
    ast_result = analyze_source_ast(source_code)

    # 2. Ephemeral Sandbox Detonation
    sandbox = DynamicSandbox()
    sandbox_result = sandbox.detonate(source_code=source_code, package_name=package_name)

    # 3. Composite Risk Assessment
    scorer = RiskScoringEngine()
    assessment = scorer.compute_assessment(
        package_name=package_name,
        ast_result=ast_result,
        sandbox_result=sandbox_result
    )

    return assessment


def scan_file_remote(file_path: str, server_url: str) -> Dict[str, Any]:
    """Scans target file via remote SupplyShield API gateway."""
    if not os.path.exists(file_path):
        print(f"[FAIL] Error: Target file '{file_path}' does not exist.")
        sys.exit(2)

    endpoint = f"{server_url.rstrip('/')}/api/scan/package"
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f, "text/plain")}
        try:
            res = requests.post(endpoint, files=files, timeout=30)
            if res.status_code == 200:
                data = res.json()
                return data.get("report", {})
            else:
                print(f"[FAIL] API scan failed with status {res.status_code}: {res.text}")
                sys.exit(2)
        except Exception as e:
            print(f"[WARN] Remote API server unavailable ({str(e)}). Falling back to local engine...")
            return scan_file_local(file_path)


def format_terminal_table(assessment: Dict[str, Any]) -> str:
    """Formats assessment results into a clean ASCII terminal summary table."""
    verdict = assessment.get("verdict", "UNKNOWN")
    score = assessment.get("composite_risk_score", 0)
    slsa = assessment.get("slsa_security_level", "SLSA-Level-0")
    pkg = assessment.get("package_name", "unknown")
    findings = assessment.get("findings") or (assessment.get("static_findings", []) + assessment.get("dynamic_findings", []))

    color_verdict = "\033[92m" if verdict == "CLEAN" else "\033[93m" if verdict == "SUSPICIOUS" else "\033[91m"
    reset = "\033[0m"

    output = []
    output.append("+-------------------------------------------------------------+")
    output.append(f"| Target Package: {pkg:<43} |")
    output.append(f"| Verdict:        {color_verdict}{verdict:<43}{reset} |")
    output.append(f"| Composite Risk: {score}/100{' ':<41} |")
    output.append(f"| SLSA Rating:    {slsa:<43} |")
    output.append(f"| Total Findings: {len(findings):<43} |")
    output.append("+-------------------------------------------------------------+")

    if findings:
        output.append("\n[FINDINGS] Detected Vulnerabilities & MITRE ATT&CK Mapping:")
        for idx, f in enumerate(findings, 1):
            sev = f.get("severity", "MEDIUM")
            rule = f.get("rule_id", "SEC-UNK")
            mitre = f.get("mitre_id", "N/A")
            desc = f.get("description", "")
            output.append(f"  [{idx}] [{sev}] [{rule}] MITRE: {mitre}")
            output.append(f"      |-- {desc}")

    return "\n".join(output)


def main():
    parser = argparse.ArgumentParser(
        description="SupplyShield CLI — Autonomous Supply-Chain Security Audit Tool"
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # Scan Sub-command
    scan_parser = subparsers.add_parser("scan", help="Scan a Python file or package")
    scan_parser.add_argument("target", help="Path to Python script or package file (.py)")
    scan_parser.add_argument(
        "--server", help="Remote SupplyShield API URL (e.g. http://127.0.0.1:8000)", default=None
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "SUSPICIOUS", "ANY"],
        default="CRITICAL",
        help="Exit with non-zero status (1) if verdict matches or exceeds threshold (for CI/CD blocking)"
    )
    scan_parser.add_argument(
        "--format",
        choices=["terminal", "json", "html"],
        default="terminal",
        help="Output format (terminal summary, raw json, or standalone html)"
    )
    scan_parser.add_argument(
        "--output", help="Save report to specified output file path", default=None
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        if args.format == "terminal":
            print_banner()

        target_file = args.target

        if args.server:
            assessment = scan_file_remote(target_file, args.server)
        else:
            assessment = scan_file_local(target_file)

        verdict = assessment.get("verdict", "CLEAN")

        # Output formatting
        if args.format == "terminal":
            print(format_terminal_table(assessment))
        elif args.format == "json":
            json_report = generate_json_report(assessment)
            out_str = json.dumps(json_report, indent=2)
            if args.output:
                with open(args.output, "w") as f:
                    f.write(out_str)
                print(f"[OK] JSON security audit report saved to '{args.output}'")
            else:
                print(out_str)
        elif args.format == "html":
            html_report = generate_html_report(assessment)
            if args.output:
                with open(args.output, "w") as f:
                    f.write(html_report)
                print(f"[OK] HTML security audit report saved to '{args.output}'")
            else:
                print(html_report)

        # CI/CD Pipeline Build Blocking Logic
        should_fail = False
        if args.fail_on == "CRITICAL" and verdict == "CRITICAL_MALICIOUS":
            should_fail = True
        elif args.fail_on == "SUSPICIOUS" and verdict in ["CRITICAL_MALICIOUS", "SUSPICIOUS"]:
            should_fail = True
        elif args.fail_on == "ANY" and verdict != "CLEAN":
            should_fail = True

        if should_fail:
            print(f"\n[CI/CD BLOCK] Build blocked! Package verdict '{verdict}' matched threshold '--fail-on {args.fail_on}'.")
            sys.exit(1)
        else:
            if args.format == "terminal":
                print("\n[OK] Security check passed. Package safe for pipeline deployment.")
            sys.exit(0)


if __name__ == "__main__":
    if sys.platform == "win32":
        try:
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        except Exception:
            pass
    main()
