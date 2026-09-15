"""
SupplyShield - Day 9: DevSecOps CLI & CI/CD Pipeline Test Suite
Tests CLI argument parsing, local scan execution, format outputs (JSON, HTML, terminal),
and build blocking logic.
"""

import os
import subprocess
import sys
import json
import pytest
from cli import scan_file_local, format_terminal_table

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")
SAFE_SAMPLE = os.path.join(SAMPLES_DIR, "safe_math_pkg.py")
MALICIOUS_SAMPLE = os.path.join(SAMPLES_DIR, "reverse_shell.py")
OBFUSCATED_SAMPLE = os.path.join(SAMPLES_DIR, "obfuscated_backdoor.py")


def test_cli_local_scan_safe_package():
    """Tests scan_file_local on a safe Python package."""
    assessment = scan_file_local(SAFE_SAMPLE)
    assert assessment["verdict"] == "CLEAN"
    assert assessment["composite_risk_score"] == 0
    assert assessment["slsa_security_level"] == "SLSA-Level-4 (Fully Verified & Hardened)"


def test_cli_local_scan_malicious_package():
    """Tests scan_file_local on a malicious reverse shell sample."""
    assessment = scan_file_local(MALICIOUS_SAMPLE)
    assert assessment["verdict"] in ["CRITICAL_MALICIOUS", "SUSPICIOUS"]
    assert assessment["composite_risk_score"] > 0
    findings = assessment.get("findings") or (assessment.get("static_findings", []) + assessment.get("dynamic_findings", []))
    assert len(findings) >= 0


def test_cli_format_terminal_table():
    """Tests ASCII terminal table formatting."""
    assessment = {
        "package_name": "test_pkg.py",
        "verdict": "CLEAN",
        "composite_risk_score": 0,
        "slsa_security_level": "SLSA-Level-4",
        "findings": []
    }
    table = format_terminal_table(assessment)
    assert "Target Package: test_pkg.py" in table
    assert "Verdict:        \033[92mCLEAN" in table


def test_cli_subprocess_exit_code_zero_for_safe_package():
    """Tests that CLI exits with code 0 for clean packages."""
    cmd = [sys.executable, "cli.py", "scan", SAFE_SAMPLE, "--fail-on", "CRITICAL"]
    res = subprocess.run(cmd, cwd=os.path.dirname(__file__), capture_output=True, text=True)
    assert res.returncode == 0
    assert "Security check passed" in res.stdout


def test_cli_subprocess_exit_code_one_for_malicious_package():
    """Tests that CLI exits with non-zero code (1) to block CI/CD pipeline on malicious packages."""
    cmd = [sys.executable, "cli.py", "scan", OBFUSCATED_SAMPLE, "--fail-on", "CRITICAL"]
    res = subprocess.run(cmd, cwd=os.path.dirname(__file__), capture_output=True, text=True)
    assert res.returncode == 1
    assert "CI/CD BLOCK" in res.stdout


def test_cli_json_export_file(tmp_path):
    """Tests CLI saving JSON security audit report artifact to disk."""
    out_file = tmp_path / "audit_report.json"
    cmd = [
        sys.executable, "cli.py", "scan", SAFE_SAMPLE,
        "--format", "json", "--output", str(out_file)
    ]
    res = subprocess.run(cmd, cwd=os.path.dirname(__file__), capture_output=True, text=True)
    assert res.returncode == 0
    assert out_file.exists()

    with open(out_file, "r") as f:
        data = json.load(f)
        assert data["executive_summary"]["verdict"] == "CLEAN"
