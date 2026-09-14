"""
SupplyShield - Day 8: Executive Security Audit Report Engine Test Suite
Tests JSON report generation, HTML template formatting, MITRE ATT&CK extraction,
and FastAPI export endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from main import app
from engine.report_generator import generate_json_report, generate_html_report

client = TestClient(app)

@pytest.fixture
def mock_scan_record():
    return {
        "scan_id": 42,
        "filename": "reverse_shell_backdoor.py",
        "composite_score": 92.5,
        "verdict": "CRITICAL_MALICIOUS",
        "slsa_level": "SLSA-Level-0",
        "created_at": "2026-09-14T15:00:00Z",
        "findings": [
            {
                "rule_id": "SEC-SYS-002",
                "severity": "CRITICAL",
                "title": "System Command Execution",
                "description": "Invocation of os.system executing reverse shell payload",
                "mitre_id": "T1059.004"
            },
            {
                "rule_id": "SEC-CRED-005",
                "severity": "HIGH",
                "title": "Credential Access",
                "description": "Access to os.environ and AWS secrets",
                "mitre_id": "T1552.001"
            }
        ]
    }


def test_json_report_structure(mock_scan_record):
    """Verifies executive JSON report structure, metrics, and remediation guidance."""
    report = generate_json_report(mock_scan_record)

    assert report["report_id"] == "REP-42"
    assert report["target"] == "reverse_shell_backdoor.py"
    assert report["executive_summary"]["risk_score"] == 92.5
    assert report["executive_summary"]["verdict"] == "CRITICAL_MALICIOUS"
    assert report["executive_summary"]["slsa_provenance_level"] == "SLSA-Level-0"
    assert report["executive_summary"]["critical_findings"] == 1
    assert "T1059.004" in report["executive_summary"]["mitre_techniques_detected"]
    assert len(report["remediation_guidance"]) >= 2


def test_html_report_rendering(mock_scan_record):
    """Verifies print-ready HTML audit report contains required HTML tags and styling."""
    html_output = generate_html_report(mock_scan_record)

    assert "<!DOCTYPE html>" in html_output
    assert "SupplyShield Security Audit Report" in html_output
    assert "CRITICAL_MALICIOUS" in html_output
    assert "reverse_shell_backdoor.py" in html_output
    assert "SEC-SYS-002" in html_output
    assert "T1059.004" in html_output


def test_clean_package_report():
    """Verifies report generation for a clean benign package."""
    clean_record = {
        "scan_id": 1,
        "filename": "safe_math.py",
        "composite_score": 0,
        "verdict": "CLEAN",
        "slsa_level": "SLSA-Level-4",
        "findings": []
    }
    report = generate_json_report(clean_record)
    assert report["executive_summary"]["verdict"] == "CLEAN"
    assert report["executive_summary"]["total_findings"] == 0

    html_output = generate_html_report(clean_record)
    assert "No security vulnerabilities detected. Package is clean." in html_output


def test_api_report_export_endpoints():
    """Verifies FastAPI GET /api/scan/{id}/report and /html endpoints."""
    # First post a scan to create a database record
    scan_res = client.post("/api/scan/code", json={
        "code": "import os\nos.system('echo test')",
        "package_name": "test_cmd.py"
    })
    assert scan_res.status_code == 200
    scan_id = scan_res.json()["report"]["scan_id"]

    # Test JSON export endpoint
    json_export = client.get(f"/api/scan/{scan_id}/report")
    assert json_export.status_code == 200
    assert json_export.json()["success"] is True
    assert json_export.json()["report"]["report_id"] == f"REP-{scan_id}"

    # Test HTML export endpoint
    html_export = client.get(f"/api/scan/{scan_id}/report/html")
    assert html_export.status_code == 200
    assert "text/html" in html_export.headers["content-type"]
    assert "SupplyShield Security Audit Report" in html_export.text
