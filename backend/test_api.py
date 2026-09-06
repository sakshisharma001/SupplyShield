"""
SupplyShield - Automated Integration Test Suite for FastAPI Gateway & WebSockets
Tests all REST endpoints, file uploads, history queries, and WebSocket telemetry feeds.
"""

import os
import sys

# Ensure backend root is in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_root_endpoint():
    """Verify root / endpoint returns operational status and links."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ONLINE"
    assert data["service"] == "SupplyShield Security Gateway"
    print("  [PASSED] Root / endpoint verified.")


def test_health_endpoint():
    """Verify /api/health reports all engines as ACTIVE."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert data["engines"]["ast_static_engine"] == "ACTIVE"
    assert data["engines"]["ephemeral_sandbox"] == "ACTIVE"
    assert data["engines"]["risk_scorer"] == "ACTIVE"
    assert data["engines"]["sqlite_audit_db"] == "ACTIVE"
    print("  [PASSED] /api/health endpoint verified with all engines active.")


def test_scan_code_safe_pkg():
    """Verify /api/scan/code correctly scans clean math package."""
    sample_path = os.path.join(CURRENT_DIR, "samples", "safe_math_pkg.py")
    with open(sample_path, "r", encoding="utf-8") as f:
        safe_code = f.read()

    response = client.post(
        "/api/scan/code",
        json={"code": safe_code, "package_name": "safe_math_pkg.py"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    report = data["report"]
    assert report["verdict"] == "CLEAN"
    assert report["composite_risk_score"] == 0
    assert "SLSA-Level-4" in report["slsa_security_level"]
    print(f"  [PASSED] /api/scan/code safe package -> Verdict: {report['verdict']}, Score: {report['composite_risk_score']}")


def test_scan_code_malicious_backdoor():
    """Verify /api/scan/code detects obfuscated backdoor and assigns CRITICAL verdict."""
    sample_path = os.path.join(CURRENT_DIR, "samples", "obfuscated_backdoor.py")
    with open(sample_path, "r", encoding="utf-8") as f:
        malicious_code = f.read()

    response = client.post(
        "/api/scan/code",
        json={"code": malicious_code, "package_name": "obfuscated_backdoor.py"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    report = data["report"]
    assert report["verdict"] == "CRITICAL_MALICIOUS"
    assert report["composite_risk_score"] >= 80
    assert "SLSA-Level-0" in report["slsa_security_level"]
    print(f"  [PASSED] /api/scan/code malicious backdoor -> Verdict: {report['verdict']}, Score: {report['composite_risk_score']}")


def test_scan_package_file_upload():
    """Verify /api/scan/package accepts multipart file upload and scans successfully."""
    sample_path = os.path.join(CURRENT_DIR, "samples", "credential_stealer.py")
    with open(sample_path, "rb") as f:
        response = client.post(
            "/api/scan/package",
            files={"file": ("credential_stealer.py", f, "text/x-python")},
            data={"package_name": "uploaded_credential_stealer.py"}
        )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    report = data["report"]
    assert report["verdict"] in ["SUSPICIOUS", "CRITICAL_MALICIOUS"]
    assert report["composite_risk_score"] > 50
    print(f"  [PASSED] /api/scan/package file upload -> Verdict: {report['verdict']}, Score: {report['composite_risk_score']}")


def test_history_and_details_endpoints():
    """Verify /api/history and /api/scan/{id} retrieve stored scan records."""
    # 1. Fetch history
    hist_response = client.get("/api/history?limit=10")
    assert hist_response.status_code == 200
    hist_data = hist_response.json()
    assert hist_data["success"] is True
    assert hist_data["count"] > 0
    latest_scan_id = hist_data["scans"][0]["id"]
    
    # 2. Fetch specific detail
    detail_response = client.get(f"/api/scan/{latest_scan_id}")
    assert detail_response.status_code == 200
    detail_data = detail_response.json()
    assert detail_data["success"] is True
    assert detail_data["scan_id"] == latest_scan_id
    assert "composite_risk_score" in detail_data["report"]
    print(f"  [PASSED] /api/history and /api/scan/{latest_scan_id} verified.")


def test_websocket_telemetry():
    """Verify WebSocket /ws/telemetry connection, handshake, and ping-pong."""
    with client.websocket_connect("/ws/telemetry") as websocket:
        # 1. Receive initial welcome handshake
        handshake = websocket.receive_json()
        assert handshake["stage"] == "HANDSHAKE"
        assert handshake["level"] == "INFO"
        
        # 2. Send ping to test bidirectional socket
        websocket.send_text("PING")
        pong = websocket.receive_json()
        assert pong["type"] == "PONG"
        assert pong["status"] == "HEALTHY"
        print("  [PASSED] WebSocket /ws/telemetry handshake & bi-directional communication verified.")


if __name__ == "__main__":
    print("\n=================================================================")
    print("[*] RUNNING SUPPLYSHIELD FASTAPI & WEBSOCKET GATEWAY TEST SUITE")
    print("=================================================================\n")
    test_root_endpoint()
    test_health_endpoint()
    test_scan_code_safe_pkg()
    test_scan_code_malicious_backdoor()
    test_scan_package_file_upload()
    test_history_and_details_endpoints()
    test_websocket_telemetry()
    print("\n=================================================================")
    print("[+] ALL FASTAPI & WEBSOCKET API TESTS PASSED SUCCESSFULLY! (100%)")
    print("=================================================================\n")
