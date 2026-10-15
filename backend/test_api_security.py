"""
Unit and Integration Tests for Phase 4: API & Report Security
Validates:
1. Stored XSS defense: all fields in HTML reports are escaped (no raw <script> tags).
2. Finding description mapping: ensures finding messages/descriptions are properly mapped.
3. Input size limits: rejects /api/scan/code requests exceeding MAX_CODE_LENGTH_CHARS with HTTP 413.
4. Path traversal sanitization: verifies filenames like ../../etc/passwd are stripped to basename.
5. API Key authentication: enforces X-API-Key and Bearer auth when configured, allows open access when unset.
"""

import os
import sys
import unittest
from fastapi.testclient import TestClient

# Ensure backend root is on sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from config import settings
from main import app
from engine.report_generator import generate_html_report, generate_json_report


class TestReportXSSDefense(unittest.TestCase):
    """Verifies that malicious HTML/JS payloads cannot break out into raw executable tags."""

    def test_xss_payload_escaped_in_html_report(self):
        """Ensures <script> tags in target, description, snippet, and MITRE fields are HTML-escaped."""
        xss_payload = "<script>alert('XSS-INJECTED')</script>"
        scan_record = {
            "scan_id": 9999,
            "package_name": f"evil_pkg_{xss_payload}.py",
            "composite_risk_score": 95,
            "verdict": "CRITICAL_MALICIOUS",
            "slsa_security_level": "SLSA-Level-0",
            "findings": [
                {
                    "rule_id": f"RULE_{xss_payload}",
                    "severity": "CRITICAL",
                    "description": f"Vulnerable code executed {xss_payload}",
                    "message": f"Message with {xss_payload}",
                    "snippet": f"os.system('{xss_payload}')",
                    "mitre_tag": f"T1059 {xss_payload}",
                }
            ]
        }

        html_out = generate_html_report(scan_record)

        # 1. Unescaped script tags must NEVER appear in the generated HTML
        self.assertNotIn("<script>alert('XSS-INJECTED')</script>", html_out,
                         "Critical Security Failure: Unescaped raw <script> tag found in HTML report!")

        # 2. Properly escaped entities MUST appear
        self.assertIn("&lt;script&gt;alert(&#x27;XSS-INJECTED&#x27;)&lt;/script&gt;", html_out,
                      "Expected HTML entities &lt;script&gt; were not found in escaped output.")

    def test_finding_description_mapping(self):
        """Ensures descriptions from findings (description, message, or title) map cleanly without empty strings."""
        scan_record = {
            "scan_id": 1001,
            "package_name": "clean_pkg.py",
            "composite_risk_score": 10,
            "verdict": "CLEAN",
            "findings": [
                {
                    "rule_id": "TEST_RULE_01",
                    "severity": "LOW",
                    "description": "Legitimate finding description text",
                    "mitre_tag": "T1059"
                },
                {
                    "rule_id": "TEST_RULE_02",
                    "severity": "LOW",
                    "message": "Fallback message used when description omitted",
                    "mitre_tag": "T1059"
                }
            ]
        }

        html_out = generate_html_report(scan_record)
        self.assertIn("Legitimate finding description text", html_out)
        self.assertIn("Fallback message used when description omitted", html_out)


class TestAPISecurity(unittest.TestCase):
    """Integration tests for FastAPI gateway endpoints."""

    def setUp(self):
        self.client = TestClient(app)
        self.original_api_key = settings.API_KEY
        self.original_max_chars = settings.MAX_CODE_LENGTH_CHARS

    def tearDown(self):
        settings.API_KEY = self.original_api_key
        settings.MAX_CODE_LENGTH_CHARS = self.original_max_chars

    def test_oversized_code_payload_returns_413(self):
        """Verifies that code payloads exceeding MAX_CODE_LENGTH_CHARS return HTTP 413."""
        settings.MAX_CODE_LENGTH_CHARS = 500  # Set small threshold for test
        large_code = "x = 1\n" * 200  # ~1200 characters

        response = self.client.post("/api/scan/code", json={"code": large_code, "package_name": "large.py"})
        self.assertEqual(response.status_code, 413)
        self.assertIn("exceeds maximum size limit", response.json()["detail"])

    def test_path_traversal_filename_sanitization(self):
        """Verifies that filenames like ../../etc/passwd or sub/evil.py are stripped to basename."""
        file_content = b"print('safe')"
        files = {
            "file": ("../../etc/passwd.py", file_content, "text/x-python")
        }

        response = self.client.post("/api/scan/package", files=files)
        # Even if pipeline finishes or mock runs, filename must be sanitized to passwd.py
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["filename"], "passwd.py")
        self.assertNotIn("..", data["filename"])

    def test_api_key_authentication(self):
        """Verifies X-API-Key and Bearer header enforcement when SUPPLYSHIELD_API_KEY is configured."""
        test_key = "supplyshield-secret-token-xyz"
        settings.API_KEY = test_key

        try:
            # 1. Request without API key -> 401 Unauthorized
            res_no_key = self.client.post("/api/scan/code", json={"code": "x = 1"})
            self.assertEqual(res_no_key.status_code, 401)
            self.assertIn("Unauthorized", res_no_key.json()["detail"])

            # 2. Request with invalid API key -> 401 Unauthorized
            res_bad_key = self.client.post(
                "/api/scan/code",
                json={"code": "x = 1"},
                headers={"X-API-Key": "wrong-key"}
            )
            self.assertEqual(res_bad_key.status_code, 401)

            # 3. Request with valid X-API-Key header -> 200 OK
            res_valid_header = self.client.post(
                "/api/scan/code",
                json={"code": "x = 1"},
                headers={"X-API-Key": test_key}
            )
            self.assertEqual(res_valid_header.status_code, 200)

            # 4. Request with valid Authorization: Bearer <key> -> 200 OK
            res_valid_bearer = self.client.post(
                "/api/scan/code",
                json={"code": "x = 1"},
                headers={"Authorization": f"Bearer {test_key}"}
            )
            self.assertEqual(res_valid_bearer.status_code, 200)

        finally:
            # Revert API key
            settings.API_KEY = ""

        # 5. When API key is unset, access is open (demo/local mode)
        res_open = self.client.post("/api/scan/code", json={"code": "x = 1"})
        self.assertEqual(res_open.status_code, 200)


if __name__ == "__main__":
    unittest.main()
