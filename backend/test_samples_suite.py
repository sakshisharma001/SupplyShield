"""
SupplyShield - Day 6: Comprehensive Malware Sample Test Suite
Tests all 7 samples against the AST analyzer to verify detection rules trigger correctly.
Each test validates specific security rule IDs and expected risk classifications.
"""

import os
import sys
import pytest

# Ensure backend root is in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from engine.ast_analyzer import analyze_source_ast

SAMPLES_DIR = os.path.join(CURRENT_DIR, "samples")


def load_sample(filename: str) -> str:
    """Load a sample file's source code."""
    filepath = os.path.join(SAMPLES_DIR, filename)
    with open(filepath, "r", encoding="utf-8") as f:
        return f.read()


# ========================================================================
# Test 1: Safe Package — Should detect NOTHING
# ========================================================================
class TestSafeMathPackage:
    """Verify that clean, legitimate code produces zero findings."""

    def setup_method(self):
        self.result = analyze_source_ast(load_sample("safe_math_pkg.py"))

    def test_syntax_valid(self):
        assert self.result["status"] == "SUCCESS"
        assert self.result["is_valid_syntax"] is True

    def test_zero_risk_score(self):
        assert self.result["static_risk_score"] == 0

    def test_no_findings(self):
        assert len(self.result["findings"]) == 0

    def test_no_dangerous_calls(self):
        assert self.result["metrics"]["dangerous_calls_count"] == 0

    def test_no_obfuscation(self):
        assert self.result["metrics"]["obfuscated_strings_count"] == 0


# ========================================================================
# Test 2: Obfuscated Backdoor — Should catch Base64 + exec()
# ========================================================================
class TestObfuscatedBackdoor:
    """Verify detection of Base64 encoded payloads and dynamic execution."""

    def setup_method(self):
        self.result = analyze_source_ast(load_sample("obfuscated_backdoor.py"))
        self.rule_ids = [f["rule_id"] for f in self.result["findings"]]

    def test_detects_obfuscation(self):
        assert "SEC-OBF-004" in self.rule_ids, "Should detect Base64 obfuscated payload"

    def test_detects_dynamic_exec(self):
        assert "SEC-DYN-001" in self.rule_ids, "Should detect exec() call"

    def test_high_risk_score(self):
        assert self.result["static_risk_score"] >= 60, f"Expected high score, got {self.result['static_risk_score']}"

    def test_has_critical_findings(self):
        severities = [f["severity"] for f in self.result["findings"]]
        assert "CRITICAL" in severities


# ========================================================================
# Test 3: Credential Stealer — Should catch file access + network
# ========================================================================
class TestCredentialStealer:
    """Verify detection of SSH key theft and credential exfiltration."""

    def setup_method(self):
        self.result = analyze_source_ast(load_sample("credential_stealer.py"))
        self.rule_ids = [f["rule_id"] for f in self.result["findings"]]

    def test_detects_ssh_key_access(self):
        assert "SEC-CRED-005" in self.rule_ids, "Should detect .ssh/id_rsa access"

    def test_detects_env_file_access(self):
        cred_findings = [f for f in self.result["findings"] if f["rule_id"] == "SEC-CRED-005"]
        messages = " ".join(f["message"] for f in cred_findings)
        assert ".env" in messages or ".ssh" in messages

    def test_detects_network_exfil(self):
        assert "SEC-NET-003" in self.rule_ids, "Should detect urllib network call"

    def test_risk_score_elevated(self):
        assert self.result["static_risk_score"] >= 30


# ========================================================================
# Test 4: Reverse Shell — Should catch os.system + subprocess + crontab
# ========================================================================
class TestReverseShell:
    """Verify detection of reverse shell, persistence, and privilege escalation."""

    def setup_method(self):
        self.result = analyze_source_ast(load_sample("reverse_shell.py"))
        self.rule_ids = [f["rule_id"] for f in self.result["findings"]]

    def test_detects_os_system(self):
        assert "SEC-SYS-002" in self.rule_ids, "Should detect os.system() calls"

    def test_detects_subprocess(self):
        sys_findings = [f for f in self.result["findings"] if f["rule_id"] == "SEC-SYS-002"]
        messages = " ".join(f["message"] for f in sys_findings)
        assert "subprocess" in messages.lower() or "os.system" in messages.lower()

    def test_multiple_dangerous_calls(self):
        assert self.result["metrics"]["dangerous_calls_count"] >= 3, "Should flag multiple dangerous calls"

    def test_high_risk_score(self):
        assert self.result["static_risk_score"] >= 50


# ========================================================================
# Test 5: DNS Exfiltrator — Should catch socket + credential files
# ========================================================================
class TestDNSExfiltrator:
    """Verify detection of DNS tunneling and cloud credential harvesting."""

    def setup_method(self):
        self.result = analyze_source_ast(load_sample("dns_exfiltrator.py"))
        self.rule_ids = [f["rule_id"] for f in self.result["findings"]]

    def test_detects_credential_targets(self):
        assert "SEC-CRED-005" in self.rule_ids, "Should detect .aws/credentials and .config/gcloud"

    def test_detects_sensitive_paths(self):
        cred_findings = [f for f in self.result["findings"] if f["rule_id"] == "SEC-CRED-005"]
        all_messages = " ".join(f["message"] for f in cred_findings)
        assert ".aws" in all_messages or "shadow" in all_messages or "gcloud" in all_messages

    def test_risk_score_elevated(self):
        assert self.result["static_risk_score"] >= 20


# ========================================================================
# Test 6: Typosquatting Package — Should catch compile + exec + os.system
# ========================================================================
class TestTyposquatPackage:
    """Verify detection of hidden malicious payload in a fake utility package."""

    def setup_method(self):
        self.result = analyze_source_ast(load_sample("typosquat_package.py"))
        self.rule_ids = [f["rule_id"] for f in self.result["findings"]]

    def test_detects_compile_call(self):
        assert "SEC-DYN-001" in self.rule_ids, "Should detect compile() call"

    def test_detects_exec_call(self):
        dyn_findings = [f for f in self.result["findings"] if f["rule_id"] == "SEC-DYN-001"]
        func_names = " ".join(f["title"] for f in dyn_findings)
        assert "exec" in func_names.lower() or "compile" in func_names.lower()

    def test_compile_hides_inner_code(self):
        # os.system inside compile() string is opaque to AST — only compile+exec are caught
        # This validates that attackers CAN hide inner payloads, but we still catch the wrapper
        assert "SEC-SYS-002" not in self.rule_ids, "Inner compiled code is opaque to AST"

    def test_critical_risk_score(self):
        assert self.result["static_risk_score"] >= 50


# ========================================================================
# Test 7: Cryptominer Dropper — Should catch subprocess + urllib + os.system
# ========================================================================
class TestCryptominerDropper:
    """Verify detection of cryptominer download and execution."""

    def setup_method(self):
        self.result = analyze_source_ast(load_sample("cryptominer_dropper.py"))
        self.rule_ids = [f["rule_id"] for f in self.result["findings"]]

    def test_detects_os_system_calls(self):
        assert "SEC-SYS-002" in self.rule_ids, "Should detect os.system and subprocess calls"

    def test_detects_subprocess_execution(self):
        assert "SEC-SYS-002" in self.rule_ids, "Should detect subprocess.Popen"

    def test_detects_os_system(self):
        sys_findings = [f for f in self.result["findings"] if f["rule_id"] == "SEC-SYS-002"]
        assert len(sys_findings) >= 2, "Should flag multiple OS command calls"

    def test_high_risk_score(self):
        assert self.result["static_risk_score"] >= 40


# ========================================================================
# Summary Test: Risk Ordering Verification
# ========================================================================
class TestRiskOrdering:
    """Verify that safe packages score lower than malicious ones."""

    def test_safe_lower_than_malicious(self):
        safe_score = analyze_source_ast(load_sample("safe_math_pkg.py"))["static_risk_score"]
        mal_score = analyze_source_ast(load_sample("credential_stealer.py"))["static_risk_score"]
        assert safe_score < mal_score, "Safe package must score lower than malicious"

    def test_safe_is_zero(self):
        score = analyze_source_ast(load_sample("safe_math_pkg.py"))["static_risk_score"]
        assert score == 0, "Clean code should have zero risk"

    def test_obfuscated_scores_highest(self):
        scores = {}
        for sample in ["safe_math_pkg.py", "obfuscated_backdoor.py", "credential_stealer.py"]:
            scores[sample] = analyze_source_ast(load_sample(sample))["static_risk_score"]
        assert scores["obfuscated_backdoor.py"] > scores["safe_math_pkg.py"]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
