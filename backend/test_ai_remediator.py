"""
Tests for SupplyShield AI Remediation Engine
"""

import pytest
from engine.ai_remediator import generate_ai_remediation

def test_reverse_shell_remediation():
    res = generate_ai_remediation(
        code_snippet="import socket, subprocess\ns = socket.socket()",
        rule_id="REVERSE_SHELL_ATTACK",
        description="Reverse shell detected"
    )
    assert res["status"] == "success"
    assert res["rule_id"] == "REVERSE_SHELL_ATTACK"
    assert "socket" in res["original_code"]
    assert "requests" in res["fixed_code"]
    assert "Mitigate Reverse Shell" in res["title"]

def test_generic_fallback_remediation():
    res = generate_ai_remediation(
        code_snippet="custom_bad_code()",
        rule_id="CUSTOM_RULE_X",
        description="Custom vulnerability"
    )
    assert res["status"] == "success"
    assert res["rule_id"] == "CUSTOM_RULE_X"
    assert "SECURE REFACTOR" in res["fixed_code"]
