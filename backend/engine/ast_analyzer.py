"""
SupplyShield - Abstract Syntax Tree (AST) Static Security Engine
Parses Python source code into syntax trees to identify dangerous calls,
obfuscation techniques, sensitive target accesses, and Trojan Source (Bidi) vectors.
"""

import ast
import base64
import math
import re
from typing import Dict, List, Any, Optional

# Trojan Source / Bidirectional override unicode characters (CVE-2021-42574)
BIDI_OVERRIDE_CHARS = {
    '\u202A': 'LEFT-TO-RIGHT EMBEDDING (LRE)',
    '\u202B': 'RIGHT-TO-LEFT EMBEDDING (RLE)',
    '\u202D': 'LEFT-TO-RIGHT OVERRIDE (LRO)',
    '\u202E': 'RIGHT-TO-LEFT OVERRIDE (RLO)',
    '\u202C': 'POP DIRECTIONAL FORMATTING (PDF)',
    '\u2066': 'LEFT-TO-RIGHT ISOLATE (LRI)',
    '\u2067': 'RIGHT-TO-LEFT ISOLATE (RLI)',
    '\u2068': 'FIRST STRONG ISOLATE (FSI)',
    '\u2069': 'POP DIRECTIONAL ISOLATE (PDI)'
}

# Sensitive file indicators targeted by credential-stealing backdoors
SENSITIVE_PATTERNS = [
    r"\.ssh[/\\]id_rsa",
    r"\.ssh[/\\]id_ed25519",
    r"\.aws[/\\]credentials",
    r"\.env",
    r"/etc/shadow",
    r"/etc/passwd",
    r"\.config[/\\]gcloud"
]

class ASTSecurityVisitor(ast.NodeVisitor):
    """
    Compiler-level NodeVisitor traversing the AST to detect dangerous function calls,
    dynamic code evaluation, suspicious imports, and data exfiltration patterns.
    """
    
    def __init__(self, raw_lines: List[str]):
        self.raw_lines = raw_lines
        self.findings: List[Dict[str, Any]] = []
        self.dangerous_calls_count = 0
        self.obfuscated_strings_count = 0
        self.imported_modules: List[str] = []
        
    def _get_snippet(self, lineno: Optional[int]) -> str:
        if lineno is not None and 1 <= lineno <= len(self.raw_lines):
            return self.raw_lines[lineno - 1].strip()
        return ""

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imported_modules.append(alias.name)
            if alias.name in ["pty", "ctypes"]:
                self.findings.append({
                    "rule_id": "SEC-IMP-001",
                    "severity": "MEDIUM",
                    "title": f"Low-Level System Import ({alias.name})",
                    "message": f"Module '{alias.name}' can be leveraged for terminal hijack or memory manipulation.",
                    "line": node.lineno,
                    "snippet": self._get_snippet(node.lineno),
                    "mitre_tag": "T1059 Command and Scripting Interpreter"
                })
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            self.imported_modules.append(node.module)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = self._resolve_callable_name(node.func)
        lineno = getattr(node, 'lineno', None)
        snippet = self._get_snippet(lineno)

        # Rule 1: Dynamic Execution (eval, exec, compile)
        if func_name in ["eval", "exec", "compile", "__import__"]:
            self.dangerous_calls_count += 1
            self.findings.append({
                "rule_id": "SEC-DYN-001",
                "severity": "CRITICAL",
                "title": f"Dynamic Code Execution ({func_name})",
                "message": f"Detected direct call to '{func_name}', common in polymorphic and obfuscated supply-chain backdoors.",
                "line": lineno,
                "snippet": snippet,
                "mitre_tag": "T1059.006 Python Command Execution"
            })

        # Rule 2: Process & Subprocess Spawning (os.system, subprocess.Popen)
        elif func_name in ["os.system", "os.popen", "os.spawn", "subprocess.Popen", "subprocess.run", "subprocess.call"]:
            self.dangerous_calls_count += 1
            self.findings.append({
                "rule_id": "SEC-SYS-002",
                "severity": "HIGH",
                "title": f"Host OS Command Spawning ({func_name})",
                "message": f"Execution of external shell processes via '{func_name}'.",
                "line": lineno,
                "snippet": snippet,
                "mitre_tag": "T1059 Command Execution"
            })

        # Rule 3: Network Sockets & Outbound Requests
        elif func_name in ["socket.socket", "urllib.request.urlopen", "requests.post", "requests.get", "http.client.HTTPConnection"]:
            self.findings.append({
                "rule_id": "SEC-NET-003",
                "severity": "MEDIUM",
                "title": f"Outbound Network Connection ({func_name})",
                "message": f"Network transmission capability detected via '{func_name}'.",
                "line": lineno,
                "snippet": snippet,
                "mitre_tag": "T1071 Application Layer Protocol"
            })

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            text = node.value
            lineno = getattr(node, 'lineno', None)
            snippet = self._get_snippet(lineno)

            # Rule 4: Base64 Obfuscation Detection
            if len(text) > 32 and re.match(r'^[A-Za-z0-9+/=]+$', text):
                try:
                    decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
                    # Check if decoded payload contains code tokens
                    if any(token in decoded for token in ["import", "socket", "os.", "subprocess", "/bin/", "http", "exec"]):
                        self.obfuscated_strings_count += 1
                        self.findings.append({
                            "rule_id": "SEC-OBF-004",
                            "severity": "CRITICAL",
                            "title": "Decodable Base64 Obfuscated Payload",
                            "message": f"Base64 string decodes to actionable command payload: '{decoded[:60]}...'",
                            "line": lineno,
                            "snippet": snippet,
                            "mitre_tag": "T1027 Obfuscated Files or Information"
                        })
                except Exception:
                    pass

            # Rule 5: Sensitive Target File Patterns (.ssh, .env, .aws)
            for pattern in SENSITIVE_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    self.findings.append({
                        "rule_id": "SEC-CRED-005",
                        "severity": "HIGH",
                        "title": "Sensitive Credential File Targeted",
                        "message": f"Hardcoded sensitive path indicator: '{text}'.",
                        "line": lineno,
                        "snippet": snippet,
                        "mitre_tag": "T1552 Credentials in Files"
                    })

            # Rule 6: High Shannon Entropy String Detection
            entropy = self._calculate_entropy(text)
            if len(text) > 40 and entropy > 4.8:
                self.findings.append({
                    "rule_id": "SEC-ENT-006",
                    "severity": "MEDIUM",
                    "title": f"High Entropy String Literal (Entropy: {entropy:.2f})",
                    "message": "Potential encrypted payload or secret key embedded in source.",
                    "line": lineno,
                    "snippet": snippet,
                    "mitre_tag": "T1027 Obfuscated Information"
                })

        self.generic_visit(node)

    def _resolve_callable_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value = self._resolve_callable_name(node.value)
            return f"{value}.{node.attr}" if value else node.attr
        return ""

    @staticmethod
    def _calculate_entropy(data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        for x in set(data):
            p_x = data.count(x) / length
            entropy += - p_x * math.log2(p_x)
        return entropy


def analyze_source_ast(source_code: str) -> Dict[str, Any]:
    """
    Main entrypoint for AST Static Analysis.
    Returns syntax metrics, vulnerability findings, Trojan Source checks, and risk score.
    """
    raw_lines = source_code.splitlines()
    
    # 1. Trojan Source (Bidi Overrides) Pre-Scan
    bidi_findings = []
    for idx, line in enumerate(raw_lines, 1):
        for char, char_name in BIDI_OVERRIDE_CHARS.items():
            if char in line:
                bidi_findings.append({
                    "rule_id": "SEC-BIDI-000",
                    "severity": "CRITICAL",
                    "title": f"Trojan Source Unicode Override Detected ({char_name})",
                    "message": "Invisible bidirectional control character alters visual code layout (CVE-2021-42574).",
                    "line": idx,
                    "snippet": line.strip(),
                    "mitre_tag": "T1036 Masquerading"
                })

    # 2. Compiler AST Parsing
    try:
        tree = ast.parse(source_code)
    except SyntaxError as e:
        return {
            "status": "SYNTAX_ERROR",
            "is_valid_syntax": False,
            "error": str(e),
            "findings": bidi_findings,
            "risk_score": 10 if bidi_findings else 0,
            "metrics": {"total_lines": len(raw_lines), "ast_nodes_count": 0}
        }

    # 3. Node Visitor Traversal
    visitor = ASTSecurityVisitor(raw_lines)
    visitor.visit(tree)

    all_findings = bidi_findings + visitor.findings

    # 4. Calculate Static Risk Score (0 - 100)
    score = 0
    for finding in all_findings:
        if finding["severity"] == "CRITICAL":
            score += 35
        elif finding["severity"] == "HIGH":
            score += 20
        elif finding["severity"] == "MEDIUM":
            score += 10
        elif finding["severity"] == "LOW":
            score += 5

    final_score = min(score, 100)

    # Count total AST nodes
    node_count = sum(1 for _ in ast.walk(tree))

    return {
        "status": "SUCCESS",
        "is_valid_syntax": True,
        "metrics": {
            "total_lines": len(raw_lines),
            "ast_nodes_count": node_count,
            "imported_modules": list(set(visitor.imported_modules)),
            "dangerous_calls_count": visitor.dangerous_calls_count,
            "obfuscated_strings_count": visitor.obfuscated_strings_count
        },
        "findings": all_findings,
        "static_risk_score": final_score
    }
