"""
SupplyShield - Abstract Syntax Tree (AST) Static Security Engine
Parses Python source code into AST representations to identify dangerous imports,
command executions, dynamic code evaluation, credential theft patterns, and
obfuscation before code is detonated or installed.

Features:
- Full alias resolution (e.g. from os import system as s; import subprocess as sp)
- Constant folding for dynamic call construction (getattr(__import__('os'), 'sys' + 'tem'))
- Context-aware scoring (safe literal lists vs shell=True command injection)
- Multi-layer recursive base64/zlib payload unpacking (up to depth 3)
- Shannon entropy evaluation restricted to valid decode payloads (low false positives)
"""

import ast
import re
import math
import base64
import zlib
from typing import Dict, List, Any, Optional

# Trojan Source Bidirectional Unicode Control Characters (CVE-2021-42574)
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

# Credential and sensitive host system file regex patterns
SENSITIVE_PATTERNS = [
    r"\.ssh[/\\]id_rsa",
    r"\.ssh[/\\]id_ed25519",
    r"\.aws[/\\]credentials",
    r"\.env",
    r"/etc/shadow",
    r"/etc/passwd",
    r"\.config[/\\]gcloud",
    r"chrome.*cookies",
    r"cookies\.sqlite",
    r"AppData.*Chrome",
    r"SUPPLYSHIELD_CANARY"
]

# Network and exfiltration library imports
NETWORK_IMPORT_MODULES = [
    "requests", "httpx", "aiohttp", "urllib", "urllib2", "urllib3",
    "http.client", "ftplib", "smtplib", "imaplib", "paramiko", "socket"
]

# File deletion / anti-forensic function calls
FILE_DELETION_CALLS = [
    "os.remove", "os.unlink", "os.rmdir", "shutil.rmtree",
    "pathlib.Path.unlink", "pathlib.Path.rmdir"
]

# Decompression functions used in multi-stage unpackers
DECOMPRESSION_CALLS = [
    "zlib.decompress", "gzip.decompress", "bz2.decompress", "lzma.decompress"
]

LOGIC_BOMB_SLEEP_THRESHOLD = 30.0


class ASTSecurityVisitor(ast.NodeVisitor):
    """
    Compiler-level NodeVisitor traversing the AST with alias tracking,
    constant expression evaluation, and context-sensitive risk scoring.
    """

    def __init__(self, raw_lines: List[str], current_depth: int = 0):
        self.raw_lines = raw_lines
        self.current_depth = current_depth
        self.findings: List[Dict[str, Any]] = []
        self.dangerous_calls_count = 0
        self.obfuscated_strings_count = 0
        self.imported_modules: List[str] = []
        # Alias map: tracks custom import bindings (e.g. s -> os.system, sp -> subprocess)
        self.aliases: Dict[str, str] = {}

    def _get_snippet(self, lineno: Optional[int]) -> str:
        if lineno is not None and 1 <= lineno <= len(self.raw_lines):
            return self.raw_lines[lineno - 1].strip()
        return ""

    def _evaluate_constant_str(self, node: ast.AST) -> Optional[str]:
        """Evaluates string constants and simple constant-folded string additions ('a' + 'b')."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._evaluate_constant_str(node.left)
            right = self._evaluate_constant_str(node.right)
            if left is not None and right is not None:
                return left + right
        return None

    def _resolve_callable_name(self, node: ast.AST) -> str:
        """
        Resolves callable expressions to normalized module.function paths,
        handling aliases, getattr calls, and dynamic module loaders.
        """
        # Case 1: Simple Name (e.g. eval, or alias 's')
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)

        # Case 2: Attribute access (e.g. os.system, sp.Popen)
        elif isinstance(node, ast.Attribute):
            base = self._resolve_callable_name(node.value)
            full_name = f"{base}.{node.attr}" if base else node.attr
            return self.aliases.get(full_name, full_name)

        # Case 3: Call expression returning module or function (getattr, __import__, importlib)
        elif isinstance(node, ast.Call):
            # getattr(obj, "func") or getattr(__import__("os"), "sys"+"tem")
            if isinstance(node.func, ast.Name) and node.func.id == "getattr" and len(node.args) >= 2:
                base = self._resolve_callable_name(node.args[0])
                attr = self._evaluate_constant_str(node.args[1])
                if base and attr:
                    full_name = f"{base}.{attr}"
                    return self.aliases.get(full_name, full_name)

            # __import__("os")
            elif isinstance(node.func, ast.Name) and node.func.id == "__import__" and node.args:
                mod_name = self._evaluate_constant_str(node.args[0])
                if mod_name:
                    return self.aliases.get(mod_name, mod_name)

            # importlib.import_module("os")
            elif isinstance(node.func, ast.Attribute) and node.func.attr == "import_module" and node.args:
                mod_name = self._evaluate_constant_str(node.args[0])
                if mod_name:
                    return self.aliases.get(mod_name, mod_name)

        return ""

    # ─────────────────────────────────────────────────────────────────────────
    # IMPORT TRACKING (ALIAS RESOLUTION)
    # ─────────────────────────────────────────────────────────────────────────
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imported_modules.append(alias.name)
            # Store alias mapping
            if alias.asname:
                self.aliases[alias.asname] = alias.name
            else:
                self.aliases[alias.name] = alias.name

            # Suspicious low-level system modules
            if alias.name in ["pty", "ctypes"]:
                self.findings.append({
                    "rule_id": "SEC-IMP-001",
                    "severity": "MEDIUM",
                    "title": f"Low-Level System Import ({alias.name})",
                    "message": f"Module '{alias.name}' can be leveraged for terminal hijacking or raw memory manipulation.",
                    "line": node.lineno,
                    "snippet": self._get_snippet(node.lineno),
                    "mitre_tag": "T1059 Command and Scripting Interpreter",
                    "mitre_justification": f"Imported low-level interface ({alias.name}) often used to evade high-level monitoring."
                })
            elif alias.name in NETWORK_IMPORT_MODULES:
                self.findings.append({
                    "rule_id": "SEC-IMP-002",
                    "severity": "LOW",
                    "title": f"Network Communication Library Import ({alias.name})",
                    "message": f"Module '{alias.name}' provides network communication capabilities.",
                    "line": node.lineno,
                    "snippet": self._get_snippet(node.lineno),
                    "mitre_tag": "T1071 Application Layer Protocol",
                    "mitre_justification": "Network socket or HTTP library capable of C2 communication or data exfiltration."
                })
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = node.module or ""
        if mod:
            self.imported_modules.append(mod)

        for alias in node.names:
            full_target = f"{mod}.{alias.name}" if mod else alias.name
            if alias.asname:
                self.aliases[alias.asname] = full_target
            else:
                self.aliases[alias.name] = full_target

        mod_base = mod.split(".")[0]
        if mod_base in NETWORK_IMPORT_MODULES or mod in NETWORK_IMPORT_MODULES:
            self.findings.append({
                "rule_id": "SEC-IMP-002",
                "severity": "LOW",
                "title": f"Network/HTTP Library Import (from {mod})",
                "message": f"Module '{mod}' enables outbound HTTP/TCP data transmission.",
                "line": node.lineno,
                "snippet": self._get_snippet(node.lineno),
                "mitre_tag": "T1071 Application Layer Protocol",
                "mitre_justification": "Imported networking module capable of remote communication."
            })
        self.generic_visit(node)

    # ─────────────────────────────────────────────────────────────────────────
    # CALL VISITATION & CONTEXT-AWARE RISK EVALUATION
    # ─────────────────────────────────────────────────────────────────────────
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
                "message": f"Direct call to '{func_name}', standard in obfuscated backdoors to execute runtime strings.",
                "line": lineno,
                "snippet": snippet,
                "mitre_tag": "T1059.006 Python Command Execution",
                "mitre_justification": f"Dynamic interpreter call '{func_name}' executes unchecked strings as code."
            })

        # Rule 2: Shell & Subprocess Execution (Context-Aware)
        elif func_name in ["os.system", "os.popen", "os.spawn", "subprocess.Popen", "subprocess.run", "subprocess.call"]:
            self.dangerous_calls_count += 1

            # Context Check: shell=True or dynamic expression vs safe literal argument list
            has_shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            is_literal_list = False
            if node.args and isinstance(node.args[0], ast.List):
                if all(isinstance(elt, ast.Constant) for elt in node.args[0].elts):
                    is_literal_list = True

            if has_shell_true or func_name in ["os.system", "os.popen"]:
                # High/Critical risk: command passes through system shell
                sev = "HIGH"
                desc = f"Shell command execution via '{func_name}' (shell=True or direct shell string). High risk of command injection."
            elif is_literal_list:
                # Low risk: fixed literal binary call without shell interpretation
                sev = "LOW"
                desc = f"Subprocess invocation via '{func_name}' using static literal argument list."
            else:
                sev = "HIGH"
                desc = f"Subprocess invocation via '{func_name}' with dynamic argument expressions."

            self.findings.append({
                "rule_id": "SEC-SYS-002",
                "severity": sev,
                "title": f"Host OS Command Spawning ({func_name})",
                "message": desc,
                "line": lineno,
                "snippet": snippet,
                "mitre_tag": "T1059 Command Execution",
                "mitre_justification": f"Execution of operating system commands via Python subprocess API ({func_name})."
            })

        # Rule 3: Network Sockets & Outbound Requests
        elif func_name in ["socket.socket", "socket.getaddrinfo", "urllib.request.urlopen", "urllib.request.urlretrieve", "requests.post", "requests.get", "http.client.HTTPConnection"]:
            self.findings.append({
                "rule_id": "SEC-NET-003",
                "severity": "MEDIUM",
                "title": f"Outbound Network Connection ({func_name})",
                "message": f"Network transmission capability invoked via '{func_name}'.",
                "line": lineno,
                "snippet": snippet,
                "mitre_tag": "T1071 Application Layer Protocol",
                "mitre_justification": f"API call '{func_name}' establishes network connection to remote endpoints."
            })

        # Rule 4: File Deletion / Anti-Forensics
        elif func_name in FILE_DELETION_CALLS:
            self.dangerous_calls_count += 1
            self.findings.append({
                "rule_id": "SEC-SYS-003",
                "severity": "HIGH",
                "title": f"Anti-Forensic File Deletion ({func_name})",
                "message": f"Destructive file deletion via '{func_name}'. Common in malware wiping traces after execution.",
                "line": lineno,
                "snippet": snippet,
                "mitre_tag": "T1070.004 Indicator Removal: File Deletion",
                "mitre_justification": f"File deletion call '{func_name}' can destroy system evidence or hostage files."
            })

        # Rule 5: Decompression Obfuscation (zlib/gzip + base64)
        elif func_name in DECOMPRESSION_CALLS:
            self.obfuscated_strings_count += 1
            self.findings.append({
                "rule_id": "SEC-OBF-007",
                "severity": "HIGH",
                "title": f"Decompression Routine ({func_name})",
                "message": f"Decompression routine '{func_name}' frequently used in compressed shellcode unpackers.",
                "line": lineno,
                "snippet": snippet,
                "mitre_tag": "T1027 Obfuscated Files or Information",
                "mitre_justification": "Payload decompression routine used to evade basic string scanning."
            })

        # Rule 6: Logic Bomb Sleep Delay (time.sleep >= 30)
        elif func_name == "time.sleep" and node.args:
            try:
                sleep_arg = node.args[0]
                sleep_val = None
                if isinstance(sleep_arg, ast.Constant) and isinstance(sleep_arg.value, (int, float)):
                    sleep_val = float(sleep_arg.value)
                if sleep_val is not None and sleep_val >= LOGIC_BOMB_SLEEP_THRESHOLD:
                    self.findings.append({
                        "rule_id": "SEC-TIME-008",
                        "severity": "HIGH",
                        "title": f"Logic Bomb Sleep Delay ({sleep_val}s)",
                        "message": f"time.sleep({sleep_val}) with delay >= {LOGIC_BOMB_SLEEP_THRESHOLD}s is a classic sandbox evasion technique.",
                        "line": lineno,
                        "snippet": snippet,
                        "mitre_tag": "T1497.003 Virtualization/Sandbox Evasion: Time Based Evasion",
                        "mitre_justification": f"Sleep delay of {sleep_val}s designed to exceed analysis watchdog limits."
                    })
            except Exception:
                pass

        # Rule 6b: Import Hook Manipulation (sys.meta_path)
        elif func_name in ["sys.meta_path.insert", "sys.meta_path.append"]:
            self.findings.append({
                "rule_id": "SEC-HOOK-002",
                "severity": "HIGH",
                "title": f"Import Hook Manipulation ({func_name})",
                "message": "Dynamic registration of custom import finder/loader to intercept module imports.",
                "line": lineno,
                "snippet": snippet,
                "mitre_tag": "T1546.012 Event Triggered Execution",
                "mitre_justification": "Manipulating sys.meta_path intercepts import statements to inject rogue code."
            })

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # Detect monkeypatching of builtins
        for target in node.targets:
            target_name = self._resolve_callable_name(target)
            if target_name.startswith("builtins.") or target_name.startswith("__builtins__."):
                self.dangerous_calls_count += 1
                self.findings.append({
                    "rule_id": "SEC-HOOK-001",
                    "severity": "CRITICAL",
                    "title": f"Builtin Function Monkeypatching ({target_name})",
                    "message": f"Overriding standard builtin symbol '{target_name}' to hijack runtime behavior.",
                    "line": getattr(node, "lineno", None),
                    "snippet": self._get_snippet(getattr(node, "lineno", None)),
                    "mitre_tag": "T1562.001 Impair Defenses",
                    "mitre_justification": f"Modification of builtin function '{target_name}' hijacks execution of benign libraries."
                })
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        # Homoglyph / confusable identifier check (Unicode TR39)
        if any(ord(c) > 127 for c in node.id):
            # Exclude known benign or already alerted
            already = any(f.get("rule_id") == "SEC-HOMOGLYPH-001" and f.get("line") == getattr(node, "lineno", None) for f in self.findings)
            if not already:
                self.findings.append({
                    "rule_id": "SEC-HOMOGLYPH-001",
                    "severity": "HIGH",
                    "title": f"Non-ASCII Homoglyph Identifier ({node.id})",
                    "message": f"Identifier '{node.id}' contains non-ASCII characters, characteristic of Trojan typosquatting.",
                    "line": getattr(node, "lineno", None),
                    "snippet": self._get_snippet(getattr(node, "lineno", None)),
                    "mitre_tag": "T1036 Masquerading",
                    "mitre_justification": "Cyrillic or Unicode homoglyph characters used to visually mimic standard library identifiers."
                })
        self.generic_visit(node)

    # ─────────────────────────────────────────────────────────────────────────
    # STRING CONSTANT ANALYSIS (RECURSIVE UNPACKING & SHANNON ENTROPY)
    # ─────────────────────────────────────────────────────────────────────────
    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            text = node.value
            lineno = getattr(node, 'lineno', None)
            snippet = self._get_snippet(lineno)

            # Rule 7: Sensitive Target Paths (.ssh, .env, .aws)
            for pattern in SENSITIVE_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    self.findings.append({
                        "rule_id": "SEC-CRED-005",
                        "severity": "HIGH",
                        "title": "Sensitive Credential File Targeted",
                        "message": f"Hardcoded sensitive path indicator: '{text}'.",
                        "line": lineno,
                        "snippet": snippet,
                        "mitre_tag": "T1552 Credentials in Files",
                        "mitre_justification": f"Literal path references credential or key store '{text}'."
                    })

            # Rule 7b: Ransomware / Extortion Indicators
            if any(term in text.lower() for term in ["encrypted_by_ransomware", "your files are encrypted", "decrypt_instructions"]):
                self.findings.append({
                    "rule_id": "SEC-RANSOM-001",
                    "severity": "CRITICAL",
                    "title": "Ransomware / Extortion Indicator",
                    "message": f"Hardcoded ransomware ransom or encryption marker found: '{text}'.",
                    "line": lineno,
                    "snippet": snippet,
                    "mitre_tag": "T1486 Data Encrypted for Impact",
                    "mitre_justification": "Text contains overt indicators of ransomware encryption or extortion ransom note."
                })

            # Rule 8: Base64 Decoding & Recursive AST Unpacking
            # Require minimum length of 32 characters and valid Base64 alphabet
            if len(text) >= 32 and re.match(r'^[A-Za-z0-9+/=_\-]+$', text.strip()):
                try:
                    # Pad if needed
                    padded = text.strip() + "=" * ((4 - len(text.strip()) % 4) % 4)
                    decoded_bytes = base64.b64decode(padded)

                    # Try decompression if payload is compressed
                    try:
                        decompressed = zlib.decompress(decoded_bytes)
                        decoded_bytes = decompressed
                    except Exception:
                        pass

                    decoded_text = decoded_bytes.decode('utf-8', errors='ignore')

                    # 8a: Does the decoded payload parse as executable Python code?
                    if len(decoded_text.strip()) > 10:
                        try:
                            # Attempt AST parse on decoded string
                            ast.parse(decoded_text)
                            self.obfuscated_strings_count += 1
                            self.findings.append({
                                "rule_id": "SEC-OBF-004",
                                "severity": "CRITICAL",
                                "title": "Executable Python Code Hidden in Base64",
                                "message": f"Base64 string decodes to valid Python code ({len(decoded_text)} chars): '{decoded_text[:60]}...'",
                                "line": lineno,
                                "snippet": snippet,
                                "mitre_tag": "T1027 Obfuscated Files or Information",
                                "mitre_justification": "Embedded Base64 literal contains full executable Python source code."
                            })

                            # Recursive inner AST analysis up to depth 3
                            if self.current_depth < 3:
                                inner_res = analyze_source_ast(decoded_text, current_depth=self.current_depth + 1)
                                for f in inner_res.get("findings", []):
                                    f_copy = dict(f)
                                    f_copy["title"] = f"[Decoded Layer {self.current_depth + 1}] {f_copy.get('title')}"
                                    self.findings.append(f_copy)

                        except SyntaxError:
                            # 8b: Not valid Python, but contains dangerous command indicators
                            if any(token in decoded_text for token in [
                                "import ", "socket", "os.", "subprocess", "/bin/", "powershell", "http://", "https://"
                            ]):
                                self.obfuscated_strings_count += 1
                                self.findings.append({
                                    "rule_id": "SEC-OBF-004",
                                    "severity": "CRITICAL",
                                    "title": "Decodable Base64 Obfuscated Command Payload",
                                    "message": f"Base64 string decodes to command/script payload: '{decoded_text[:60]}...'",
                                    "line": lineno,
                                    "snippet": snippet,
                                    "mitre_tag": "T1027 Obfuscated Files or Information",
                                    "mitre_justification": "Encoded Base64 payload reveals underlying system commands or network endpoints."
                                })

                except Exception:
                    pass

            # Rule 9: High Shannon Entropy String Literal
            # Only evaluate strings longer than 64 characters to avoid false positives on normal words/hashes
            if len(text) >= 64:
                entropy = self._calculate_entropy(text)
                if entropy > 4.6:
                    # Verify it has varied character classes (not just repetitive tokens)
                    has_digits = any(c.isdigit() for c in text)
                    has_alpha = any(c.isalpha() for c in text)
                    if has_digits and has_alpha:
                        self.findings.append({
                            "rule_id": "SEC-ENT-006",
                            "severity": "MEDIUM",
                            "title": f"High Entropy String Literal (Entropy: {entropy:.2f})",
                            "message": f"String of length {len(text)} exhibits high Shannon entropy ({entropy:.2f}), suggesting packed payload or cryptographic key.",
                            "line": lineno,
                            "snippet": snippet,
                            "mitre_tag": "T1027 Obfuscated Files or Information",
                            "mitre_justification": "Unusually high Shannon entropy in string literal indicates packed or encrypted bytes."
                        })

        self.generic_visit(node)

    @staticmethod
    def _calculate_entropy(data: str) -> float:
        """Computes standard Shannon entropy: H(X) = -sum(p(x) * log2(p(x)))."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        for x in set(data):
            p_x = data.count(x) / length
            entropy += - p_x * math.log2(p_x)
        return entropy


try:
    from backend.engine.custom_rules import CustomRuleEngine
except ModuleNotFoundError:
    from engine.custom_rules import CustomRuleEngine


def analyze_source_ast(
    source_code: str,
    custom_rules_path: Optional[str] = None,
    current_depth: int = 0
) -> Dict[str, Any]:
    """
    Main entrypoint for AST Static Analysis.
    Performs Trojan Source pre-scan, AST visitor traversal, policy rule checks,
    and returns metrics, findings, and computed static risk score.
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
                    "mitre_tag": "T1036 Masquerading",
                    "mitre_justification": "Bidirectional Unicode control character hides executable code logic from code reviewers."
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
    visitor = ASTSecurityVisitor(raw_lines, current_depth=current_depth)
    visitor.visit(tree)

    # 4. Custom Enterprise Policy Rule Evaluation (root depth only)
    custom_findings = []
    if current_depth == 0:
        try:
            custom_engine = CustomRuleEngine(rules_path_or_list=custom_rules_path)
            custom_findings = custom_engine.evaluate_source(source_code, ast_tree=tree)
        except Exception:
            custom_findings = []

    all_findings = bidi_findings + visitor.findings + custom_findings

    # 5. Calculate Static Risk Score (0 - 100)
    score = 0
    for finding in all_findings:
        sev = finding.get("severity")
        if sev == "CRITICAL":
            score += 35
        elif sev == "HIGH":
            score += 20
        elif sev == "MEDIUM":
            score += 10
        elif sev == "LOW":
            score += 3

    final_score = min(score, 100)
    node_count = sum(1 for _ in ast.walk(tree))

    return {
        "status": "SUCCESS",
        "is_valid_syntax": True,
        "metrics": {
            "total_lines": len(raw_lines),
            "ast_nodes_count": node_count,
            "imported_modules": list(set(visitor.imported_modules)),
            "dangerous_calls_count": visitor.dangerous_calls_count,
            "obfuscated_strings_count": visitor.obfuscated_strings_count,
            "custom_rule_violations_count": len(custom_findings),
            "recursion_depth": current_depth
        },
        "findings": all_findings,
        "static_risk_score": final_score
    }
