"""
SupplyShield - Dynamic YARA & Custom Security Policy Rule Engine
Loads custom JSON/YAML security rules and evaluates codebase AST / content
against enterprise compliance policies.
"""

import ast
import json
import math
import os
import re
from typing import Dict, List, Any, Optional, Union

DEFAULT_RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "rules.json")


class CustomRuleEngine:
    """
    Evaluates source code against custom policy rules (banned imports, regex secrets,
    forbidden system calls, and max entropy limits).
    """

    def __init__(self, rules_path_or_list: Optional[Union[str, List[Dict[str, Any]]]] = None):
        self.rules: List[Dict[str, Any]] = []
        
        if isinstance(rules_path_or_list, list):
            self.rules = rules_path_or_list
        else:
            target_path = rules_path_or_list if rules_path_or_list else DEFAULT_RULES_PATH
            self.load_rules(target_path)

    def load_rules(self, file_path: str) -> None:
        """Loads policy rules from JSON configuration file."""
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    self.rules = json.load(f)
            except Exception as e:
                print(f"[Warning] Failed to load custom rules from {file_path}: {e}")
                self.rules = []
        else:
            self.rules = []

    def evaluate_source(self, source_code: str, ast_tree: Optional[ast.AST] = None) -> List[Dict[str, Any]]:
        """
        Main evaluation entry point.
        Analyzes source_code and returns a list of custom rule violations.
        """
        findings: List[Dict[str, Any]] = []
        raw_lines = source_code.splitlines()

        # Parse AST if not provided
        if ast_tree is None:
            try:
                ast_tree = ast.parse(source_code)
            except SyntaxError:
                ast_tree = None

        # 1. Evaluate REGEX_PATTERN rules
        findings.extend(self._evaluate_regex_rules(raw_lines))

        # 2. Evaluate AST-based rules if AST is valid
        if ast_tree:
            findings.extend(self._evaluate_ast_rules(ast_tree, raw_lines))

        return findings

    def _evaluate_regex_rules(self, raw_lines: List[str]) -> List[Dict[str, Any]]:
        findings = []
        regex_rules = [r for r in self.rules if r.get("type") == "REGEX_PATTERN"]

        for rule in regex_rules:
            pattern_str = rule.get("pattern", "")
            if not pattern_str:
                continue

            try:
                pattern = re.compile(pattern_str)
            except re.error:
                continue

            for idx, line in enumerate(raw_lines, 1):
                match = pattern.search(line)
                if match:
                    findings.append({
                        "rule_id": rule.get("rule_id", "CUSTOM-REG-000"),
                        "severity": rule.get("severity", "HIGH"),
                        "title": rule.get("name", "Custom Regex Match"),
                        "message": rule.get("message", f"Matched custom regex pattern '{pattern_str}'."),
                        "line": idx,
                        "snippet": line.strip(),
                        "risk_score_boost": rule.get("risk_score_boost", 20),
                        "mitre_tag": rule.get("mitre_tag", "T1027 Obfuscated Files")
                    })
        return findings

    def _evaluate_ast_rules(self, ast_tree: ast.AST, raw_lines: List[str]) -> List[Dict[str, Any]]:
        findings = []
        
        # Categorize rules for efficient evaluation
        banned_imports = {
            r.get("target"): r for r in self.rules if r.get("type") == "BANNED_IMPORT" and isinstance(r.get("target"), str)
        }
        
        forbidden_calls = {}
        for r in self.rules:
            if r.get("type") == "FORBIDDEN_CALL":
                target = r.get("target")
                if isinstance(target, str):
                    forbidden_calls[target] = r
                elif isinstance(target, list):
                    for t in target:
                        forbidden_calls[t] = r

        entropy_rules = [r for r in self.rules if r.get("type") == "MAX_ENTROPY_THRESHOLD"]

        def get_snippet(lineno: Optional[int]) -> str:
            if lineno is not None and 1 <= lineno <= len(raw_lines):
                return raw_lines[lineno - 1].strip()
            return ""

        def resolve_callable_name(node: ast.AST) -> str:
            if isinstance(node, ast.Name):
                return node.id
            elif isinstance(node, ast.Attribute):
                val = resolve_callable_name(node.value)
                return f"{val}.{node.attr}" if val else node.attr
            return ""

        def calculate_entropy(data: str) -> float:
            if not data:
                return 0.0
            length = len(data)
            return -sum((data.count(c) / length) * math.log2(data.count(c) / length) for c in set(data))

        # Walk AST
        for node in ast.walk(ast_tree):
            lineno = getattr(node, 'lineno', None)
            snippet = get_snippet(lineno)

            # Check BANNED_IMPORT
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in banned_imports:
                        r = banned_imports[alias.name]
                        findings.append({
                            "rule_id": r.get("rule_id", "CUSTOM-IMP-000"),
                            "severity": r.get("severity", "MEDIUM"),
                            "title": r.get("name", f"Banned Import ({alias.name})"),
                            "message": r.get("message", f"Import of prohibited module '{alias.name}'."),
                            "line": lineno,
                            "snippet": snippet,
                            "risk_score_boost": r.get("risk_score_boost", 15),
                            "mitre_tag": r.get("mitre_tag", "T1027 Obfuscated Files")
                        })

            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module in banned_imports:
                    r = banned_imports[node.module]
                    findings.append({
                        "rule_id": r.get("rule_id", "CUSTOM-IMP-000"),
                        "severity": r.get("severity", "MEDIUM"),
                        "title": r.get("name", f"Banned Import ({node.module})"),
                        "message": r.get("message", f"Import of prohibited module '{node.module}'."),
                        "line": lineno,
                        "snippet": snippet,
                        "risk_score_boost": r.get("risk_score_boost", 15),
                        "mitre_tag": r.get("mitre_tag", "T1027 Obfuscated Files")
                    })

            # Check FORBIDDEN_CALL
            elif isinstance(node, ast.Call):
                func_name = resolve_callable_name(node.func)
                if func_name in forbidden_calls:
                    r = forbidden_calls[func_name]
                    findings.append({
                        "rule_id": r.get("rule_id", "CUSTOM-CALL-000"),
                        "severity": r.get("severity", "HIGH"),
                        "title": r.get("name", f"Forbidden Function Call ({func_name})"),
                        "message": r.get("message", f"Execution of prohibited function '{func_name}'."),
                        "line": lineno,
                        "snippet": snippet,
                        "risk_score_boost": r.get("risk_score_boost", 25),
                        "mitre_tag": r.get("mitre_tag", "T1059 Command Execution")
                    })

            # Check MAX_ENTROPY_THRESHOLD
            elif isinstance(node, ast.Constant):
                if isinstance(node.value, str):
                    val = node.value
                    entropy = calculate_entropy(val)
                    for r in entropy_rules:
                        threshold = r.get("threshold", 5.0)
                        min_len = r.get("min_length", 20)
                        if len(val) >= min_len and entropy >= threshold:
                            findings.append({
                                "rule_id": r.get("rule_id", "CUSTOM-ENT-000"),
                                "severity": r.get("severity", "HIGH"),
                                "title": r.get("name", f"Max Entropy Exceeded (Entropy: {entropy:.2f})"),
                                "message": r.get("message", f"String literal exceeds entropy threshold {threshold}."),
                                "line": lineno,
                                "snippet": snippet,
                                "risk_score_boost": r.get("risk_score_boost", 20),
                                "mitre_tag": r.get("mitre_tag", "T1027 Obfuscated Information")
                            })

        return findings
