"""
SupplyShield - Day 11 Automated Test Suite for Custom Security Policy Rule Engine
Tests loading JSON policy rules, evaluating regex matches, banned imports, forbidden calls,
and entropy thresholds.
"""

import os
import unittest
try:
    from backend.engine.custom_rules import CustomRuleEngine
    from backend.engine.ast_analyzer import analyze_source_ast
except ModuleNotFoundError:
    from engine.custom_rules import CustomRuleEngine
    from engine.ast_analyzer import analyze_source_ast



class TestCustomRuleEngine(unittest.TestCase):

    def setUp(self):
        self.sample_rules = [
            {
                "rule_id": "TEST-IMP-001",
                "name": "Banned Module Import",
                "type": "BANNED_IMPORT",
                "target": "pycryptodome",
                "severity": "MEDIUM",
                "risk_score_boost": 15,
                "message": "Import of prohibited module 'pycryptodome'."
            },
            {
                "rule_id": "TEST-CALL-002",
                "name": "Prohibited Call",
                "type": "FORBIDDEN_CALL",
                "target": "os.system",
                "severity": "HIGH",
                "risk_score_boost": 25,
                "message": "Prohibited call os.system."
            },
            {
                "rule_id": "TEST-SEC-003",
                "name": "Hardcoded Secret",
                "type": "REGEX_PATTERN",
                "pattern": r"AKIA[0-9A-Z]{16}",
                "severity": "CRITICAL",
                "risk_score_boost": 35,
                "message": "AWS Key matched."
            },
            {
                "rule_id": "TEST-ENT-004",
                "name": "High Entropy String",
                "type": "MAX_ENTROPY_THRESHOLD",
                "threshold": 4.5,
                "min_length": 20,
                "severity": "HIGH",
                "risk_score_boost": 20,
                "message": "High entropy string detected."
            }
        ]
        self.engine = CustomRuleEngine(rules_path_or_list=self.sample_rules)

    def test_banned_import_detection(self):
        code = "import pycryptodome\nprint('hello')"
        findings = self.engine.evaluate_source(code)
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("TEST-IMP-001", rule_ids)

    def test_forbidden_call_detection(self):
        code = "import os\nos.system('whoami')"
        findings = self.engine.evaluate_source(code)
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("TEST-CALL-002", rule_ids)

    def test_regex_pattern_secret_detection(self):
        code = "AWS_KEY = 'AKIA1234567890ABCDEF'\n"
        findings = self.engine.evaluate_source(code)
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("TEST-SEC-003", rule_ids)

    def test_max_entropy_threshold_detection(self):
        # String with high character diversity
        code = "SECRET_BLOB = 'aB1!cD2@eF3#gH4$iJ5%kL6^mN7&oP8*qR9'\n"
        findings = self.engine.evaluate_source(code)
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("TEST-ENT-004", rule_ids)

    def test_ast_analyzer_integration_with_custom_rules(self):
        code = "import pycryptodome\nAWS_KEY = 'AKIA1234567890ABCDEF'\n"
        result = analyze_source_ast(code)
        self.assertEqual(result["status"], "SUCCESS")
        self.assertGreater(result["metrics"]["custom_rule_violations_count"], 0)
        self.assertGreater(result["static_risk_score"], 20)

    def test_default_rules_json_loading(self):
        engine = CustomRuleEngine()
        self.assertGreater(len(engine.rules), 0)


if __name__ == "__main__":
    unittest.main()
