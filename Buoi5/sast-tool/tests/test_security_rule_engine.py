import unittest
import json
from sast_tool.security_rule_engine import SecurityRuleEngine


class TestSecurityRuleEngine(unittest.TestCase):
    def setUp(self):
        # Create temporary rule file
        self.rules = [
            {"type": "Use of eval", "severity": "high"},
            {"type": "Pattern Match", "severity": "medium"}
        ]
        with open("rules/temp_rules.json", "w") as f:
            json.dump(self.rules, f)
        self.engine = SecurityRuleEngine("rules/temp_rules.json")

    def tearDown(self):
        import os
        os.remove("rules/temp_rules.json")

    def test_evaluate(self):
        ast_issues = [{"type": "Use of eval", "message": "msg",
                       "lineno": 1, "col_offset": 0}]
        pattern_issues = [{"type": "Pattern Match", "message":
                           "msg", "lineno": 2, "col_offset": 1}]
        results = self.engine.evaluate(ast_issues, pattern_issues)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]['severity'], "high")
        self.assertEqual(results[1]['severity'], "medium")
