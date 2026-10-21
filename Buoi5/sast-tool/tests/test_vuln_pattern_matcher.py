import unittest
from sast_tool.vuln_pattern_matcher import VulnPatternMatcher


class TestVulnPatternMatcher(unittest.TestCase):
    def test_hardcoded_password(self):
        code = 'password = "secret"'
        matcher = VulnPatternMatcher()
        issues = matcher.match(code)
        self.assertTrue(any(i['type'] == 'Pattern Match' for i in issues))

    def test_pickle_import(self):
        code = 'import pickle'
        matcher = VulnPatternMatcher()
        issues = matcher.match(code)
        self.assertTrue(any(i['type'] == 'Pattern Match' for i in issues))
