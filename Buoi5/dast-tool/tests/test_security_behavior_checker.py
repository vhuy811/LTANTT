import unittest
from security_behavior_checker import SecurityBehaviorChecker


class TestSecurityBehaviorChecker(unittest.TestCase):
    def test_suspicious_calls(self):
        sbc = SecurityBehaviorChecker()
        self.assertIsInstance(sbc.suspicious_calls(), list)
