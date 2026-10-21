import unittest
from memory_analyzer import MemoryAnalyzer


class TestMemoryAnalyzer(unittest.TestCase):
    def test_check_overflow(self):
        ma = MemoryAnalyzer()
        self.assertTrue(ma.check_overflow(2**64))
        self.assertFalse(ma.check_overflow(100))
