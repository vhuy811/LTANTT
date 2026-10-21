import unittest
import os
from runtime_monitor import RuntimeMonitor


class TestRuntimeMonitor(unittest.TestCase):
    def test_cpu_and_memory(self):
        rm = RuntimeMonitor(os.getpid())
        self.assertIsInstance(rm.get_cpu_usage(), float)
        self.assertGreaterEqual(rm.get_memory_usage(), 0)
