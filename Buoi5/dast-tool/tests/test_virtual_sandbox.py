import unittest
from virtual_sandbox import VirtualSandbox


class TestVirtualSandbox(unittest.TestCase):
    def test_run_isolated(self):
        vs = VirtualSandbox()
        out, err = vs.run_isolated("echo test")
        self.assertIn("test", out)
        self.assertEqual(err, "")
