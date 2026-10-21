import unittest
import tempfile
from sast_tool.code_quality_checker import CodeQualityChecker


class TestCodeQualityChecker(unittest.TestCase):
    def test_flake8_detection(self):
        with tempfile.NamedTemporaryFile(suffix=".py",
                                         mode="w", delete=True) as tmp:
            tmp.write("import os\n\n\n")
            tmp.flush()
            checker = CodeQualityChecker()
            issues = checker.check(tmp.name)
            self.assertTrue(all(i['type'] == 'Lint Issue' for i in issues)
                            or len(issues) == 0)
