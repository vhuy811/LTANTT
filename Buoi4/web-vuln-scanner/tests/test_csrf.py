import unittest
from scanners.csrf_detector import CSRFDetector


class TestCSRFDetector(unittest.TestCase):
    def setUp(self):
        self.detector = CSRFDetector()

    def test_csrf_token_present(self):
        html = '''<form><input type="hidden"
                name="csrf_token" value="abc123"/></form>'''
        result = self.detector.scan(html)
        self.assertTrue(result.get('csrf_protected'))

    def test_csrf_token_missing(self):
        html = '<form><input type="text" name="username"/></form>'
        result = self.detector.scan(html)
        self.assertFalse(result.get('csrf_protected'))
        self.assertIn('vulnerable', result.get('desc').lower())


if __name__ == '__main__':
    unittest.main()
