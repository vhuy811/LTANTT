import unittest
from unittest.mock import patch
from scanners.xss_scanner import XSSScanner


class TestXSSScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = XSSScanner()

    @patch('scanners.xss_scanner.requests.get')
    def test_detect_xss(self, mock_get):
        mock_get.return_value.text = '''
            <html><body><script>alert(1)</script></body></html>'''

        url = "http://example.com"
        findings = self.scanner.scan(url)

        self.assertTrue(any(f['payload'] == "<script>alert(1)</script>"
                            for f in findings))
        self.assertEqual(findings[0]['type'], 'XSS')
        self.assertEqual(findings[0]['risk'], 'HIGH')


if __name__ == '__main__':
    unittest.main()
