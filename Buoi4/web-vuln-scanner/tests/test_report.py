import unittest
from report.report_generator import ReportGenerator


class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        self.generator = ReportGenerator()

    def test_generate_report_with_list(self):
        findings_list = [
            [{'param': 'input', 'desc': 'XSS found', 'risk': 'High'}],
            [{'param': 'id', 'desc': 'SQL Injection', 'risk': 'Critical'}]
        ]
        report = self.generator.generate(findings_list)
        self.assertEqual(len(report['vulnerabilities']), 2)
        self.assertTrue(any(v['desc'] == 'XSS found'
                            for v in report['vulnerabilities']))

    def test_generate_report_with_dict(self):
        findings_dict = {'param': 'url', 'desc': 'SSRF found', 'risk': 'High'}
        report = self.generator.generate([findings_dict])
        self.assertEqual(len(report['vulnerabilities']), 1)
        self.assertEqual(report['vulnerabilities'][0]['param'], 'url')


if __name__ == '__main__':
    unittest.main()
