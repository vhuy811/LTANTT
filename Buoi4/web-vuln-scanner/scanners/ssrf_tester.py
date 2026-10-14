import re
from urllib.parse import urlparse, parse_qs


class SSRFTester:
    internal_ips = [
        re.compile(r'127\.0\.0\.1'),
        re.compile(r'localhost'),
        re.compile(r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
        re.compile(r'192\.168\.\d{1,3}\.\d{1,3}'),
        re.compile(r'172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}')
    ]

    def scan(self, url):
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param, values in params.items():
            for val in values:
                for pattern in self.internal_ips:
                    if pattern.search(val):
                        findings.append({
                            'param': param,
                            'value': val,
                            'desc': 'Potential SSRF to internal resource',
                            'risk': 'High'
                        })
        return findings
