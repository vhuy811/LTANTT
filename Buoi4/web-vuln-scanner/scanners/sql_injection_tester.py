from urllib.parse import urlparse, parse_qs


class SQLInjectionTester:
    payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users;--",
        "\" OR 1=1--",
        "' UNION SELECT NULL--"
    ]

    def scan(self, url):
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param, values in params.items():
            for val in values:
                for payload in self.payloads:
                    if payload in val:
                        findings.append({
                            'param': param,
                            'payload': payload,
                            'desc': 'Potential SQL Injection',
                            'risk': 'Critical'
                        })
        return findings
