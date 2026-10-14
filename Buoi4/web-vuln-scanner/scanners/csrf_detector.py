import re


class CSRFDetector:
    csrf_token_patterns = [
        re.compile(r'name=["\']csrf_token["\']', re.I),
        re.compile(r'name=["\']_csrf["\']', re.I),
        re.compile(r'name=["\']csrfmiddlewaretoken["\']', re.I)
    ]

    def scan(self, html_content):
        for pattern in self.csrf_token_patterns:
            if pattern.search(html_content):
                return {'csrf_protected': True}
        return {'csrf_protected': False, 'desc':
                'No CSRF token found, vulnerable to CSRF', 'risk': 'Medium'}
