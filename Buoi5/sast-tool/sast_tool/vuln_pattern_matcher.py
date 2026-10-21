import re


class VulnPatternMatcher:
    def match(self, code: str):
        patterns = [
            {'pattern': r'password\s*=\s*".*"',
             'message': 'Hardcoded password detected.'},
            {'pattern': r'import\s+pickle',
             'message': 'Usage of pickle module can be unsafe.'}
        ]
        issues = []
        for p in patterns:
            for match in re.finditer(p['pattern'], code):
                issues.append({
                    'type': 'Pattern Match',
                    'message': p['message'],
                    'lineno': code[:match.start()].count('\n') + 1,
                    'col_offset': match.start() - code.rfind('\n', 0, match.start()) - 1
                })
        return issues
