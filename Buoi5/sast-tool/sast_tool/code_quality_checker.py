import subprocess


class CodeQualityChecker:
    def check(self, filepath):
        issues = []
        result = subprocess.run(["flake8", filepath],
                                capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line:
                parts = line.split(":")
                if len(parts) >= 4:
                    # kiểm tra chắc chắn phần line và col là số
                    try:
                        lineno = int(parts[1])
                        col_offset = int(parts[2])
                    except ValueError:
                        continue
                    issues.append({
                        'type': 'Lint Issue',
                        'message': line,
                        'lineno': lineno,
                        'col_offset': col_offset
                    })
        return issues
