import ast


class ASTAnalyzer:
    def analyze(self, code: str):
        tree = ast.parse(code)
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, 'id', '') == 'eval':
                issues.append({
                    'type': 'Use of eval',
                    'message': 'Use of eval() is dangerous and should be avoided.',
                    'lineno': node.lineno,
                    'col_offset': node.col_offset
                })
        return issues
