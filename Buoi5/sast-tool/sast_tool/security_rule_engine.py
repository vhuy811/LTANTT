import json


class SecurityRuleEngine:
    def __init__(self, rules_file='rules/default_rules.json'):
        with open(rules_file) as f:
            self.rules = json.load(f)

    def evaluate(self, ast_issues, pattern_issues):
        issues = []
        for issue in ast_issues + pattern_issues:
            for rule in self.rules:
                if rule['type'] in issue['type']:
                    issue['severity'] = rule.get('severity', 'medium')
                    issues.append(issue)
        return issues
