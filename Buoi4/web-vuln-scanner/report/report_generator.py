class ReportGenerator:
    def generate(self, findings_list):
        report = {'vulnerabilities': []}
        for findings in findings_list:
            if isinstance(findings, list):
                report['vulnerabilities'].extend(findings)
            elif isinstance(findings, dict):
                report['vulnerabilities'].append(findings)
        return report
