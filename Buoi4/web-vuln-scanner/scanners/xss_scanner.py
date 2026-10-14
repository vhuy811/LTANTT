import requests


class XSSScanner:
    def __init__(self):
        self.payloads = ["<script>alert(1)</script>",
                         "'><svg/onload=alert(1)>"]

    def scan(self, url):
        results = []
        for payload in self.payloads:
            test_url = f"{url}?q={payload}"
            try:
                resp = requests.get(test_url, timeout=5)
                if payload in resp.text:
                    results.append({
                        "type": "XSS",
                        "payload": payload,
                        "url": test_url,
                        "risk": "HIGH"
                    })
            except Exception as e:
                pass
        return results
