"""Tra cứu lỗ hổng (CVE) cơ bản theo cổng dịch vụ phổ biến."""

VULN_PORTS = {
    21:  "FTP - CVE-2015-3306, CVE-2001-0261",
    22:  "SSH - CVE-2018-15473",
    23:  "Telnet - CVE-2011-4862",
    80:  "HTTP - CVE-2021-41773",
    443: "HTTPS - CVE-2021-3449",
}


def check_vulns(ports):
    result = {}
    for port in ports:
        if port in VULN_PORTS:
            result[port] = VULN_PORTS[port]
    return result
