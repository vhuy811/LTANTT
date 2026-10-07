"""Giao diện web (Flask) cho Netrecon + gửi kết quả qua email."""
import asyncio
import os

from flask import Flask, render_template, request

from modules import (port_scanner, service_detector, banner_grabber,
                     network_mapper, vuln_checker, email_sender)

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    target = request.form['target']
    ports = list(map(int, request.form['ports'].split(',')))
    mode = request.form['mode']
    email = request.form.get('email', '')
    result = {}

    if mode in ['scan', 'all']:
        result['scan'] = asyncio.run(port_scanner.async_scan_ports(target, ports))
    if mode in ['service', 'all']:
        result['service'] = service_detector.detect_service(target, ports)
    if mode in ['banner', 'all']:
        result['banner'] = {port: banner_grabber.grab_banner(target, port) for port in ports}
    if mode in ['map', 'all']:
        result['map'] = network_mapper.map_network()
    if mode in ['vuln', 'all']:
        result['vuln'] = vuln_checker.check_vulns(ports)

    # Soạn nội dung email
    body = "Ket qua NetRecon:\n\n"
    for k, v in result.items():
        body += f"--- {k.upper()} ---\n{v}\n\n"

    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    if email:
        email_sender.send_email(email, "Ket qua quet tu NetRecon", body, smtp_user, smtp_pass)

    return render_template('result.html', result=result, target=target)


if __name__ == '__main__':
    # Chỉ nghe localhost cho an toàn (công cụ quét không nên mở ra LAN)
    app.run(debug=True, host='127.0.0.1', port=5000)
