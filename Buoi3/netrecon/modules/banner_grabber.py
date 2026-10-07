"""Lấy banner dịch vụ qua socket, có timeout để không treo."""
import socket
import logging
from datetime import datetime

logging.basicConfig(filename='netrecon.log', level=logging.INFO)


def log(msg):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logging.info(f"[{now}] {msg}")


def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        banner = s.recv(1024).decode(errors='replace').strip()
        s.close()
        log(f"[{ip}:{port}] Banner: {banner}")
        return banner
    except Exception as e:
        return f"Failed to grab banner: {e}"
