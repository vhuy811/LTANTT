"""Liệt kê bảng ARP (sơ đồ mạng) — các host trong cùng mạng LAN."""
import subprocess
import logging
from datetime import datetime

logging.basicConfig(filename='netrecon.log', level=logging.INFO)


def log(msg):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logging.info(f"[{now}] {msg}")


def map_network():
    log("Mapping network...")
    # Windows/macOS: arp -a. Nếu không có arp (một số Linux) thì dùng `ip neigh`.
    for cmd in (["arp", "-a"], ["ip", "neigh"]):
        try:
            out = subprocess.check_output(cmd).decode(errors='replace')
            log(out)
            return out
        except FileNotFoundError:
            continue
        except Exception as e:
            return f"Error: {e}"
    return "Error: khong tim thay lenh arp hoac ip"
