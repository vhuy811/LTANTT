"""Quét cổng TCP bất đồng bộ (asyncio), giới hạn tốc độ bằng Semaphore (rate limiting)."""
import asyncio
import logging
from datetime import datetime

logging.basicConfig(filename='netrecon.log', level=logging.INFO)


def log(message):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logging.info(f"[{now}] {message}")


async def scan_port(target, port, semaphore, open_ports):
    try:
        async with semaphore:                     # rate limiting: tối đa N kết nối đồng thời
            conn = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=1)
            log(f"Port {port} is open on {target}")
            print(f"[+] {port}/tcp open")
            open_ports.append(port)
            writer.close()
            await writer.wait_closed()
    except Exception:
        pass                                        # cổng đóng/lọc -> bỏ qua


async def async_scan_ports(target, ports, rate_limit=100):
    """Quét danh sách cổng, trả về danh sách cổng mở (đã sắp xếp).

    Ghi chú: code đề bài không `return` nên mục SCAN trong web/email hiện None;
    ở đây trả về danh sách cổng mở để kết quả hiển thị đầy đủ.
    """
    semaphore = asyncio.Semaphore(rate_limit)
    open_ports = []
    tasks = [scan_port(target, port, semaphore, open_ports) for port in ports]
    await asyncio.gather(*tasks)
    return sorted(open_ports)
