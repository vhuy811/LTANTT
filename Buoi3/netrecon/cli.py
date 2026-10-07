"""Giao diện dòng lệnh cho Netrecon.

    python cli.py --target 127.0.0.1 --ports 22,80,443 --mode all
    mode: scan | service | banner | map | vuln | all
"""
import asyncio

import click

from modules.port_scanner import async_scan_ports
from modules.service_detector import detect_service
from modules.banner_grabber import grab_banner
from modules.network_mapper import map_network
from modules.vuln_checker import check_vulns


@click.command()
@click.option('--target', prompt='Target IP', help='Dia chi IP muc tieu.')
@click.option('--ports', default='22,80,443', help='Danh sach cong, cach nhau dau phay.')
@click.option('--rate-limit', default=100, help='So ket noi dong thoi toi da (rate limiting).')
@click.option('--mode', default='all', help='Chon: scan, service, banner, map, vuln, all')
def cli(target, ports, rate_limit, mode):
    ports_list = list(map(int, ports.split(',')))

    if mode in ['scan', 'all']:
        open_ports = asyncio.run(async_scan_ports(target, ports_list, rate_limit))
        print(f"[SCAN] Cong mo: {open_ports}")
    if mode in ['service', 'all']:
        print("[SERVICE]")
        print(detect_service(target, ports_list))
    if mode in ['banner', 'all']:
        print("[BANNER]")
        for p in ports_list:
            print(f"  {p}: {grab_banner(target, p)}")
    if mode in ['map', 'all']:
        print("[MAP]")
        print(map_network())
    if mode in ['vuln', 'all']:
        print("[VULN]")
        print(check_vulns(ports_list))


if __name__ == '__main__':
    cli()
