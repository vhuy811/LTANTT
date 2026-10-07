"""Lọc danh sách mục tiêu theo whitelist / blacklist trước khi quét."""


def filter_targets(ip_list, whitelist=None, blacklist=None):
    whitelist = set(whitelist or [])
    blacklist = set(blacklist or [])
    result = []
    for ip in ip_list:
        if blacklist and ip in blacklist:
            continue                       # trong danh sách cấm -> loại
        if whitelist and ip not in whitelist:
            continue                       # có whitelist mà không nằm trong -> loại
        result.append(ip)
    return result
