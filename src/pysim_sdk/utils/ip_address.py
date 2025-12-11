def ip2str(ip: int):
    return f"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}"


def str2ip(ip: str):
    return sum(
        [int(octet) << (8 * i) for i, octet in enumerate(reversed(ip.split(".")))]
    )
