from __future__ import annotations
import ipaddress

DEFAULT_ALLOWED = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

def validate_private_ip(ip: str, allowed=None) -> str:
    addr = ipaddress.ip_address(ip)
    nets = [ipaddress.ip_network(x) for x in (allowed or [str(n) for n in DEFAULT_ALLOWED])]
    if not any(addr in net for net in nets):
        raise ValueError(f"Target {ip} is outside the configured lab networks")
    return ip

def validate_limit(value: int, maximum: int, field: str) -> int:
    if value < 0 or value > maximum:
        raise ValueError(f"{field} must be between 0 and {maximum}")
    return value
