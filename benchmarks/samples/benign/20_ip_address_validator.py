"""IP address parsing with ipaddress standard library."""
import ipaddress

def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False
