import re

def is_ip(indicator: str) -> bool:
    """Check if string looks like an IPv4 address"""
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", indicator) is not None
