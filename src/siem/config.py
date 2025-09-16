import json, yaml, ipaddress
from pathlib import Path

def load_config(path: str) -> dict:
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def ip_in_allowlist(ip: str, cidrs: list[str]) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in ipaddress.ip_network(c) for c in cidrs)
