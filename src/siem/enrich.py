# src/siem/enrich.py
from __future__ import annotations
import ipaddress
import socket
from datetime import datetime

HOSTNAME = socket.gethostname()

def classify_ip(addr: str) -> str:
    """
    Return a simple class for the IP: 'private', 'loopback', 'link_local', 'reserved', or 'public'.
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return "invalid"

    if ip.is_private:
        return "private"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return "reserved"
    return "public"

def normalize_syslog_ts(raw_ts: str, assume_year: int | None = None) -> str | None:
    """
    Convert a syslog-like timestamp (e.g., 'Sep 15 12:34:56') to this format for clean purposes (yyyy-mm-ddTHH:MM:SSZ).
    If year is not present in the raw ts, we assume the current year unless overridden by assume_year.
    Returns ISO string or None if parsing fails.
    """
    # Syslog month is a 3-letter name, day can be 1 or 2 digits: '%b %d %H:%M:%S'
    try:
        year = assume_year or datetime.utcnow().year
        dt = datetime.strptime(f"{year} {raw_ts}", "%Y %b %d %H:%M:%S")
        # NOTE: This assumes the log time is already UTC. If it’s localtime, you’d need tz handling.
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None

def enrich_event(ev: dict) -> dict:
    """
        This is to see what the hostname is and the ip class if it is private or public 
      - host: hostname of the collector
      - src_ip_class: private/public/etc.
      - normalized_ts: ISO8601 UTC derived from raw_ts (best-effort)
    """
    out = dict(ev)  # shallow copy
    out["host"] = HOSTNAME

    ip = ev.get("src_ip")
    if ip:
        out["src_ip_class"] = classify_ip(ip)

    raw_ts = ev.get("raw_ts")
    if raw_ts:
        norm = normalize_syslog_ts(raw_ts)
        if norm:
            out["normalized_ts"] = norm

    return out
