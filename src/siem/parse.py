from __future__ import annotations
import re
from datetime import datetime

FAILED_SSH_RE = re.compile(
    r'(?P<ts>\w{3}\s+\d{1,2}\s[\d:]{8}).*sshd\[.*\]: Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
)
ACCEPTED_SSH_RE = re.compile(
    r'(?P<ts>\w{3}\s+\d{1,2}\s[\d:]{8}).*sshd\[.*\]: Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
)

def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"

def parse_line(line: str) -> dict | None:
    """Return a structured event dict or None."""
    m = FAILED_SSH_RE.search(line)
    if m:
        return {
            "type": "AUTH_FAIL",
            "service": "ssh",
            "user": m.group("user"),
            "src_ip": m.group("ip"),
            "raw_ts": m.group("ts"),
            "ingest_ts": now_iso(),
            "raw": line.rstrip("\n"),
        }
    m = ACCEPTED_SSH_RE.search(line)
    if m:
        return {
            "type": "AUTH_OK",
            "service": "ssh",
            "user": m.group("user"),
            "src_ip": m.group("ip"),
            "raw_ts": m.group("ts"),
            "ingest_ts": now_iso(),
            "raw": line.rstrip("\n"),
        }
    return None
