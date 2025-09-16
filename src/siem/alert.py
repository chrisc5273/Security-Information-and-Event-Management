from __future__ import annotations
import json
from typing import TextIO

def emit_event(ev: dict, json_out_handle: TextIO | None) -> None:
    """Human-readable line + optional JSONL write."""
    ip = ev.get("src_ip", "?")
    u = ev.get("user", "?")
    ts = ev.get("raw_ts", "?")
    ipcls = ev.get("src_ip_class")
    cls_suffix = f" class={ipcls}" if ipcls else ""


    if ev["type"] == "AUTH_FAIL":
        print(f"[!] FAIL ssh user={u} ip={ip}{cls_suffix} raw_ts={ts}")
    elif ev["type"] == "AUTH_OK":
        print(f"[*] OK   ssh user={u} ip={ip}{cls_suffix} raw_ts={ts}")

    if json_out_handle:
        json_out_handle.write(json.dumps(ev, ensure_ascii=False) + "\n")
        json_out_handle.flush()
