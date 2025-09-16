from __future__ import annotations
import time
import json
from collections import defaultdict, deque
from typing import TextIO
from .parse import now_iso

#variables
spray_users = defaultdict(lambda: deque(maxlen=1024))

# windows: defaultdict[str, deque[float]]
def detect_bruteforce(ev: dict,
                      windows: defaultdict[str, deque[float]],
                      threshold: int,
                      window_sec: int,
                      json_out_handle: TextIO | None) -> None:
    """Track per-IP FAIL timestamps; alert when count >= threshold within window."""
    if ev.get("type") != "AUTH_FAIL":
        return

    ip = ev["src_ip"]
    t = time.time()
    dq = windows[ip]
    dq.append(t)

    # get rid of old timestamps within the window_sec
    while dq and (t - dq[0]) > window_sec:
        dq.popleft()

    if len(dq) >= threshold:
        alert = {
            "type": "ALERT",
            "rule": "SSH_BRUTEFORCE",
            "src_ip": ip,
            "count": len(dq),
            "window_sec": window_sec,
            "first_seen": ev["ingest_ts"],
            "emitted_ts": now_iso(),
        }
        print(f"[ALERT] SSH brute force suspected ip={ip} count={len(dq)} window={window_sec}s")
        if json_out_handle:
            json_out_handle.write(json.dumps(alert) + "\n")
            json_out_handle.flush()
        # Optional: uncomment to avoid repeated alerts
        # dq.clear()

        
# per-IP => set of users within window
"""
ev → current event (dict, already parsed + enriched).

spray_map → defaultdict that maps src_ip → deque[(timestamp, user)].

distinct_users → threshold: how many different users from same IP trigger alert.

window_sec → how long the detection window is.

outfile → where to write JSON alerts (or None).

"""
def detect_spray(ev, spray_map, distinct_users, window_sec, outfile):
    if ev.get("type") != "AUTH_FAIL": return
    ip, user, t = ev["src_ip"], ev.get("user"), time.time()
    dq = spray_map[ip]
    dq.append((t, user))
    while dq and (t - dq[0][0]) > window_sec:
        dq.popleft()
    uniq = {u for _, u in dq}
    if len(uniq) >= distinct_users:
        # emit alert with list(uniq)
        ...
