from __future__ import annotations
import time
import json
from collections import defaultdict, deque
from typing import TextIO
from .parse import now_iso
from .config import ip_in_allowlist
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
    if(ip_in_allowlist(ev["src_ip"], ev.get("allowlist", []))):
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
def detect_spray(ev: dict,
                 spray_map: defaultdict[str, deque[tuple[float, str]]],
                 distinct_users: int,
                 window_sec: int,
                 outfile: TextIO | None) -> None:
    """Track per-IP failed logins; alert when distinct users >= threshold within window."""
    # 1. Filter: Only process failed logins
    if ev.get("type") != "AUTH_FAIL":
        return
    if(ip_in_allowlist(ev["src_ip"], ev.get("allowlist", []))):
        return    
    # 2. Extract Data: Get IP, User, and Current Time
    ip, user, t = ev["src_ip"], ev.get("user"), time.time()
    
    # 3. Append: Get the IP's deque and append the timestamp/user tuple
    dq = spray_map[ip]
    dq.append((t, user))
    
    # 4. Prune: Remove expired events outside the time window
    while dq and (t - dq[0][0]) > window_sec:
        dq.popleft()
        
    # 5. Uniqueness Check: Create a set of distinct users
    uniq = {u for _, u in dq}
    
    # 6. Alert Condition: Check if the number of distinct users meets the threshold
    if len(uniq) >= distinct_users:
        
        # Human-readable console alert
        print(f"[ALERT] SSH password spray suspected ip={ip} distinct_users={len(uniq)} window={window_sec}s")
        
        # Structure the alert event (Note: using list(uniq) for JSON compatibility)
        alert = {
            "type": "ALERT",
            "rule": "SSH_SPRAY", # Changed to SSH_SPRAY for consistency with detect.py
            "src_ip": ip,
            "distinct_users": list(uniq), # Convert set to list for JSON
            "count": len(dq), # Total attempts in the window
            "window_sec": window_sec,
            "first_seen": ev["ingest_ts"],
            "emitted_ts": now_iso(), # Requires now_iso() function
        }
        
        # 7. Write JSON Alert (MISSING STEP)
        if outfile:
            outfile.write(json.dumps(alert, ensure_ascii=False) + "\n")
            outfile.flush()
        