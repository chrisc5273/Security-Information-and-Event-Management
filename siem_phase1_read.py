# siem_phase1_read.py
#The code below has been seperated into different files which represent different functions
import argparse
import os
import sys
import time
import re
import json
import tty
from collections import defaultdict, deque
from datetime import datetime
import termios

FAILED_SSH_RE = re.compile(
    r'(?P<ts>\w{3}\s+\d{1,2}\s[\d:]{8}).*sshd\[.*\]: Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
)
ACCEPTED_SSH_RE = re.compile(
    r'(?P<ts>\w{3}\s+\d{1,2}\s[\d:]{8}).*sshd\[.*\]: Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
)

def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"

def parse_line(line: str):
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

def emit_event(ev: dict, json_out_handle):
    # human-readable
    if ev["type"] == "AUTH_FAIL":
        print(f"[!] FAIL ssh user={ev['user']} ip={ev['src_ip']} raw_ts={ev['raw_ts']}")
    elif ev["type"] == "AUTH_OK":
        print(f"[*] OK   ssh user={ev['user']} ip={ev['src_ip']} raw_ts={ev['raw_ts']}")
    # optional JSONL
    if json_out_handle:
        json_out_handle.write(json.dumps(ev, ensure_ascii=False) + "\n")
        json_out_handle.flush()

def detect_bruteforce(ev: dict, windows, threshold: int, window_sec: int, json_out_handle):
    """
    Keep a per-IP sliding window of FAIL timestamps; alert if count exceeds threshold.
    """
    if ev["type"] != "AUTH_FAIL":
        return

    ip = ev["src_ip"]
    t = time.time()
    dq = windows[ip]
    dq.append(t)
    # pop old entries outside window
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
        # optional: clear to avoid spamming; comment out if you want repeated alerts
       # windows[ip].clear()

def get_char() -> str:
    #set it to raw

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd);
        ch = sys.stdin.read(1);
    finally:
        #changes it back to the old setting undos the raw
        termios.settcattr(fd, termios.TCSADRAIN, old_settings)
    return ch;


def typing_test(duration: int) -> int:
    c = []
    print(f"you have these many {duration} seconds...")
    start = time.time();
    while time.time() - start < duration:
        ch = get_char();
        c.append(ch)
        #This shows the typed key live important to note.
        sys.stdout.write(ch)
        sys.stdout.flush()
    
    elapsed = time.time() - start
    count = len(c)
    cps = count / elapsed if elapsed > 0 else 0
    print(f"\n\nResults:\nTyped characters: {c}\nTotal: {count} chars in {elapsed:.2f}s\nAverage speed: {cps:.2f} chars/sec")

typing_test(10)



def read_head(path: str, lines: int = 50) -> None:
    """Print the first N lines to verify we can read the file."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                print(line.rstrip("\n"))
                if i + 1 >= lines:
                    break
    except FileNotFoundError:
        sys.stderr.write(f"[!] File not found: {path}\n")
        sys.exit(1)
    except PermissionError:
        sys.stderr.write(f"[!] Permission denied: {path}\nTry copying the log to data/raw first.\n")
        sys.exit(1)

def tail(path: str, poll_sec: float = 0.5,
         detect=False, threshold=5, window_sec=60,
         json_out: str | None = None) -> None:
    """Follow the file and process new lines. Handles rotation/truncation."""
    json_handle = open(json_out, "a", encoding="utf-8") if json_out else None
    windows = defaultdict(lambda: deque(maxlen=1024))  # per-IP time window

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, os.SEEK_END)
            inode = os.fstat(f.fileno()).st_ino

            while True:
                line = f.readline()
                if not line:
                    # detect rotation/truncation
                    try:
                        cur_inode = os.stat(path).st_ino
                        if cur_inode != inode or f.tell() > os.path.getsize(path):
                            # reopen
                            f.close()
                            f = open(path, "r", encoding="utf-8", errors="replace")
                            f.seek(0, os.SEEK_END)
                            inode = os.fstat(f.fileno()).st_ino
                    except FileNotFoundError:
                        # log temporarily missing during rotation
                        pass
                    time.sleep(poll_sec)
                    continue

                # process new line
                ev = parse_line(line)
                if ev:
                    emit_event(ev, json_handle)
                    if detect:
                        detect_bruteforce(ev, windows, threshold, window_sec, json_handle)

    except KeyboardInterrupt:
        print("\n[+] Stopping...")
    except FileNotFoundError:
        sys.stderr.write(f"[!] File not found: {path}\n")
        sys.exit(1)
    except PermissionError:
        sys.stderr.write(f"[!] Permission denied: {path}\nTry copying the log to data/raw first.\n")
        sys.exit(1)
    finally:
        if json_handle:
            json_handle.close()

def main():
    parser = argparse.ArgumentParser(description="Phase 1: Read or tail a log file.")
    parser.add_argument("--log-path", default="data/raw/auth.log",
                        help="Path to a log file (default: data/raw/auth.log)")
    parser.add_argument("--head", type=int, default=20,
                        help="Show the first N lines and exit (default: 20).")
    parser.add_argument("--follow", action="store_true",
                        help="Follow the file like `tail -f` (ignores --head).")
    # 🔽 new flags
    parser.add_argument("--detect", action="store_true",
                        help="Enable simple detection (SSH brute-force).")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Fails required to alert (default: 5).")
    parser.add_argument("--window-sec", type=int, default=60,
                        help="Time window for counting fails (default: 60s).")
    parser.add_argument("--json-out", default=None,
                        help="Write events/alerts as JSONL to this file.")
    args = parser.parse_args()

    if not os.path.exists(args.log_path):
        sys.stderr.write(f"[!] Path does not exist: {args.log_path}\n")
        sys.exit(1)

    if args.follow:
        print(f"[*] Following {args.log_path} (Ctrl+C to stop)...")
        tail(args.log_path, detect=args.detect, threshold=args.threshold,
             window_sec=args.window_sec, json_out=args.json_out)
    else:
        print(f"[*] Showing first {args.head} lines of {args.log_path}:\n")
        read_head(args.log_path, args.head)

if __name__ == "__main__":
    main()
