# siem_phase2_monitor.py
import argparse
import os
import sys
import time
import re
import json
from collections import defaultdict, deque
from datetime import datetime

# ---------- helpers ----------
def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def extract_ip(line: str) -> str | None:
    m = IP_RE.search(line)
    return m.group(0) if m else None

def compile_patterns(patterns: list[str] | None, flags: int) -> list[re.Pattern]:
    if not patterns:
        return []
    return [re.compile(p, flags) for p in patterns]

def matches_any(line: str, pats: list[re.Pattern]) -> bool:
    return any(p.search(line) for p in pats)

# ---------- core I/O ----------
def read_head(path: str, lines: int = 50,
              include_pats=None, exclude_pat=None,
              save_raw=None, save_json=None,
              ci=False):
    """Print first N lines that pass filters; optionally save."""
    flags = re.IGNORECASE if ci else 0
    inc = compile_patterns(include_pats, flags)
    exc = re.compile(exclude_pat, flags) if exclude_pat else None

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            shown = 0
            for line in f:
                if _filter_line(line, inc, exc):
                    _emit(line, save_raw, save_json, rule="head")
                    shown += 1
                    if shown >= lines:
                        break
    except FileNotFoundError:
        sys.stderr.write(f"[!] File not found: {path}\n")
        sys.exit(1)
    except PermissionError:
        sys.stderr.write(f"[!] Permission denied: {path}\nTry copying the log to data/raw first.\n")
        sys.exit(1)

def tail(path: str, poll_sec: float = 0.5,
         include_pats=None, exclude_pat=None,
         threshold: int = 0, window_sec: int = 60,
         save_raw=None, save_json=None, ci=False):
    """Follow the file; filter lines; raise alerts on thresholds."""
    flags = re.IGNORECASE if ci else 0
    inc = compile_patterns(include_pats, flags)
    exc = re.compile(exclude_pat, flags) if exclude_pat else None

    # Per-IP sliding windows of timestamps
    buckets: dict[str, deque[float]] = defaultdict(deque)
    window = float(window_sec)
    use_thresholds = threshold > 0

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            # Start at EOF so we only see new lines
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(poll_sec)
                    continue

                if not _filter_line(line, inc, exc):
                    continue

                # Emit the matched line
                _emit(line, save_raw, save_json, rule="match")

                # Threshold logic (e.g., brute force detector)
                if use_thresholds:
                    ip = extract_ip(line) or "unknown"
                    now = time.time()
                    dq = buckets[ip]
                    dq.append(now)
                    # drop old timestamps outside the window
                    while dq and (now - dq[0]) > window:
                        dq.popleft()
                    if len(dq) >= threshold:
                        _alert(ip, len(dq), window_sec, save_raw, save_json)
    except FileNotFoundError:
        sys.stderr.write(f"[!] File not found: {path}\n")
        sys.exit(1)
    except PermissionError:
        sys.stderr.write(f"[!] Permission denied: {path}\nTry copying the log to data/raw first.\n")
        sys.exit(1)

# ---------- filtering & output ----------
def _filter_line(line: str, include_pats, exclude_pat) -> bool:
    if include_pats and not matches_any(line, include_pats):
        return False
    if exclude_pat and exclude_pat.search(line):
        return False
    return True

def _emit(line: str, save_raw: str | None, save_json: str | None, rule: str):
    msg = line.rstrip("\n")
    print(msg)
    if save_raw:
        with open(save_raw, "a", encoding="utf-8") as wf:
            wf.write(msg + "\n")
    if save_json:
        rec = {
            "ts": now_iso(),
            "message": msg,
            "rule": rule,
            "ip": extract_ip(msg)
        }
        with open(save_json, "a", encoding="utf-8") as jf:
            jf.write(json.dumps(rec) + "\n")

def _alert(ip: str, count: int, window_sec: int, save_raw: str | None, save_json: str | None):
    text = f"[ALERT] {ip} reached {count} events in {window_sec}s"
    print(text, file=sys.stderr)
    if save_raw:
        with open(save_raw, "a", encoding="utf-8") as wf:
            wf.write(text + "\n")
    if save_json:
        rec = {"ts": now_iso(), "severity": "ALERT", "ip": ip, "count": count, "window_sec": window_sec}
        with open(save_json, "a", encoding="utf-8") as jf:
            jf.write(json.dumps(rec) + "\n")

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="Phase 2: Filter, follow, and alert on logs.")
    parser.add_argument("--log-path", default="data/raw/auth.log",
                        help="Path to a log file (default: data/raw/auth.log)")
    parser.add_argument("--head", type=int, default=20,
                        help="Show the first N lines that match filters and exit (default: 20).")
    parser.add_argument("--follow", action="store_true",
                        help="Follow the file like `tail -f` (ignores --head).")

    # Filtering
    parser.add_argument("--include", action="append",
                        help="Regex to include (can repeat). Example: --include 'Failed password' --include 'Invalid user'")
    parser.add_argument("--exclude",
                        help="Regex to exclude.")
    parser.add_argument("--ci", action="store_true",
                        help="Case-insensitive matching.")

    # Threshold alerting
    parser.add_argument("--threshold", type=int, default=0,
                        help="Trigger alert after N matching events per IP within the window (0=off).")
    parser.add_argument("--window", type=int, default=60,
                        help="Time window in seconds for threshold (default: 60).")

    # Saving
    parser.add_argument("--save", help="Append matched lines and alerts to this file.")
    parser.add_argument("--json", help="Append JSON records of matches/alerts to this file.")

    args = parser.parse_args()

    if not os.path.exists(args.log_path):
        sys.stderr.write(f"[!] Path does not exist: {args.log_path}\n")
        sys.exit(1)

    if args.follow:
        print(f"[*] Following {args.log_path} with filters (Ctrl+C to stop)...")
        tail(
            args.log_path,
            include_pats=args.include,
            exclude_pat=args.exclude,
            threshold=args.threshold,
            window_sec=args.window,
            save_raw=args.save,
            save_json=args.json,
            ci=args.ci,
        )
    else:
        print(f"[*] Showing first {args.head} matching line(s) of {args.log_path}:\n")
        read_head(
            args.log_path,
            lines=args.head,
            include_pats=args.include,
            exclude_pat=args.exclude,
            save_raw=args.save,
            save_json=args.json,
            ci=args.ci,
        )

if __name__ == "__main__":
    main()
