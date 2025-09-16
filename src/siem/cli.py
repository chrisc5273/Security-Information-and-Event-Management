from __future__ import annotations
import argparse
import os
import sys
from . import io
from siem.config import load_config
def main() -> None:
    parser = argparse.ArgumentParser(description="SIEM-Lite: read or tail a log file.")
    parser.add_argument("--log-path", default="data/raw/auth.log",
                        help="Path to a log file (default: data/raw/auth.log)")
    parser.add_argument("--head", type=int, default=20,
                        help="Show the first N lines and exit (default: 20).")
    parser.add_argument("--follow", action="store_true",
                        help="Follow the file like `tail -f` (ignores --head).")
    parser.add_argument("--detect", action="store_true",
                        help="Enable simple detection (SSH brute-force).")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Fails required to alert (default: 5).")
    parser.add_argument("--window-sec", type=int, default=60,
                        help="Time window for counting fails (default: 60s).")
    parser.add_argument("--json-out", default=None,
                        help="Write events/alerts as JSONL to this file.")
    parser.add_argument("--config",default = "configs/default.yml" )
    
    cfg = load_config(args.config)
    thresh = cfg["thresholds"]["bruteforce"]["fails"]
    win    = cfg["thresholds"]["bruteforce"]["window_seconds"]
    args = parser.parse_args()

    if args.threshold:   thresh = args.threshold
    if args.window_sec:  win    = args.window_sec

    if not os.path.exists(args.log_path):
        sys.stderr.write(f"[!] Path does not exist: {args.log_path}\n")
        sys.exit(1)

    if args.follow:
        print(f"[*] Following {args.log_path} (Ctrl+C to stop)...")
        io.tail(args.log_path,
                detect=args.detect,
                threshold=args.threshold,
                window_sec=args.window_sec,
                json_out=args.json_out)
    else:
        print(f"[*] Showing first {args.head} lines of {args.log_path}:\n")
        io.read_head(args.log_path, args.head)

if __name__ == "__main__":
    main()
