# siem_phase1_read.py
import argparse
import os
import sys
import time

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



def tail(path: str, poll_sec: float = 0.5) -> None:
    """Follow the file and print new lines as they’re written (like `tail -f`)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            # Seek to the end of the file so we only see new lines meaning we have to wait for new lines
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(poll_sec)
                else:
                    print(line.rstrip("\n"))

    except FileNotFoundError:
        sys.stderr.write(f"[!] File not found: {path}\n")
        sys.exit(1)
    except PermissionError:
        sys.stderr.write(f"[!] Permission denied: {path}\nTry copying the log to data/raw first.\n")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Phase 1: Read or tail a log file.")
    parser.add_argument("--log-path", default="data/raw/auth.log",
                        help="Path to a log file (default: data/raw/auth.log)")
    parser.add_argument("--head", type=int, default=20,
                        help="Show the first N lines and exit (default: 20).")
    parser.add_argument("--follow", action="store_true",
                        help="Follow the file like `tail -f` (ignores --head).")
    args = parser.parse_args()

    if not os.path.exists(args.log_path):
        sys.stderr.write(f"[!] Path does not exist: {args.log_path}\n")
        sys.exit(1)

    if args.follow:
        print(f"[*] Following {args.log_path} (Ctrl+C to stop)...")
        tail(args.log_path)
    else:
        print(f"[*] Showing first {args.head} lines of {args.log_path}:\n")
        read_head(args.log_path, args.head)

if __name__ == "__main__":
    main()
