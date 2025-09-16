from __future__ import annotations
import os
import sys
import time
import json
from collections import defaultdict, deque
from typing import TextIO
from .enrich import enrich_event
from .parse import parse_line
from .alert import emit_event
from .detect import detect_bruteforce

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

def tail(path: str,
         poll_sec: float = 0.5,
         detect: bool = False,
         threshold: int = 5,
         window_sec: int = 60,
         json_out: str | None = None) -> None:
    """Follow the file and process new lines. Handles rotation/truncation."""
    json_handle: TextIO | None = open(json_out, "a", encoding="utf-8") if json_out else None
    windows: "defaultdict[str, deque[float]]" = defaultdict(lambda: deque(maxlen=1024))

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, os.SEEK_END)
            #This part gives you the inode of the file you opened earlier (even if the path later points to a different file). different than os.stat(path)
            inode = os.fstat(f.fileno()).st_ino

            while True:
                line = f.readline()
                if not line:
                    # detect rotation/truncation
                    try:
                        #if the inode of the file at this path is different from the one we originally opened, it means log rotation happened (new file replaced the old one).
                        cur_inode = os.stat(path).st_ino
                        #Checks whether or not file was truncated so if it was reading at line 9800 and all of a sudden file size is 0. It wont read anymore lines
                        if cur_inode != inode or f.tell() > os.path.getsize(path):
                            f.close()
                            f = open(path, "r", encoding="utf-8", errors="replace")
                            f.seek(0, os.SEEK_END)
                            inode = os.fstat(f.fileno()).st_ino
                    except FileNotFoundError:
                        pass
                    time.sleep(poll_sec)
                    continue

                ev = parse_line(line)
                if ev:
                    ev = enrich_event(ev)  # <-- add enrichment here
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
