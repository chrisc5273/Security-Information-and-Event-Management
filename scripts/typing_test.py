import sys, tty, termios, time

def get_char() -> str:
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch

def typing_test(duration: int) -> None:
    chars = []
    print(f"You have {duration} seconds...")
    start = time.time()
    while time.time() - start < duration:
        ch = get_char()
        chars.append(ch)
        sys.stdout.write(ch)
        sys.stdout.flush()
    elapsed = time.time() - start
    cps = len(chars) / elapsed if elapsed > 0 else 0
    print(f"\n\nResults:\nTotal: {len(chars)} chars in {elapsed:.2f}s\nAverage: {cps:.2f} chars/sec")

if __name__ == "__main__":
    typing_test(10)
