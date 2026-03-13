"""
data/generate_logs.py
---------------------
Synthetic Apache Log Generator for CyberWatch

Generates realistic fake server logs mixing normal traffic
and various attack patterns — so you can test the full
pipeline without needing a real server or downloading CICIDS.

Usage:
    python data/generate_logs.py                        # 1000 lines → data/access.log
    python data/generate_logs.py --lines 5000           # custom line count
    python data/generate_logs.py --output my_logs.log   # custom output path
    python data/generate_logs.py --attack-ratio 0.3     # 30% attack traffic
    python data/generate_logs.py --stream               # stream new lines every second (live mode test)
"""

import random
import argparse
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path


# ── Data pools ───────────────────────────────────────────

NORMAL_IPS = [f"10.0.{random.randint(0,5)}.{i}" for i in range(1, 40)]
ATTACK_IPS = [
    "192.168.0.21", "203.0.113.5", "45.33.32.156",
    "198.20.69.74", "185.220.101.3", "91.108.4.50",
    "172.16.99.1", "37.49.226.159"
]

NORMAL_URLS = [
    "/", "/index.html", "/about.html", "/contact.html",
    "/api/data", "/api/users", "/products", "/blog",
    "/assets/style.css", "/assets/app.js", "/favicon.ico",
    "/images/logo.png", "/search?q=test", "/dashboard",
]

LOGIN_URLS = ["/login", "/signin", "/auth/login", "/user/login"]

ATTACK_URLS = [
    "/wp-login.php", "/admin", "/phpmyadmin", "/.env",
    "/config.php", "/backup.zip", "/.git/config",
    "/shell.php", "/cmd.php", "/../../../etc/passwd",
    "/xmlrpc.php", "/wp-admin", "/manager/html",
    "/actuator/env", "/.aws/credentials",
]

NORMAL_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Chrome/120.0.0.0 Safari/537.36",
    "Safari/17.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17 like Mac OS X)",
]

ATTACK_AGENTS = [
    "python-requests/2.28.0",
    "nikto/2.1.6",
    "sqlmap/1.7.8",
    "curl/7.68.0",
    "go-http-client/1.1",
    "masscan/1.3",
    "zgrab/0.x",
    "dirbuster/1.0",
]

TIMESTAMP_FMT = "%d/%b/%Y:%H:%M:%S +0000"


# ── Log line builders ─────────────────────────────────────

def normal_line(ts: datetime) -> str:
    ip     = random.choice(NORMAL_IPS)
    method = random.choices(["GET", "POST"], weights=[85, 15])[0]
    url    = random.choice(NORMAL_URLS)
    status = random.choices([200, 304, 301, 404], weights=[80, 10, 5, 5])[0]
    size   = random.randint(512, 8192) if status == 200 else random.randint(128, 512)
    agent  = random.choice(NORMAL_AGENTS)
    return _fmt(ip, method, url, status, size, agent, ts)


def brute_force_burst(ts: datetime, n: int = 8) -> list[str]:
    """Simulate rapid repeated login failures from one IP."""
    ip    = random.choice(ATTACK_IPS)
    agent = random.choice(ATTACK_AGENTS)
    lines = []
    for i in range(n):
        t = ts + timedelta(seconds=i)
        lines.append(_fmt(ip, "POST", random.choice(LOGIN_URLS), 401, 512, agent, t))
    return lines


def port_scan_burst(ts: datetime, n: int = 15) -> list[str]:
    """Simulate scanning many endpoints rapidly."""
    ip    = random.choice(ATTACK_IPS)
    agent = random.choice(ATTACK_AGENTS)
    lines = []
    for i in range(n):
        t   = ts + timedelta(seconds=i * 0.3)
        url = random.choice(ATTACK_URLS)
        status = random.choice([404, 403, 200, 500])
        lines.append(_fmt(ip, "GET", url, status, 256, agent, t))
    return lines


def web_attack_line(ts: datetime) -> str:
    ip     = random.choice(ATTACK_IPS)
    url    = random.choice(ATTACK_URLS)
    agent  = random.choice(ATTACK_AGENTS)
    status = random.choice([403, 404, 500])
    return _fmt(ip, random.choice(["GET", "POST"]), url, status, 256, agent, ts)


def _fmt(ip, method, url, status, size, agent, ts):
    return (f'{ip} - - [{ts.strftime(TIMESTAMP_FMT)}] '
            f'"{method} {url} HTTP/1.1" {status} {size} "-" "{agent}"')


# ── Generator ─────────────────────────────────────────────

def generate(
    n_lines       : int   = 1000,
    attack_ratio  : float = 0.15,
    start_time    : datetime = None,
    speed_minutes : float = 60.0,   # simulate N minutes of traffic
) -> list[str]:
    """
    Generate a list of log lines mixing normal traffic and attacks.

    Parameters
    ----------
    n_lines       : total number of log lines
    attack_ratio  : fraction of lines that are attack-related (0.0 – 1.0)
    start_time    : timestamp of first entry (default: 6 hours ago)
    speed_minutes : how many minutes of traffic to simulate
    """
    if start_time is None:
        start_time = datetime.now(timezone.utc) - timedelta(hours=6)

    lines      = []
    n_attacks  = int(n_lines * attack_ratio)
    n_normal   = n_lines - n_attacks
    time_step  = timedelta(minutes=speed_minutes) / max(n_lines, 1)

    # Schedule attack events at random positions
    attack_positions = set(random.sample(range(n_lines), min(n_attacks, n_lines)))

    attack_types = ["brute_force", "port_scan", "web_attack"]
    attack_idx   = 0

    ts = start_time
    i  = 0

    while len(lines) < n_lines:
        ts += time_step

        if i in attack_positions:
            atype = attack_types[attack_idx % len(attack_types)]
            attack_idx += 1

            if atype == "brute_force" and len(lines) + 8 <= n_lines * 1.1:
                lines.extend(brute_force_burst(ts, n=random.randint(5, 10)))
            elif atype == "port_scan" and len(lines) + 15 <= n_lines * 1.1:
                lines.extend(port_scan_burst(ts, n=random.randint(8, 20)))
            else:
                lines.append(web_attack_line(ts))
        else:
            lines.append(normal_line(ts))

        i += 1

    # Shuffle slightly to mix attack/normal (but keep rough chronological order)
    chunk = 20
    shuffled = []
    for start in range(0, len(lines), chunk):
        block = lines[start:start + chunk]
        random.shuffle(block)
        shuffled.extend(block)

    return shuffled[:n_lines]


def write_log(lines: list[str], output_path: str):
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[Generator] ✅  Wrote {len(lines)} lines → {output_path}")


def stream_log(output_path: str, attack_ratio: float = 0.15, interval: float = 0.5):
    """
    Append new log lines to a file in real time — for testing live tail mode.
    Ctrl+C to stop.
    """
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    print(f"[Generator] Streaming to {output_path} (Ctrl+C to stop)...")
    count = 0
    try:
        while True:
            ts  = datetime.utcnow()
            roll = random.random()
            if roll < attack_ratio * 0.3:
                new_lines = brute_force_burst(ts, n=random.randint(3, 6))
            elif roll < attack_ratio:
                new_lines = [web_attack_line(ts)]
            else:
                new_lines = [normal_line(ts)]

            with open(output_path, "a", encoding="utf-8") as f:
                f.write("\n".join(new_lines) + "\n")

            count += len(new_lines)
            if count % 50 == 0:
                print(f"[Generator] {count} lines written...")
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n[Generator] Stopped. Total lines written: {count}")


# ── CLI ───────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic Apache logs for CyberWatch")
    parser.add_argument("--lines",        type=int,   default=1000,              help="Number of log lines to generate")
    parser.add_argument("--output",       type=str,   default="data/access.log", help="Output file path")
    parser.add_argument("--attack-ratio", type=float, default=0.15,              help="Fraction of attack traffic (0.0–1.0)")
    parser.add_argument("--stream",       action="store_true",                   help="Stream new lines every 0.5s (for live tail testing)")
    parser.add_argument("--interval",     type=float, default=0.5,               help="Stream interval in seconds")
    args = parser.parse_args()

    if args.stream:
        stream_log(args.output, attack_ratio=args.attack_ratio, interval=args.interval)
    else:
        lines = generate(n_lines=args.lines, attack_ratio=args.attack_ratio)
        write_log(lines, args.output)

        # Show a quick preview
        attack_lines = [l for l in lines if any(a in l for a in ["401","403","wp-login","admin","sqlmap","nikto","python-requests"])]
        print(f"[Generator] Attack lines in output: ~{len(attack_lines)} / {len(lines)}")
        print("[Generator] Sample attack line:")
        if attack_lines:
            print(" ", attack_lines[0])
