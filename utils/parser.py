"""
utils/parser.py
---------------
Log Parser for Autonomous Log Monitoring & Cyber Attack Detection
Parses raw Apache / HTTP Combined Log Format into a structured DataFrame.

Supports:
  - Apache Combined Log Format
  - Nginx access logs
  - Generic HTTP access logs
  - Pre-structured CSV logs (e.g. CICIDS 2017)
"""

import re
import pandas as pd
from datetime import datetime
from pathlib import Path


# ─────────────────────────────────────────────
# Apache / Nginx Combined Log Format pattern
# Example line:
#   192.168.1.1 - john [12/Oct/2023:10:23:45 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
# ─────────────────────────────────────────────
APACHE_PATTERN = re.compile(
    r'(?P<ip>\S+)'            # IP address
    r'\s+\S+'                 # ident (usually -)
    r'\s+(?P<user>\S+)'       # auth user
    r'\s+\[(?P<time>[^\]]+)\]'  # timestamp
    r'\s+"(?P<method>\S+)'    # HTTP method
    r'\s+(?P<url>\S+)'        # URL path
    r'\s+(?P<protocol>[^"]+)"'  # protocol
    r'\s+(?P<status>\d{3})'   # status code
    r'\s+(?P<size>\S+)'       # response size
    r'(?:\s+"(?P<referer>[^"]*)")?'   # referer (optional)
    r'(?:\s+"(?P<agent>[^"]*)")?'     # user agent (optional)
)

TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_line(line: str) -> dict | None:
    """
    Parse a single Apache/Nginx log line.
    Returns a dict of fields, or None if the line doesn't match.
    """
    match = APACHE_PATTERN.match(line.strip())
    if not match:
        return None

    data = match.groupdict()

    # Parse timestamp → Python datetime
    try:
        data["timestamp"] = datetime.strptime(data["time"], TIMESTAMP_FORMAT)
    except ValueError:
        data["timestamp"] = None
    del data["time"]

    # Convert numeric fields
    data["status"] = int(data["status"])
    data["size"] = int(data["size"]) if data["size"] != "-" else 0

    # Normalise user field
    data["user"] = None if data["user"] == "-" else data["user"]

    return data


def parse_log_file(filepath: str) -> pd.DataFrame:
    """
    Read an Apache/Nginx log file and return a structured DataFrame.

    Parameters
    ----------
    filepath : str
        Path to the .log or .txt file.

    Returns
    -------
    pd.DataFrame with columns:
        ip, user, timestamp, method, url, protocol,
        status, size, referer, agent
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {filepath}")

    records = []
    skipped = 0

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            parsed = parse_line(line)
            if parsed:
                records.append(parsed)
            else:
                skipped += 1

    if skipped > 0:
        print(f"[parser] Skipped {skipped} unmatched lines.")

    df = pd.DataFrame(records)

    if df.empty:
        print("[parser] Warning: no lines matched the Apache log format.")
        return df

    # Sort by timestamp ascending
    if "timestamp" in df.columns:
        df = df.sort_values("timestamp").reset_index(drop=True)

    print(f"[parser] Parsed {len(df)} log entries from {path.name}")
    return df


def parse_csv_log(filepath: str) -> pd.DataFrame:
    """
    Load a pre-structured CSV log file (e.g. CICIDS 2017).
    Strips whitespace from column names automatically.

    Parameters
    ----------
    filepath : str
        Path to the .csv file.

    Returns
    -------
    pd.DataFrame
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"CSV file not found: {filepath}")

    df = pd.read_csv(path, low_memory=False)

    # Clean column names (CICIDS has leading spaces in headers)
    df.columns = df.columns.str.strip()

    print(f"[parser] Loaded CSV: {len(df)} rows, {len(df.columns)} columns from {path.name}")
    return df


# ─────────────────────────────────────────────
# Feature extraction
# Adds derived columns useful for ML & agents
# ─────────────────────────────────────────────

def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Given a parsed Apache log DataFrame, engineer features
    needed by the ML threat detection model.

    New columns added:
        hour            - hour of request (0-23)
        is_error        - True if status >= 400
        is_auth_fail    - True if status 401 or 403
        login_attempt   - True if URL contains /login or /signin
        req_per_min_ip  - rolling requests per minute per IP
        error_rate_ip   - fraction of errors per IP (over full dataset)
        is_new_ip       - True if IP only appears once in dataset
    """
    if df.empty:
        return df

    df = df.copy()

    # Time-based features
    if "timestamp" in df.columns:
        df["hour"] = df["timestamp"].dt.hour

    # Status-based features
    df["is_error"] = df["status"] >= 400
    df["is_auth_fail"] = df["status"].isin([401, 403])

    # URL-based features
    login_pattern = r"/(?:login|signin|auth|admin|wp-login)"
    df["login_attempt"] = df["url"].str.contains(login_pattern, case=False, regex=True, na=False)

    # Per-IP aggregations
    ip_counts = df.groupby("ip").size().rename("ip_total_requests")
    ip_errors = df[df["is_error"]].groupby("ip").size().rename("ip_error_count")

    df = df.join(ip_counts, on="ip")
    df = df.join(ip_errors, on="ip")
    df["ip_error_count"] = df["ip_error_count"].fillna(0)
    df["error_rate_ip"] = df["ip_error_count"] / df["ip_total_requests"]

    # Flag IPs that appear only once (rare / new source)
    df["is_new_ip"] = df["ip_total_requests"] == 1

    print(f"[parser] Feature extraction complete. Shape: {df.shape}")
    return df


# ─────────────────────────────────────────────
# Quick test — run this file directly to verify
# ─────────────────────────────────────────────

def _generate_sample_logs() -> list[str]:
    """Generate a few sample Apache log lines for testing."""
    return [
        '192.168.1.10 - - [12/Oct/2023:10:23:45 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        '192.168.1.10 - - [12/Oct/2023:10:23:46 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '192.168.1.10 - - [12/Oct/2023:10:23:47 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '192.168.1.10 - - [12/Oct/2023:10:23:48 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '10.0.0.5 - admin [12/Oct/2023:10:24:01 +0000] "GET /dashboard HTTP/1.1" 200 4096 "-" "curl/7.68"',
        '203.0.113.99 - - [12/Oct/2023:10:25:10 +0000] "GET /wp-login.php HTTP/1.1" 404 256 "-" "python-requests/2.28"',
        'INVALID LINE THAT SHOULD BE SKIPPED',
    ]


if __name__ == "__main__":
    import tempfile, os

    # Write sample lines to a temp file
    sample_lines = _generate_sample_logs()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("\n".join(sample_lines))
        tmp_path = f.name

    print("=" * 50)
    print("Testing parse_log_file()")
    print("=" * 50)
    df = parse_log_file(tmp_path)
    print(df[["ip", "method", "url", "status", "timestamp"]].to_string(index=False))

    print("\n" + "=" * 50)
    print("Testing extract_features()")
    print("=" * 50)
    df_feat = extract_features(df)
    cols = ["ip", "status", "login_attempt", "is_auth_fail", "error_rate_ip", "is_new_ip"]
    print(df_feat[cols].to_string(index=False))

    os.unlink(tmp_path)
    print("\n[parser] All tests passed.")
