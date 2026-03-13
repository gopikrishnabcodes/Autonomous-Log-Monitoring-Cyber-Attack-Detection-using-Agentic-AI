"""
main.py
-------
Orchestrator — wires all 4 agents together and runs the pipeline.

Usage:
  python main.py --log data/access.log        # batch mode (file)
  python main.py --tail data/access.log       # live tail mode
  python main.py --csv  data/cicids.csv       # CICIDS 2017 CSV mode
  python main.py --demo                       # built-in demo with synthetic logs
"""

import queue
import argparse

# Load .env file if present (set EMAIL, SLACK, etc.)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed — use os.environ directly
import time
import sys
import pandas as pd
from pathlib import Path
from datetime import datetime

from agents.collector    import LogCollectorAgent
from agents.analyzer     import LogAnalyzerAgent
from agents.threat_agent import ThreatDetectionAgent
from agents.alert_agent  import AlertAgent, AlertConfig
from utils.parser        import parse_csv_log, extract_features
from ml.train_model      import train_isolation_forest, MODEL_PATH


def run_batch(log_path: str):
    """Mode 1: read a complete Apache log file."""
    print(f"\n[Main] Batch mode → {log_path}")

    q1 = queue.Queue()   # Collector → Analyzer
    q2 = queue.Queue()   # Analyzer  → ThreatAgent
    q3 = queue.Queue()   # ThreatAgent → AlertAgent

    collector = LogCollectorAgent(log_path, q1)
    analyzer  = LogAnalyzerAgent(q1, q2, batch_size=50)
    threat    = ThreatDetectionAgent(q2, q3, threshold=0.60)
    alert     = AlertAgent(q3, AlertConfig())

    analyzer.start()
    threat.start()
    alert.start()

    collector.run_batch()     # blocks until file is fully read

    # Wait for pipeline to drain
    time.sleep(3)

    analyzer.stop()
    threat.stop()
    alert.stop()

    _print_summary([collector, analyzer, threat, alert])


def run_tail(log_path: str):
    """Mode 2: tail a live log file (Ctrl+C to stop)."""
    print(f"\n[Main] Tail mode → {log_path} (Ctrl+C to stop)")

    q1 = queue.Queue()
    q2 = queue.Queue()
    q3 = queue.Queue()

    collector = LogCollectorAgent(log_path, q1, poll_interval=0.5)
    analyzer  = LogAnalyzerAgent(q1, q2, batch_size=10)
    threat    = ThreatDetectionAgent(q2, q3)
    alert     = AlertAgent(q3, AlertConfig())

    analyzer.start()
    threat.start()
    alert.start()
    collector.start_tail()

    try:
        while True:
            time.sleep(5)
            _print_status([collector, analyzer, threat, alert])
    except KeyboardInterrupt:
        print("\n[Main] Interrupted.")
    finally:
        collector.stop()
        analyzer.stop()
        threat.stop()
        alert.stop()


def run_csv(csv_path: str):
    """Mode 3: process a CICIDS-style labeled CSV (offline)."""
    print(f"\n[Main] CSV mode → {csv_path}")

    df = parse_csv_log(csv_path)

    # Map CICIDS columns to our feature names if needed
    cicids_map = {
        "Flow Duration"         : "size",
        "Total Fwd Packets"     : "ip_total_requests",
        "Total Backward Packets": "ip_error_count",
        "Destination Port"      : "status",
        "Flow Packets/s"        : "error_rate_ip",
    }
    df = df.rename(columns={k: v for k, v in cicids_map.items() if k in df.columns})

    # Fill required cols that CICIDS doesn't have
    for col in ["ip", "hour", "url", "is_error", "is_auth_fail",
                "login_attempt", "is_new_ip", "agent"]:
        if col not in df.columns:
            df[col] = 0

    # Train model on this data if no model exists
    if not MODEL_PATH.exists():
        print("[Main] No model found — training on CSV data...")
        train_isolation_forest(df)

    # Run agents synchronously (no threads needed for batch)
    from agents.analyzer     import LogAnalyzerAgent
    from agents.threat_agent import ThreatDetectionAgent
    from agents.alert_agent  import AlertAgent, AlertConfig

    analyzer = LogAnalyzerAgent(queue.Queue(), queue.Queue())
    threat   = ThreatDetectionAgent(queue.Queue(), queue.Queue())
    alert    = AlertAgent(queue.Queue(), AlertConfig())

    df_analyzed = analyzer.analyze_dataframe(df)
    df_scored   = threat.score_dataframe(df_analyzed)
    threats     = df_scored[df_scored["threat_level"].isin(["WATCH", "ALERT"])]

    alert.handle_dataframe(threats)
    print(f"\n[Main] Done. {len(threats)} threats found in {len(df)} records.")


def run_demo():
    """Mode 4: synthetic demo — no real log file needed."""
    print("\n[Main] Demo mode — generating synthetic attack scenario...\n")

    import tempfile, os

    # Mix of normal traffic + attack patterns
    sample_lines = [
        # Normal traffic
        '10.0.0.1 - - [13/Mar/2026:09:01:00 +0000] "GET /index.html HTTP/1.1" 200 2048 "-" "Mozilla/5.0"',
        '10.0.0.2 - - [13/Mar/2026:09:01:01 +0000] "GET /about.html HTTP/1.1" 200 1024 "-" "Chrome/120"',
        '10.0.0.3 - - [13/Mar/2026:09:01:05 +0000] "GET /api/data HTTP/1.1" 200 4096 "-" "axios/1.0"',
        # Brute force from 192.168.0.21
        '192.168.0.21 - - [13/Mar/2026:02:42:10 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
        '192.168.0.21 - - [13/Mar/2026:02:42:11 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
        '192.168.0.21 - - [13/Mar/2026:02:42:12 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
        '192.168.0.21 - - [13/Mar/2026:02:42:13 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
        '192.168.0.21 - - [13/Mar/2026:02:42:14 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
        '192.168.0.21 - - [13/Mar/2026:02:42:15 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
        # Port scan from 203.0.113.5
        '203.0.113.5 - - [13/Mar/2026:02:43:00 +0000] "GET /wp-login.php HTTP/1.1" 404 256 "-" "nikto/2.1"',
        '203.0.113.5 - - [13/Mar/2026:02:43:01 +0000] "GET /phpmyadmin HTTP/1.1" 404 256 "-" "nikto/2.1"',
        '203.0.113.5 - - [13/Mar/2026:02:43:02 +0000] "GET /admin HTTP/1.1" 403 256 "-" "nikto/2.1"',
        # Normal again
        '10.0.0.4 - - [13/Mar/2026:09:10:00 +0000] "GET /products HTTP/1.1" 200 3072 "-" "Safari/17"',
    ]

    # Write to temp file and run batch
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("\n".join(sample_lines))
        tmp = f.name

    # Need a model — train on synthetic data first
    if not MODEL_PATH.exists():
        from utils.parser import parse_log_file, extract_features as ef
        df_train = parse_log_file(tmp)
        df_train = ef(df_train)
        train_isolation_forest(df_train, contamination=0.3)

    run_batch(tmp)
    os.unlink(tmp)


def _print_status(agents):
    print(f"\n[Main] ── Status @ {datetime.now().strftime('%H:%M:%S')} ──")
    for a in agents:
        s = a.status()
        print(f"  {s['agent']:<25}", end="")
        for k, v in list(s.items())[1:]:
            print(f" | {k}: {v}", end="")
        print()


def _print_summary(agents):
    print("\n" + "═"*52)
    print("  Pipeline Summary")
    print("═"*52)
    for a in agents:
        s = a.status()
        print(f"  {s['agent']}")
        for k, v in list(s.items())[1:]:
            print(f"    {k:<22}: {v}")
    print("═"*52)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cyber Log Monitor")
    parser.add_argument("--log",  help="Batch mode: Apache log file path")
    parser.add_argument("--tail", help="Live mode: tail a log file")
    parser.add_argument("--csv",  help="CSV mode: CICIDS or structured CSV")
    parser.add_argument("--demo", action="store_true", help="Run built-in demo")
    args = parser.parse_args()

    if args.demo:
        run_demo()
    elif args.log:
        run_batch(args.log)
    elif args.tail:
        run_tail(args.tail)
    elif args.csv:
        run_csv(args.csv)
    else:
        print("No mode specified. Running demo...\n")
        run_demo()
