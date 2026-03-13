"""
agents/analyzer.py
------------------
Agent 2 — Log Analyzer

Consumes raw log lines from Agent 1's queue.
Parses each line, batches entries, runs feature engineering,
then pushes enriched DataFrames to Agent 3's queue.

Pattern detection (rule-based, before ML):
  - Brute force login (5+ auth failures from same IP in 60s)
  - High error rate IP (>80% errors)
  - Suspicious user agents (scanners, bots)
  - Rapid request bursts
"""

import queue
import threading
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
import sys

# Allow running from project root
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.parser import parse_line, extract_features


# Known scanner / attack tool user-agent fragments
SUSPICIOUS_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab",
    "dirbuster", "gobuster", "wfuzz", "hydra",
    "python-requests", "go-http-client", "curl/",
]

class LogAnalyzerAgent:
    """
    Agent 2 — parses + enriches log lines, detects rule-based patterns.

    Parameters
    ----------
    in_queue   : queue from Agent 1 (raw log line dicts)
    out_queue  : queue to Agent 3 (enriched DataFrames)
    batch_size : how many lines to accumulate before forwarding (default 20)
    window_sec : time window (seconds) for burst/brute-force detection
    """

    def __init__(
        self,
        in_queue   : queue.Queue,
        out_queue  : queue.Queue,
        batch_size : int   = 20,
        window_sec : int   = 60,
    ):
        self.in_queue   = in_queue
        self.out_queue  = out_queue
        self.batch_size = batch_size
        self.window_sec = window_sec

        self._stop_event = threading.Event()
        self._thread     = None

        # Rolling window tracking per IP
        self._ip_window: dict[str, list[datetime]] = defaultdict(list)
        self._ip_auth_fails: dict[str, list[datetime]] = defaultdict(list)

        self.lines_parsed  = 0
        self.lines_skipped = 0
        self.alerts_raised = 0

    # ── public API ──────────────────────────────────────

    def start(self):
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        print("[Analyzer] Started — waiting for log lines...")

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        print(f"[Analyzer] Stopped. Parsed: {self.lines_parsed}, Skipped: {self.lines_skipped}")

    def analyze_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Synchronous version — analyze a pre-built DataFrame directly.
        Used in batch/offline mode (e.g. loading CICIDS CSV).
        """
        df = extract_features(df)
        df = self._apply_rule_alerts(df)
        return df

    # ── internal loop ───────────────────────────────────

    def _run_loop(self):
        """Consume from queue, parse lines, batch and forward."""
        batch = []

        while not self._stop_event.is_set():
            try:
                item = self.in_queue.get(timeout=1)
            except queue.Empty:
                if batch:
                    self._flush(batch)
                    batch = []
                continue

            # Sentinel from collector signals end of file
            if item is None:
                if batch:
                    self._flush(batch)
                self.out_queue.put(None)
                break

            parsed = parse_line(item["raw"])
            if not parsed:
                self.lines_skipped += 1
                continue

            parsed["collected_at"] = item["ts"]
            batch.append(parsed)
            self.lines_parsed += 1

            if len(batch) >= self.batch_size:
                self._flush(batch)
                batch = []

    def _flush(self, batch: list[dict]):
        """Convert batch to DataFrame, run feature engineering, push forward."""
        df = pd.DataFrame(batch)
        df = extract_features(df)
        df = self._apply_rule_alerts(df)
        self.out_queue.put(df)
        print(f"[Analyzer] Flushed {len(df)} entries → Agent 3")

    # ── rule-based pattern detection ────────────────────

    def _apply_rule_alerts(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Add a 'rule_alert' column with any triggered rule names.
        These complement the ML model scores in Agent 3.
        """
        df = df.copy()
        df["rule_alert"] = ""

        # Rule 1: Brute force — 5+ auth failures from same IP
        if "is_auth_fail" in df.columns and "ip" in df.columns:
            fail_counts = df[df["is_auth_fail"]].groupby("ip").size()
            brute_ips   = fail_counts[fail_counts >= 5].index
            mask = df["ip"].isin(brute_ips)
            df.loc[mask, "rule_alert"] = df.loc[mask, "rule_alert"].apply(
                lambda x: (x + ",brute_force").lstrip(",")
            )
            if mask.any():
                print(f"[Analyzer] ⚠ Brute force detected from: {list(brute_ips)}")
                self.alerts_raised += mask.sum()

        # Rule 2: High error rate IP (>80% errors, at least 5 requests)
        if "error_rate_ip" in df.columns and "ip_total_requests" in df.columns:
            mask = (df["error_rate_ip"] > 0.80) & (df["ip_total_requests"] >= 5)
            df.loc[mask, "rule_alert"] = df.loc[mask, "rule_alert"].apply(
                lambda x: (x + ",high_error_rate").lstrip(",")
            )

        # Rule 3: Suspicious user agent
        if "agent" in df.columns:
            def check_agent(ua):
                if not isinstance(ua, str):
                    return False
                ua_lower = ua.lower()
                return any(s in ua_lower for s in SUSPICIOUS_AGENTS)

            mask = df["agent"].apply(check_agent)
            df.loc[mask, "rule_alert"] = df.loc[mask, "rule_alert"].apply(
                lambda x: (x + ",suspicious_agent").lstrip(",")
            )

        # Rule 4: Off-hours access (midnight to 5am)
        if "hour" in df.columns:
            mask = df["hour"].between(0, 4)
            df.loc[mask, "rule_alert"] = df.loc[mask, "rule_alert"].apply(
                lambda x: (x + ",off_hours").lstrip(",")
            )

        return df

    def status(self) -> dict:
        return {
            "agent"         : "LogAnalyzer",
            "lines_parsed"  : self.lines_parsed,
            "lines_skipped" : self.lines_skipped,
            "alerts_raised" : self.alerts_raised,
            "queue_size"    : self.out_queue.qsize(),
            "running"       : self._thread.is_alive() if self._thread else False,
        }
