"""
agents/alert_agent.py
---------------------
Agent 4 — Alert Agent (Notifier fully wired in)

Reads from Agent 3 queue. For every threat:
  WATCH  → log file + CSV
  ALERT  → log + CSV + terminal box + Email + Slack + optional IP block

All credentials loaded automatically from .env file.
"""

import queue
import csv
import os
import threading
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
import pandas as pd
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))


def _load_env():
    env_path = Path(__file__).parent.parent / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

_load_env()


@dataclass
class AlertConfig:
    log_file           : str  = os.getenv("LOG_FILE",            "logs/alerts.log")
    csv_file           : str  = os.getenv("CSV_FILE",            "logs/alerts.csv")
    email_enabled      : bool = os.getenv("EMAIL_ENABLED",       "false").lower() == "true"
    smtp_host          : str  = os.getenv("SMTP_HOST",           "smtp.gmail.com")
    smtp_port          : int  = int(os.getenv("SMTP_PORT",       "587"))
    smtp_user          : str  = os.getenv("SMTP_USER",           "")
    smtp_password      : str  = os.getenv("SMTP_PASSWORD",       "")
    alert_email_to     : str  = os.getenv("ALERT_EMAIL_TO",      "")
    email_min_level    : str  = os.getenv("EMAIL_MIN_LEVEL",     "ALERT")
    slack_enabled      : bool = os.getenv("SLACK_ENABLED",       "false").lower() == "true"
    slack_webhook_url  : str  = os.getenv("SLACK_WEBHOOK_URL",   "")
    slack_min_level    : str  = os.getenv("SLACK_MIN_LEVEL",     "ALERT")
    ip_blocking_enabled: bool = os.getenv("IP_BLOCKING_ENABLED", "false").lower() == "true"
    cooldown_seconds   : int  = int(os.getenv("COOLDOWN_SECONDS","60"))


class AlertAgent:

    def __init__(self, in_queue: queue.Queue, config: AlertConfig = None):
        self.in_queue    = in_queue
        self.config      = config or AlertConfig()
        self._stop_event = threading.Event()
        self._thread     = None
        self.alerts_sent    = 0
        self.watches_logged = 0

        # Wire in Notifier
        from notifications.notifier import Notifier, NotifyConfig
        self._notifier = Notifier(NotifyConfig(
            email_enabled     = self.config.email_enabled,
            smtp_host         = self.config.smtp_host,
            smtp_port         = self.config.smtp_port,
            smtp_user         = self.config.smtp_user,
            smtp_password     = self.config.smtp_password,
            email_to          = self.config.alert_email_to,
            email_min_level   = self.config.email_min_level,
            slack_enabled     = self.config.slack_enabled,
            slack_webhook_url = self.config.slack_webhook_url,
            slack_min_level   = self.config.slack_min_level,
            cooldown_seconds  = self.config.cooldown_seconds,
        ))

        # Wire in IP Blocker
        if self.config.ip_blocking_enabled:
            from security.ip_blocker import IPBlocker
            self._blocker = IPBlocker()
        else:
            self._blocker = None

        Path(self.config.log_file).parent.mkdir(parents=True, exist_ok=True)
        Path(self.config.csv_file).parent.mkdir(parents=True, exist_ok=True)
        if not Path(self.config.csv_file).exists():
            self._write_csv_header()

        active = [x for x in [
            "Email ✓" if self.config.email_enabled else None,
            "Slack ✓" if self.config.slack_enabled else None,
            "IP-Block ✓" if self.config.ip_blocking_enabled else None,
        ] if x]
        print(f"[AlertAgent] Notifications: {', '.join(active) or 'log-only mode'}")

    def start(self):
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        print("[AlertAgent] Started — monitoring for threats...")

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        print(f"[AlertAgent] Stopped. Alerts: {self.alerts_sent}, Watches: {self.watches_logged}")

    def handle_dataframe(self, df: pd.DataFrame):
        self._process(df)

    def _run_loop(self):
        while not self._stop_event.is_set():
            try:
                df = self.in_queue.get(timeout=1)
            except queue.Empty:
                continue
            if df is None:
                break
            self._process(df)

    def _process(self, df: pd.DataFrame):
        for _, row in df.iterrows():
            level = str(row.get("threat_level", "WATCH"))
            if level == "ALERT":
                self._handle_alert(row)
            elif level == "WATCH":
                self._handle_watch(row)

    def _handle_alert(self, row):
        ts         = row.get("timestamp") or row.get("collected_at") or datetime.now()
        ip         = str(row.get("ip", "unknown"))
        attack     = str(row.get("attack_type", "unknown"))
        confidence = float(row.get("confidence", 0))
        url        = str(row.get("url", "—"))
        status     = row.get("status", "—")
        rule       = str(row.get("rule_alert", ""))

        print(
            f"\n{'═'*52}\n  ⚠  CYBER ATTACK DETECTED\n{'─'*52}\n"
            f"  Time        : {ts}\n"
            f"  IP Address  : {ip}\n"
            f"  Attack Type : {attack.replace('_',' ').title()}\n"
            f"  Confidence  : {confidence*100:.0f}%\n"
            f"  URL         : {url}\n"
            f"  Status Code : {status}\n"
            f"  Rules Hit   : {rule or 'ML model'}\n{'═'*52}"
        )
        self._write_log("ALERT", ip, attack, confidence, url, ts, rule)
        self._write_csv_row("ALERT", ip, attack, confidence, url, status, ts, rule)
        self._notifier.notify("ALERT", ip, attack, confidence, url,
                              ts if isinstance(ts, datetime) else datetime.now(), rule)
        if self._blocker:
            self._blocker.block(ip, reason=attack)
        self.alerts_sent += 1

    def _handle_watch(self, row):
        ts         = row.get("timestamp") or row.get("collected_at") or datetime.now()
        ip         = str(row.get("ip", "unknown"))
        attack     = str(row.get("attack_type", "—"))
        confidence = float(row.get("confidence", 0))
        url        = str(row.get("url", "—"))
        status     = row.get("status", "—")
        rule       = str(row.get("rule_alert", ""))

        print(f"[AlertAgent] WATCH | {ip} | {attack} | conf:{confidence:.2f} | {url}")
        self._write_log("WATCH", ip, attack, confidence, url, ts, rule)
        self._write_csv_row("WATCH", ip, attack, confidence, url, status, ts, rule)
        self._notifier.notify("WATCH", ip, attack, confidence, url,
                              ts if isinstance(ts, datetime) else datetime.now(), rule)
        self.watches_logged += 1

    def _write_log(self, level, ip, attack, confidence, url, ts, rule):
        with open(self.config.log_file, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {level} | IP:{ip} | {attack} | conf:{confidence:.2f} | {url} | [{rule}]\n")

    def _write_csv_header(self):
        with open(self.config.csv_file, "w", newline="") as f:
            csv.writer(f).writerow(["timestamp","level","ip","attack_type","confidence","url","status_code","rules"])

    def _write_csv_row(self, level, ip, attack, confidence, url, status, ts, rule):
        with open(self.config.csv_file, "a", newline="") as f:
            csv.writer(f).writerow([ts, level, ip, attack, f"{confidence:.3f}", url, status, rule])

    def status(self):
        return {
            "agent"          : "AlertAgent",
            "alerts_sent"    : self.alerts_sent,
            "watches_logged" : self.watches_logged,
            "email_enabled"  : self.config.email_enabled,
            "slack_enabled"  : self.config.slack_enabled,
            "ip_blocking"    : self.config.ip_blocking_enabled,
            "running"        : self._thread.is_alive() if self._thread else False,
        }
