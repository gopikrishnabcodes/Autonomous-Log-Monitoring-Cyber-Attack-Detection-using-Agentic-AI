"""
notifications/notifier.py
--------------------------
Email + Slack alert notifications for CyberWatch
Plugs directly into AlertAgent (alert_agent.py)

Setup:
  1. Email  → set SMTP credentials in .env or AlertConfig
  2. Slack  → create Incoming Webhook at api.slack.com/apps → set SLACK_WEBHOOK_URL
"""

import smtplib
import json
import urllib.request
import urllib.error
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import os


# ── Config ───────────────────────────────────────────────

@dataclass
class NotifyConfig:
    # ── Email (Gmail SMTP) ──────────────────
    email_enabled   : bool  = False
    smtp_host       : str   = "smtp.gmail.com"
    smtp_port       : int   = 587
    smtp_user       : str   = ""        # your Gmail: you@gmail.com
    smtp_password   : str   = ""        # Gmail App Password (not login password)
    email_to        : str   = ""        # recipient: security@yourcompany.com
    email_min_level : str   = "ALERT"   # "ALERT" or "WATCH"

    # ── Slack ───────────────────────────────
    slack_enabled      : bool = False
    slack_webhook_url  : str  = ""      # https://hooks.slack.com/services/XXX/YYY/ZZZ
    slack_min_level    : str  = "ALERT"

    # ── Cooldown (avoid spam) ───────────────
    cooldown_seconds   : int  = 60      # don't repeat same IP alert within N seconds


# ── Notifier ─────────────────────────────────────────────

class Notifier:
    """
    Sends Email and/or Slack notifications for cyber alerts.

    Usage (in alert_agent.py):
        from notifications.notifier import Notifier, NotifyConfig
        notifier = Notifier(NotifyConfig(
            email_enabled=True,
            smtp_user="you@gmail.com",
            smtp_password="your-app-password",
            email_to="security@yourcompany.com",
            slack_enabled=True,
            slack_webhook_url="https://hooks.slack.com/services/..."
        ))
        notifier.notify(level="ALERT", ip="1.2.3.4", attack="brute_force",
                        confidence=0.91, url="/login", ts=datetime.now())
    """

    def __init__(self, config: NotifyConfig = None):
        self.cfg = config or NotifyConfig()
        self._last_sent: dict[str, datetime] = {}   # ip → last notified time

    def notify(
        self,
        level      : str,
        ip         : str,
        attack     : str,
        confidence : float,
        url        : str   = "—",
        ts         : datetime = None,
        rules      : str   = "",
    ):
        """
        Send notification for a single threat event.
        Respects cooldown — same IP won't be re-notified within cooldown_seconds.
        """
        ts = ts or datetime.now()

        # Cooldown check
        last = self._last_sent.get(ip)
        if last and (ts - last).total_seconds() < self.cfg.cooldown_seconds:
            return

        # Email
        if self.cfg.email_enabled and self._level_ok(level, self.cfg.email_min_level):
            self._send_email(level, ip, attack, confidence, url, ts, rules)

        # Slack
        if self.cfg.slack_enabled and self._level_ok(level, self.cfg.slack_min_level):
            self._send_slack(level, ip, attack, confidence, url, ts, rules)

        self._last_sent[ip] = ts

    # ── Email ────────────────────────────────────────────

    def _send_email(self, level, ip, attack, confidence, url, ts, rules):
        cfg = self.cfg
        if not cfg.smtp_user or not cfg.email_to:
            print("[Notifier] Email not configured — skipping.")
            return

        subject = f"{'🚨' if level=='ALERT' else '👁'} CyberWatch {level}: {attack.replace('_',' ').title()} from {ip}"

        html_body = f"""
        <html><body style="font-family:Arial,sans-serif;background:#f4f6f9;padding:20px">
        <div style="max-width:520px;margin:auto;background:#fff;border-radius:10px;overflow:hidden;
                    box-shadow:0 2px 8px rgba(0,0,0,0.1)">
          <div style="background:{'#d32f2f' if level=='ALERT' else '#f57c00'};padding:20px 24px">
            <h2 style="color:#fff;margin:0;font-size:18px">
              {'🚨 CYBER ATTACK DETECTED' if level=='ALERT' else '👁 SUSPICIOUS ACTIVITY'}
            </h2>
          </div>
          <div style="padding:24px">
            <table style="width:100%;border-collapse:collapse;font-size:14px">
              <tr><td style="color:#888;padding:6px 0;width:140px">Time</td>
                  <td style="color:#222;font-weight:500">{ts.strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
              <tr><td style="color:#888;padding:6px 0">IP Address</td>
                  <td style="color:#1565C0;font-family:monospace;font-weight:600">{ip}</td></tr>
              <tr><td style="color:#888;padding:6px 0">Attack Type</td>
                  <td style="color:#222;font-weight:500">{attack.replace('_',' ').title()}</td></tr>
              <tr><td style="color:#888;padding:6px 0">Confidence</td>
                  <td style="color:{'#c62828' if confidence>=0.75 else '#e65100'};font-weight:700">
                    {confidence*100:.0f}%</td></tr>
              <tr><td style="color:#888;padding:6px 0">URL</td>
                  <td style="color:#222;font-family:monospace">{url}</td></tr>
              {'<tr><td style="color:#888;padding:6px 0">Rules Hit</td><td style="color:#555">'
               + rules + '</td></tr>' if rules else ''}
            </table>
          </div>
          <div style="background:#f8f9fa;padding:14px 24px;font-size:12px;color:#aaa">
            CyberWatch Autonomous Log Monitoring · Check your dashboard for full details
          </div>
        </div>
        </body></html>
        """

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = cfg.smtp_user
        msg["To"]      = cfg.email_to
        msg.attach(MIMEText(html_body, "html"))

        try:
            with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=10) as server:
                server.ehlo()
                server.starttls()
                server.login(cfg.smtp_user, cfg.smtp_password)
                server.send_message(msg)
            print(f"[Notifier] ✅ Email sent to {cfg.email_to} ({level}: {ip})")
        except Exception as e:
            print(f"[Notifier] ❌ Email failed: {e}")

    # ── Slack ────────────────────────────────────────────

    def _send_slack(self, level, ip, attack, confidence, url, ts, rules):
        if not self.cfg.slack_webhook_url:
            print("[Notifier] Slack webhook not configured — skipping.")
            return

        color   = "#d32f2f" if level == "ALERT" else "#f57c00"
        emoji   = "🚨" if level == "ALERT" else "👁"
        title   = f"{emoji} *{level}: {attack.replace('_',' ').title()}*"

        fields = [
            {"title": "IP Address",   "value": f"`{ip}`",                           "short": True},
            {"title": "Confidence",   "value": f"*{confidence*100:.0f}%*",          "short": True},
            {"title": "URL",          "value": f"`{url}`",                           "short": True},
            {"title": "Time",         "value": ts.strftime('%H:%M:%S'),              "short": True},
        ]
        if rules:
            fields.append({"title": "Rules Hit", "value": rules, "short": False})

        payload = {
            "attachments": [{
                "color"      : color,
                "title"      : title,
                "fields"     : fields,
                "footer"     : "CyberWatch Autonomous Monitor",
                "footer_icon": "https://cdn-icons-png.flaticon.com/512/1698/1698521.png",
                "ts"         : int(ts.timestamp()),
            }]
        }

        data = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            self.cfg.slack_webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = resp.read().decode()
            if result == "ok":
                print(f"[Notifier] ✅ Slack sent ({level}: {ip})")
            else:
                print(f"[Notifier] ⚠ Slack response: {result}")
        except urllib.error.URLError as e:
            print(f"[Notifier] ❌ Slack failed: {e}")

    # ── Helpers ──────────────────────────────────────────

    @staticmethod
    def _level_ok(event_level: str, min_level: str) -> bool:
        order = {"WATCH": 0, "ALERT": 1}
        return order.get(event_level, 0) >= order.get(min_level, 1)


# ── Quick test ───────────────────────────────────────────

if __name__ == "__main__":
    print("Testing Notifier (no real credentials — dry run)\n")

    cfg = NotifyConfig(
        email_enabled=False,   # set True + add credentials to actually send
        slack_enabled=False,   # set True + add webhook URL to actually send
        cooldown_seconds=0,
    )
    n = Notifier(cfg)
    n.notify(
        level="ALERT", ip="192.168.0.21", attack="brute_force",
        confidence=0.91, url="/login",
        ts=datetime.now(), rules="brute_force,off_hours"
    )
    n.notify(
        level="WATCH", ip="203.0.113.5", attack="port_scan",
        confidence=0.58, url="/wp-login.php",
        ts=datetime.now(), rules="suspicious_agent"
    )
    print("Dry run complete. Set email_enabled=True or slack_enabled=True to send real alerts.")
