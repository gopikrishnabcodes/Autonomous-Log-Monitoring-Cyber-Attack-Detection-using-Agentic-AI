"""
security/ip_blocker.py
-----------------------
Automatic IP Blocking for CyberWatch

When Agent 4 receives an ALERT, this module can automatically
block the attacker's IP address at the OS firewall level.

Supports:
  - Linux   → iptables
  - macOS   → pfctl (requires sudo)
  - Windows → netsh advfirewall (requires admin)
  - Dry run → logs what WOULD be blocked (safe default)

Enable in .env:
    IP_BLOCKING_ENABLED=true

⚠️  WARNING: Blocking IPs modifies your system firewall.
    Run with root/admin privileges.
    Always test in dry_run=True mode first.
    Keep a whitelist of safe IPs (your own, cloud providers, etc.)
"""

import os
import sys
import platform
import subprocess
import json
from pathlib import Path
from datetime import datetime


# ── Whitelist — NEVER block these IPs ───────────────────
# Add your own IP, office IP, monitoring systems here
DEFAULT_WHITELIST = {
    "127.0.0.1",
    "::1",
    "10.0.0.1",       # typical gateway
    "192.168.1.1",    # typical gateway
}


class IPBlocker:
    """
    Automatically blocks attacker IPs at the firewall level.

    Parameters
    ----------
    dry_run    : if True, only logs what WOULD be blocked (no real changes)
    whitelist  : set of IPs that must never be blocked
    block_log  : path to write block history
    """

    def __init__(
        self,
        dry_run   : bool = True,
        whitelist : set  = None,
        block_log : str  = "logs/blocked_ips.json",
    ):
        self.dry_run   = dry_run
        self.whitelist = whitelist or DEFAULT_WHITELIST
        self.block_log = Path(block_log)
        self._os       = platform.system()   # Linux, Darwin, Windows
        self._blocked  : dict[str, dict] = {}

        self.block_log.parent.mkdir(parents=True, exist_ok=True)
        self._load_history()

        mode = "DRY RUN" if dry_run else f"LIVE ({self._os})"
        print(f"[IPBlocker] Initialized — mode: {mode}")

    # ── Public API ───────────────────────────────────────

    def block(self, ip: str, reason: str = "attack"):
        """
        Block an IP address. Skips whitelist IPs and already-blocked IPs.
        """
        if ip in self.whitelist:
            print(f"[IPBlocker] Skipping whitelisted IP: {ip}")
            return False

        if ip in self._blocked:
            print(f"[IPBlocker] Already blocked: {ip}")
            return False

        if self.dry_run:
            print(f"[IPBlocker] DRY RUN — would block: {ip} (reason: {reason})")
            self._record(ip, reason, "dry_run")
            return True

        success = self._apply_block(ip)
        if success:
            print(f"[IPBlocker] ✅ Blocked: {ip} (reason: {reason})")
            self._record(ip, reason, "blocked")
        else:
            print(f"[IPBlocker] ❌ Failed to block: {ip}")
        return success

    def unblock(self, ip: str):
        """Remove a block for an IP address."""
        if ip not in self._blocked:
            print(f"[IPBlocker] IP not in block list: {ip}")
            return False

        if self.dry_run:
            print(f"[IPBlocker] DRY RUN — would unblock: {ip}")
            self._blocked.pop(ip, None)
            self._save_history()
            return True

        success = self._apply_unblock(ip)
        if success:
            print(f"[IPBlocker] ✅ Unblocked: {ip}")
            self._blocked.pop(ip, None)
            self._save_history()
        return success

    def list_blocked(self) -> list[dict]:
        """Return list of all currently blocked IPs with metadata."""
        return list(self._blocked.values())

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked

    # ── Platform-specific block commands ─────────────────

    def _apply_block(self, ip: str) -> bool:
        try:
            if self._os == "Linux":
                return self._run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
            elif self._os == "Darwin":
                # macOS pfctl — adds to /etc/pf.conf blocklist
                cmd = f'echo "block in quick from {ip}" | pfctl -a cyberwatch -f -'
                return self._run(cmd, shell=True)
            elif self._os == "Windows":
                return self._run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=CyberWatch-Block-{ip}",
                    "dir=in", "action=block",
                    f"remoteip={ip}"
                ])
            else:
                print(f"[IPBlocker] Unsupported OS: {self._os}")
                return False
        except Exception as e:
            print(f"[IPBlocker] Block error: {e}")
            return False

    def _apply_unblock(self, ip: str) -> bool:
        try:
            if self._os == "Linux":
                return self._run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            elif self._os == "Darwin":
                cmd = f'pfctl -a cyberwatch -F rules'
                return self._run(cmd, shell=True)
            elif self._os == "Windows":
                return self._run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name=CyberWatch-Block-{ip}"
                ])
            else:
                return False
        except Exception as e:
            print(f"[IPBlocker] Unblock error: {e}")
            return False

    def _run(self, cmd, shell=False) -> bool:
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[IPBlocker] Command error: {result.stderr.strip()}")
        return result.returncode == 0

    # ── Persistence ──────────────────────────────────────

    def _record(self, ip: str, reason: str, status: str):
        self._blocked[ip] = {
            "ip"         : ip,
            "reason"     : reason,
            "status"     : status,
            "blocked_at" : datetime.now().isoformat(),
        }
        self._save_history()

    def _save_history(self):
        with open(self.block_log, "w") as f:
            json.dump(self._blocked, f, indent=2)

    def _load_history(self):
        if self.block_log.exists():
            try:
                self._blocked = json.loads(self.block_log.read_text())
                print(f"[IPBlocker] Loaded {len(self._blocked)} previously blocked IPs.")
            except Exception:
                self._blocked = {}


# ── Quick test ───────────────────────────────────────────

if __name__ == "__main__":
    print("Testing IPBlocker (dry_run=True — no real changes)\n")
    blocker = IPBlocker(dry_run=True)

    # Block a test IP
    blocker.block("1.2.3.4",   reason="brute_force")
    blocker.block("5.6.7.8",   reason="port_scan")
    blocker.block("127.0.0.1", reason="test")      # should be skipped (whitelist)
    blocker.block("1.2.3.4",   reason="duplicate")  # should be skipped (already blocked)

    print(f"\nCurrently blocked ({len(blocker.list_blocked())}):")
    for entry in blocker.list_blocked():
        print(f"  {entry['ip']:<20} reason: {entry['reason']}")

    blocker.unblock("1.2.3.4")
    print(f"\nAfter unblock: {len(blocker.list_blocked())} blocked IPs")
