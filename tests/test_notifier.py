"""
tests/test_notifier.py — Notifier Tests
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from datetime import datetime, timedelta
from notifications.notifier import Notifier, NotifyConfig


class TestNotifyConfig:
    def test_defaults(self):
        cfg = NotifyConfig()
        assert cfg.email_enabled is False
        assert cfg.slack_enabled is False
        assert cfg.cooldown_seconds == 60

    def test_level_check(self):
        assert Notifier._level_ok("ALERT", "ALERT") is True
        assert Notifier._level_ok("ALERT", "WATCH") is True
        assert Notifier._level_ok("WATCH", "ALERT") is False
        assert Notifier._level_ok("WATCH", "WATCH") is True


class TestCooldown:
    def test_cooldown_blocks_repeat(self):
        cfg = NotifyConfig(email_enabled=False, slack_enabled=False, cooldown_seconds=60)
        n = Notifier(cfg)
        ts = datetime.now()
        n.notify("ALERT", "1.2.3.4", "brute_force", 0.9, "/login", ts)
        # Second call within cooldown — should be silently skipped
        n.notify("ALERT", "1.2.3.4", "brute_force", 0.9, "/login", ts + timedelta(seconds=10))
        assert "1.2.3.4" in n._last_sent

    def test_cooldown_allows_after_expiry(self):
        cfg = NotifyConfig(email_enabled=False, slack_enabled=False, cooldown_seconds=5)
        n = Notifier(cfg)
        ts1 = datetime.now() - timedelta(seconds=10)
        ts2 = datetime.now()
        n._last_sent["5.5.5.5"] = ts1   # simulate previous notification
        # Should be allowed (10s > 5s cooldown)
        n.notify("ALERT", "5.5.5.5", "port_scan", 0.8, "/scan", ts2)
        assert n._last_sent["5.5.5.5"] == ts2

    def test_different_ips_independent(self):
        cfg = NotifyConfig(email_enabled=False, slack_enabled=False, cooldown_seconds=60)
        n = Notifier(cfg)
        ts = datetime.now()
        n.notify("ALERT", "1.1.1.1", "brute_force", 0.9, "/login", ts)
        # Different IP should NOT be blocked
        first_count = len(n._last_sent)
        n.notify("ALERT", "2.2.2.2", "port_scan", 0.8, "/admin", ts)
        assert len(n._last_sent) == first_count + 1
