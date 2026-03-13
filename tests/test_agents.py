"""
tests/test_agents.py — Agent Pipeline Tests
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import queue
import time
import tempfile
import os
import pandas as pd
from agents.collector import LogCollectorAgent
from agents.analyzer  import LogAnalyzerAgent
from agents.threat_agent import ThreatDetectionAgent
from ml.train_model import train_isolation_forest

SAMPLE_LINES = [
    '10.0.0.1 - - [13/Mar/2026:09:01:00 +0000] "GET /index.html HTTP/1.1" 200 2048 "-" "Mozilla/5.0"',
    '192.168.0.21 - - [13/Mar/2026:02:42:10 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
    '192.168.0.21 - - [13/Mar/2026:02:42:11 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
    '192.168.0.21 - - [13/Mar/2026:02:42:12 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
    '192.168.0.21 - - [13/Mar/2026:02:42:13 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
    '192.168.0.21 - - [13/Mar/2026:02:42:14 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
    '203.0.113.5 - - [13/Mar/2026:02:43:00 +0000] "GET /wp-login.php HTTP/1.1" 404 256 "-" "nikto/2.1"',
]


def _write_temp_log():
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
    f.write("\n".join(SAMPLE_LINES))
    f.close()
    return f.name


class TestLogCollectorAgent:
    def test_batch_fills_queue(self):
        tmp = _write_temp_log()
        try:
            q = queue.Queue()
            agent = LogCollectorAgent(tmp, q)
            agent.run_batch()
            items = []
            while not q.empty():
                items.append(q.get())
            # Last item should be sentinel (None)
            assert items[-1] is None
            assert len(items) - 1 == len(SAMPLE_LINES)  # minus sentinel
        finally:
            os.unlink(tmp)

    def test_status_reports_count(self):
        tmp = _write_temp_log()
        try:
            q = queue.Queue()
            agent = LogCollectorAgent(tmp, q)
            agent.run_batch()
            assert agent.lines_collected == len(SAMPLE_LINES)
        finally:
            os.unlink(tmp)


class TestLogAnalyzerAgent:
    def test_analyze_dataframe(self):
        tmp = _write_temp_log()
        try:
            from utils.parser import parse_log_file
            df = parse_log_file(tmp)
            analyzer = LogAnalyzerAgent(queue.Queue(), queue.Queue())
            result = analyzer.analyze_dataframe(df)
            assert "rule_alert" in result.columns
            assert "is_auth_fail" in result.columns
        finally:
            os.unlink(tmp)

    def test_brute_force_detected(self):
        tmp = _write_temp_log()
        try:
            from utils.parser import parse_log_file
            df = parse_log_file(tmp)
            analyzer = LogAnalyzerAgent(queue.Queue(), queue.Queue())
            result = analyzer.analyze_dataframe(df)
            brute = result[result["rule_alert"].str.contains("brute_force", na=False)]
            assert len(brute) > 0
        finally:
            os.unlink(tmp)


class TestThreatDetectionAgent:
    def setup_method(self):
        from utils.parser import parse_log_file, extract_features
        tmp = _write_temp_log()
        df = parse_log_file(tmp)
        df = extract_features(df)
        os.unlink(tmp)
        train_isolation_forest(df, contamination=0.3)

    def test_score_dataframe(self):
        from utils.parser import parse_log_file, extract_features
        tmp = _write_temp_log()
        df = parse_log_file(tmp)
        df = extract_features(df)
        os.unlink(tmp)

        agent = ThreatDetectionAgent(queue.Queue(), queue.Queue())
        result = agent.score_dataframe(df)
        assert "threat_level" in result.columns
        valid_levels = {"CLEAR", "WATCH", "ALERT"}
        assert set(result["threat_level"].unique()).issubset(valid_levels)

    def test_threat_levels_assigned(self):
        from utils.parser import parse_log_file, extract_features
        tmp = _write_temp_log()
        df = parse_log_file(tmp)
        df = extract_features(df)
        os.unlink(tmp)

        # Add rule_alert column as analyzer would
        df["rule_alert"] = ""
        agent = ThreatDetectionAgent(queue.Queue(), queue.Queue())
        result = agent.score_dataframe(df)
        # Should have at least some non-CLEAR entries given attack lines
        assert "WATCH" in result["threat_level"].values or "ALERT" in result["threat_level"].values


class TestGenerateLogs:
    def test_generates_correct_count(self):
        from data.generate_logs import generate
        lines = generate(n_lines=100, attack_ratio=0.2)
        assert len(lines) == 100

    def test_output_is_apache_format(self):
        from data.generate_logs import generate
        lines = generate(n_lines=20)
        for line in lines:
            assert " HTTP/1.1" in line
            assert '"' in line
