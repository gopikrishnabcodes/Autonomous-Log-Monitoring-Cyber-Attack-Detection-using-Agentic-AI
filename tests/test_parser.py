"""
tests/test_parser.py — Parser + Feature Engineering Tests
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import tempfile
import os
import pandas as pd
from utils.parser import parse_line, parse_log_file, extract_features


SAMPLE_LINES = [
    '192.168.1.10 - - [12/Oct/2023:10:23:45 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
    '192.168.1.10 - - [12/Oct/2023:10:23:46 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
    '192.168.1.10 - - [12/Oct/2023:10:23:47 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
    '203.0.113.5  - - [12/Oct/2023:10:24:00 +0000] "GET /wp-login.php HTTP/1.1" 404 256 "-" "nikto/2.1"',
    'NOT A VALID LOG LINE',
]


class TestParseLine:
    def test_valid_get_request(self):
        result = parse_line(SAMPLE_LINES[0])
        assert result is not None
        assert result["ip"]     == "192.168.1.10"
        assert result["method"] == "GET"
        assert result["url"]    == "/index.html"
        assert result["status"] == 200
        assert result["size"]   == 1024

    def test_valid_post_401(self):
        result = parse_line(SAMPLE_LINES[1])
        assert result is not None
        assert result["method"] == "POST"
        assert result["status"] == 401
        assert result["url"]    == "/login"

    def test_invalid_line_returns_none(self):
        assert parse_line("NOT A VALID LOG LINE") is None

    def test_timestamp_parsed(self):
        result = parse_line(SAMPLE_LINES[0])
        assert result["timestamp"] is not None

    def test_agent_captured(self):
        result = parse_line(SAMPLE_LINES[1])
        assert "python-requests" in result["agent"]


class TestParseLogFile:
    def test_parses_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("\n".join(SAMPLE_LINES))
            tmp = f.name
        try:
            df = parse_log_file(tmp)
            assert isinstance(df, pd.DataFrame)
            assert len(df) == 4   # 5 lines minus 1 invalid
            assert "ip" in df.columns
            assert "status" in df.columns
        finally:
            os.unlink(tmp)

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            parse_log_file("/nonexistent/path/file.log")


class TestExtractFeatures:
    def setup_method(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("\n".join(SAMPLE_LINES))
            self.tmp = f.name
        self.df = parse_log_file(self.tmp)

    def teardown_method(self):
        os.unlink(self.tmp)

    def test_features_added(self):
        df = extract_features(self.df)
        for col in ["is_error", "is_auth_fail", "login_attempt", "error_rate_ip", "is_new_ip", "hour"]:
            assert col in df.columns, f"Missing column: {col}"

    def test_auth_fail_flag(self):
        df = extract_features(self.df)
        fails = df[df["status"] == 401]
        assert fails["is_auth_fail"].all()

    def test_login_attempt_flag(self):
        df = extract_features(self.df)
        logins = df[df["url"] == "/login"]
        assert logins["login_attempt"].all()

    def test_error_rate_correct(self):
        df = extract_features(self.df)
        ip_df = df[df["ip"] == "192.168.1.10"]
        # 2 errors out of 3 requests = 0.667
        assert ip_df["error_rate_ip"].iloc[0] == pytest.approx(2/3, rel=0.01)
