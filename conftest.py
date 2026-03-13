"""
tests/conftest.py
-----------------
Shared pytest fixtures for CyberWatch test suite.
Automatically used by all test files in tests/.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import tempfile
import os

SAMPLE_LOG_LINES = [
    '192.168.1.10 - - [12/Oct/2023:10:23:45 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
    '192.168.1.10 - - [12/Oct/2023:10:23:46 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
    '192.168.1.10 - - [12/Oct/2023:10:23:47 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
    '192.168.1.10 - - [12/Oct/2023:10:23:48 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
    '192.168.1.10 - - [12/Oct/2023:10:23:49 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
    '192.168.1.10 - - [12/Oct/2023:10:23:50 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"',
    '203.0.113.5  - - [12/Oct/2023:10:24:00 +0000] "GET /wp-login.php HTTP/1.1" 404 256 "-" "nikto/2.1"',
]


@pytest.fixture
def sample_log_file(tmp_path):
    """Writes sample Apache log lines to a temp file. Cleaned up automatically."""
    log_file = tmp_path / "access.log"
    log_file.write_text("\n".join(SAMPLE_LOG_LINES))
    return str(log_file)


@pytest.fixture
def sample_dataframe(sample_log_file):
    """Returns a parsed + feature-engineered DataFrame from sample log."""
    from utils.parser import parse_log_file, extract_features
    df = parse_log_file(sample_log_file)
    return extract_features(df)


@pytest.fixture
def trained_model(sample_dataframe):
    """Trains an Isolation Forest on sample data. Returns (model, scaler)."""
    from ml.train_model import train_isolation_forest
    model, scaler, _ = train_isolation_forest(sample_dataframe, contamination=0.3)
    return model, scaler
