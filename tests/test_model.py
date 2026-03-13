"""
tests/test_model.py — ML Model Tests
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import pandas as pd
import numpy as np
from ml.train_model import train_isolation_forest, predict, FEATURE_COLS


def _make_df():
    return pd.DataFrame([
        dict(status=200, size=2048, hour=14, is_error=False,  is_auth_fail=False, login_attempt=False, ip_total_requests=5,  ip_error_count=0,  error_rate_ip=0.00, is_new_ip=False),
        dict(status=200, size=1500, hour=11, is_error=False,  is_auth_fail=False, login_attempt=False, ip_total_requests=8,  ip_error_count=1,  error_rate_ip=0.12, is_new_ip=False),
        dict(status=401, size=512,  hour=3,  is_error=True,   is_auth_fail=True,  login_attempt=True,  ip_total_requests=20, ip_error_count=18, error_rate_ip=0.90, is_new_ip=False),
        dict(status=401, size=512,  hour=3,  is_error=True,   is_auth_fail=True,  login_attempt=True,  ip_total_requests=20, ip_error_count=18, error_rate_ip=0.90, is_new_ip=False),
        dict(status=404, size=128,  hour=2,  is_error=True,   is_auth_fail=False, login_attempt=False, ip_total_requests=80, ip_error_count=70, error_rate_ip=0.88, is_new_ip=True),
        dict(status=200, size=4096, hour=9,  is_error=False,  is_auth_fail=False, login_attempt=False, ip_total_requests=3,  ip_error_count=0,  error_rate_ip=0.00, is_new_ip=False),
    ])


class TestIsolationForest:
    def test_train_returns_model(self):
        df = _make_df()
        model, scaler, df_labeled = train_isolation_forest(df, contamination=0.3)
        assert model is not None
        assert scaler is not None

    def test_labeled_df_has_prediction(self):
        df = _make_df()
        _, _, df_labeled = train_isolation_forest(df, contamination=0.3)
        assert "prediction" in df_labeled.columns
        assert "label" in df_labeled.columns
        assert set(df_labeled["prediction"].unique()).issubset({1, -1})

    def test_model_files_saved(self):
        df = _make_df()
        train_isolation_forest(df, contamination=0.3)
        assert Path("ml/model.pkl").exists()
        assert Path("ml/scaler.pkl").exists()


class TestPredict:
    def setup_method(self):
        df = _make_df()
        train_isolation_forest(df, contamination=0.3)

    def test_predict_adds_columns(self):
        df = _make_df()
        result = predict(df)
        for col in ["prediction", "confidence", "label", "attack_type"]:
            assert col in result.columns

    def test_confidence_range(self):
        df = _make_df()
        result = predict(df)
        assert (result["confidence"] >= 0).all()
        assert (result["confidence"] <= 1).all()

    def test_labels_valid(self):
        df = _make_df()
        result = predict(df)
        valid = {"Normal", "Suspicious", "Attack"}
        assert set(result["label"].unique()).issubset(valid)
