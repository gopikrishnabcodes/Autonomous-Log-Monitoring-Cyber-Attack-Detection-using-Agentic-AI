"""
ml/train_model.py
-----------------
ML Threat Detection for Autonomous Log Monitoring System

Two models:
  1. IsolationForest  — unsupervised anomaly detection
                        Use when you have NO labels (raw logs only)
  2. RandomForest     — supervised classifier
                        Use when you have labels (e.g. CICIDS 2017)

Outputs:
  - ml/model.pkl      trained model
  - ml/scaler.pkl     feature scaler
  - ml/report.txt     evaluation report
"""

import os
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix,
    accuracy_score, precision_score, recall_score, f1_score
)


# ─────────────────────────────────────────────────────
# Feature columns used by both models
# (must match what extract_features() produces in parser.py)
# ─────────────────────────────────────────────────────
FEATURE_COLS = [
    "status",
    "size",
    "hour",
    "is_error",
    "is_auth_fail",
    "login_attempt",
    "ip_total_requests",
    "ip_error_count",
    "error_rate_ip",
    "is_new_ip",
]

MODEL_DIR = Path(__file__).parent
MODEL_PATH  = MODEL_DIR / "model.pkl"
SCALER_PATH = MODEL_DIR / "scaler.pkl"
REPORT_PATH = MODEL_DIR / "report.txt"


# ─────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────

def _prepare_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Select and clean feature columns from a parsed log DataFrame.
    Fills missing values and converts booleans to int.
    """
    available = [c for c in FEATURE_COLS if c in df.columns]
    missing   = [c for c in FEATURE_COLS if c not in df.columns]

    if missing:
        print(f"[model] Warning: missing feature columns, filling with 0: {missing}")
        for col in missing:
            df[col] = 0

    X = df[FEATURE_COLS].copy()

    # Convert booleans → int (sklearn needs numeric)
    bool_cols = X.select_dtypes(include="bool").columns
    X[bool_cols] = X[bool_cols].astype(int)

    # Fill any remaining NaN
    X = X.fillna(0)

    return X


def _save(obj, path: Path):
    os.makedirs(path.parent, exist_ok=True)
    with open(path, "wb") as f:
        pickle.dump(obj, f)
    print(f"[model] Saved → {path}")


def _load(path: Path):
    with open(path, "rb") as f:
        return pickle.load(f)


# ─────────────────────────────────────────────────────
# 1. Unsupervised — Isolation Forest
#    Use this with raw Apache logs (no labels needed)
# ─────────────────────────────────────────────────────

def train_isolation_forest(df: pd.DataFrame, contamination: float = 0.05) -> IsolationForest:
    """
    Train an Isolation Forest on parsed log features.

    Parameters
    ----------
    df            : DataFrame from parse_log_file() + extract_features()
    contamination : expected fraction of attacks in your data (default 5%)

    Returns
    -------
    Trained IsolationForest model (also saved to ml/model.pkl)
    """
    print("\n[model] Training Isolation Forest (unsupervised)...")

    X = _prepare_features(df)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_scaled)

    # Predict on training set so we can report distribution
    # IsolationForest: 1 = normal, -1 = anomaly
    raw_preds = model.predict(X_scaled)
    scores    = model.decision_function(X_scaled)

    n_anomalies = (raw_preds == -1).sum()
    n_normal    = (raw_preds ==  1).sum()

    report = (
        f"Isolation Forest Report\n"
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"{'─'*40}\n"
        f"Total samples    : {len(X)}\n"
        f"Normal (1)       : {n_normal}  ({n_normal/len(X)*100:.1f}%)\n"
        f"Anomalous (-1)   : {n_anomalies}  ({n_anomalies/len(X)*100:.1f}%)\n"
        f"Contamination    : {contamination}\n"
        f"Score range      : [{scores.min():.4f}, {scores.max():.4f}]\n"
        f"{'─'*40}\n"
        f"Features used    : {FEATURE_COLS}\n"
    )
    print(report)

    # Attach labels back to df for inspection
    df = df.copy()
    df["prediction"] = raw_preds
    df["anomaly_score"] = scores
    df["label"] = df["prediction"].map({1: "Normal", -1: "Suspicious"})

    _save(model,  MODEL_PATH)
    _save(scaler, SCALER_PATH)

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(report)

    return model, scaler, df


# ─────────────────────────────────────────────────────
# 2. Supervised — Random Forest
#    Use this with CICIDS 2017 (has a "Label" column)
# ─────────────────────────────────────────────────────

def train_random_forest(df: pd.DataFrame, label_col: str = "Label") -> RandomForestClassifier:
    """
    Train a Random Forest classifier on labeled log data (e.g. CICIDS 2017).

    Parameters
    ----------
    df        : DataFrame with feature columns + a label column
    label_col : name of the column containing attack labels (default "Label")

    Returns
    -------
    Trained RandomForestClassifier (also saved to ml/model.pkl)
    """
    print("\n[model] Training Random Forest (supervised)...")

    if label_col not in df.columns:
        raise ValueError(f"Label column '{label_col}' not found. Available: {list(df.columns)}")

    X = _prepare_features(df)
    y_raw = df[label_col].astype(str).str.strip()

    # Binary: BENIGN = 0, anything else = 1 (attack)
    y = (y_raw != "BENIGN").astype(int)
    print(f"[model] Class distribution — Normal: {(y==0).sum()}, Attack: {(y==1).sum()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_test_sc  = scaler.transform(X_test)

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        class_weight="balanced",   # handles imbalanced datasets
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train_sc, y_train)

    y_pred = model.predict(X_test_sc)

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)

    report = (
        f"Random Forest Report\n"
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"{'─'*40}\n"
        f"Accuracy  : {acc:.4f}\n"
        f"Precision : {prec:.4f}\n"
        f"Recall    : {rec:.4f}\n"
        f"F1 Score  : {f1:.4f}\n"
        f"{'─'*40}\n"
        f"{classification_report(y_test, y_pred, target_names=['Normal','Attack'])}\n"
        f"Confusion Matrix:\n{confusion_matrix(y_test, y_pred)}\n"
        f"{'─'*40}\n"
        f"Top 5 features by importance:\n"
    )

    importances = pd.Series(model.feature_importances_, index=FEATURE_COLS)
    top5 = importances.nlargest(5)
    for feat, imp in top5.items():
        report += f"  {feat:<25} {imp:.4f}\n"

    print(report)

    _save(model,  MODEL_PATH)
    _save(scaler, SCALER_PATH)

    with open(REPORT_PATH, "w") as f:
        f.write(report)

    return model, scaler


# ─────────────────────────────────────────────────────
# 3. Predict — used by Agent 3 at runtime
# ─────────────────────────────────────────────────────

ATTACK_TYPES = {
    "brute_force"  : lambda r: r["login_attempt"] and r["is_auth_fail"] and r["ip_error_count"] >= 3,
    "port_scan"    : lambda r: r["ip_total_requests"] > 50 and r["error_rate_ip"] > 0.8,
    "web_attack"   : lambda r: r["is_error"] and r["login_attempt"] and not r["is_auth_fail"],
    "unknown"      : lambda r: True,   # fallback
}

def classify_attack_type(row: pd.Series) -> str:
    """Return a human-readable attack type label for a suspicious row."""
    for attack, rule in ATTACK_TYPES.items():
        try:
            if rule(row):
                return attack
        except Exception:
            continue
    return "unknown"


def predict(df: pd.DataFrame) -> pd.DataFrame:
    """
    Load saved model + scaler and score new log entries.

    Parameters
    ----------
    df : DataFrame from parse_log_file() + extract_features()

    Returns
    -------
    df with added columns:
        prediction    :  1 (normal) or -1 (suspicious/attack)
        confidence    : float 0-1 (higher = more suspicious)
        label         : "Normal" | "Suspicious" | "Attack"
        attack_type   : e.g. "brute_force", "port_scan", etc.
    """
    if not MODEL_PATH.exists():
        raise FileNotFoundError("No trained model found. Run train_isolation_forest() or train_random_forest() first.")

    model  = _load(MODEL_PATH)
    scaler = _load(SCALER_PATH)

    X = _prepare_features(df)
    X_scaled = scaler.transform(X)

    df = df.copy()

    if isinstance(model, IsolationForest):
        raw_preds = model.predict(X_scaled)
        scores    = model.decision_function(X_scaled)
        # Normalise score → 0-1 confidence (higher = more anomalous)
        s_min, s_max = scores.min(), scores.max()
        if s_max != s_min:
            confidence = 1 - (scores - s_min) / (s_max - s_min)
        else:
            confidence = np.zeros(len(scores))
        df["prediction"]  = raw_preds
        df["confidence"]  = np.round(confidence, 3)

    elif isinstance(model, RandomForestClassifier):
        raw_preds  = model.predict(X_scaled)
        proba      = model.predict_proba(X_scaled)[:, 1]  # prob of attack class
        # Map back: 1 = attack → -1 for consistency, 0 = normal → 1
        df["prediction"] = np.where(raw_preds == 1, -1, 1)
        df["confidence"] = np.round(proba, 3)

    df["label"] = df["prediction"].map({1: "Normal", -1: "Suspicious"})

    # Upgrade label to "Attack" if confidence is high
    df.loc[(df["prediction"] == -1) & (df["confidence"] >= 0.75), "label"] = "Attack"

    # Classify attack type for flagged rows
    flagged = df["prediction"] == -1
    df["attack_type"] = "—"
    df.loc[flagged, "attack_type"] = df[flagged].apply(classify_attack_type, axis=1)

    return df


# ─────────────────────────────────────────────────────
# Quick test — run directly
# ─────────────────────────────────────────────────────

def _make_sample_df() -> pd.DataFrame:
    """Build a small synthetic log DataFrame for testing."""
    rows = [
        # Normal browsing
        dict(status=200, size=2048, hour=14, is_error=False,  is_auth_fail=False, login_attempt=False, ip_total_requests=5,  ip_error_count=0, error_rate_ip=0.00, is_new_ip=False),
        dict(status=200, size=1024, hour=11, is_error=False,  is_auth_fail=False, login_attempt=False, ip_total_requests=8,  ip_error_count=1, error_rate_ip=0.12, is_new_ip=False),
        # Brute force attack — many auth failures on /login
        dict(status=401, size=512,  hour=3,  is_error=True,   is_auth_fail=True,  login_attempt=True,  ip_total_requests=20, ip_error_count=18, error_rate_ip=0.90, is_new_ip=False),
        dict(status=401, size=512,  hour=3,  is_error=True,   is_auth_fail=True,  login_attempt=True,  ip_total_requests=20, ip_error_count=18, error_rate_ip=0.90, is_new_ip=False),
        dict(status=401, size=512,  hour=3,  is_error=True,   is_auth_fail=True,  login_attempt=True,  ip_total_requests=20, ip_error_count=18, error_rate_ip=0.90, is_new_ip=False),
        # Port scan — many requests, mostly errors, new IP
        dict(status=404, size=128,  hour=2,  is_error=True,   is_auth_fail=False, login_attempt=False, ip_total_requests=80, ip_error_count=70, error_rate_ip=0.88, is_new_ip=True),
        # Normal API request
        dict(status=200, size=4096, hour=9,  is_error=False,  is_auth_fail=False, login_attempt=False, ip_total_requests=3,  ip_error_count=0, error_rate_ip=0.00, is_new_ip=False),
    ]
    return pd.DataFrame(rows)


if __name__ == "__main__":
    df = _make_sample_df()

    print("=" * 50)
    print("Training Isolation Forest on sample data...")
    print("=" * 50)
    model, scaler, df_labeled = train_isolation_forest(df, contamination=0.3)

    print("=" * 50)
    print("Running predictions...")
    print("=" * 50)
    results = predict(df)

    print(results[["status", "login_attempt", "error_rate_ip", "label", "confidence", "attack_type"]].to_string(index=False))
    print("\n[model] Done. Model saved to ml/model.pkl")
