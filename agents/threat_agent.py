"""
agents/threat_agent.py
----------------------
Agent 3 — Threat Detection Agent

Receives enriched DataFrames from Agent 2.
Runs the saved ML model to score each entry.
Combines ML score + rule alerts → final threat decision.
Forwards confirmed threats to Agent 4 (AlertAgent).

Threat levels:
  CLEAR    — normal traffic, no action
  WATCH    — low-confidence anomaly, log only
  ALERT    — high-confidence attack, trigger Agent 4
"""

import queue
import threading
import pandas as pd
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from ml.train_model import predict, MODEL_PATH


THREAT_LEVEL = {
    "CLEAR" : 0,
    "WATCH" : 1,
    "ALERT" : 2,
}


class ThreatDetectionAgent:
    """
    Agent 3 — ML scoring + threat level assignment.

    Parameters
    ----------
    in_queue  : queue from Agent 2 (enriched DataFrames)
    out_queue : queue to Agent 4 (threat records)
    threshold : confidence threshold above which ALERT is raised (default 0.65)
    """

    def __init__(
        self,
        in_queue  : queue.Queue,
        out_queue : queue.Queue,
        threshold : float = 0.65,
    ):
        self.in_queue  = in_queue
        self.out_queue = out_queue
        self.threshold = threshold

        self._stop_event = threading.Event()
        self._thread     = None

        self.total_scored  = 0
        self.total_alerts  = 0
        self.total_watches = 0

        # Check model exists
        if not MODEL_PATH.exists():
            print("[ThreatAgent] ⚠ No trained model found at ml/model.pkl.")
            print("[ThreatAgent]   Run ml/train_model.py first, or call train() below.")
            self._model_ready = False
        else:
            self._model_ready = True
            print(f"[ThreatAgent] Model loaded from {MODEL_PATH}")

    # ── public API ──────────────────────────────────────

    def start(self):
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        print("[ThreatAgent] Started — waiting for enriched batches...")

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        print(f"[ThreatAgent] Stopped. Scored: {self.total_scored}, "
              f"Alerts: {self.total_alerts}, Watches: {self.total_watches}")

    def score_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Synchronous scoring — use in batch/offline mode.
        Returns df with threat_level, label, confidence, attack_type columns.
        """
        return self._score(df)

    # ── internal loop ───────────────────────────────────

    def _run_loop(self):
        while not self._stop_event.is_set():
            try:
                df = self.in_queue.get(timeout=1)
            except queue.Empty:
                continue

            if df is None:
                self.out_queue.put(None)
                break

            scored = self._score(df)
            threats = scored[scored["threat_level"].isin(["WATCH", "ALERT"])]

            if not threats.empty:
                self.out_queue.put(threats)
                self.total_alerts  += (threats["threat_level"] == "ALERT").sum()
                self.total_watches += (threats["threat_level"] == "WATCH").sum()

            self.total_scored += len(scored)

    # ── scoring logic ────────────────────────────────────

    def _score(self, df: pd.DataFrame) -> pd.DataFrame:
        """Run ML model + combine with rule alerts to assign threat_level."""
        df = df.copy()

        if self._model_ready:
            try:
                df = predict(df)
            except Exception as e:
                print(f"[ThreatAgent] Model prediction failed: {e}")
                df["label"]       = "Unknown"
                df["confidence"]  = 0.0
                df["attack_type"] = "—"

        else:
            # No model — fall back to rule alerts only
            df["label"]       = "Unknown"
            df["confidence"]  = 0.0
            df["attack_type"] = "—"

        df["threat_level"] = df.apply(self._assign_threat_level, axis=1)

        # Print summary for flagged rows
        flagged = df[df["threat_level"] != "CLEAR"]
        for _, row in flagged.iterrows():
            ip   = row.get("ip", "?")
            lvl  = row["threat_level"]
            conf = row.get("confidence", 0)
            atype = row.get("attack_type", "—")
            rule  = row.get("rule_alert", "")
            print(f"[ThreatAgent] {lvl:5s} | IP: {ip:<18} | {atype:<15} | "
                  f"conf: {conf:.2f} | rules: [{rule}]")

        return df

    def _assign_threat_level(self, row: pd.Series) -> str:
        """
        Combine ML label + rule alerts → final threat level.

        Logic:
          - ML Attack + confidence >= threshold  → ALERT
          - ML Suspicious OR any rule triggered  → WATCH
          - Everything else                      → CLEAR
        """
        label      = str(row.get("label", "Normal"))
        confidence = float(row.get("confidence", 0.0))
        rule_alert = str(row.get("rule_alert", ""))
        has_rule   = bool(rule_alert.strip())

        if label == "Attack" and confidence >= self.threshold:
            return "ALERT"

        if label in ("Suspicious", "Attack") or has_rule:
            return "WATCH"

        return "CLEAR"

    def status(self) -> dict:
        return {
            "agent"         : "ThreatDetectionAgent",
            "model_ready"   : self._model_ready,
            "total_scored"  : self.total_scored,
            "total_alerts"  : self.total_alerts,
            "total_watches" : self.total_watches,
            "threshold"     : self.threshold,
            "running"       : self._thread.is_alive() if self._thread else False,
        }
