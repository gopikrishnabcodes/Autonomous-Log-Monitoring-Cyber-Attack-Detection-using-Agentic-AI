"""
agents/collector.py
-------------------
Agent 1 — Log Collector

Watches a log file (or folder) for new entries and pushes them
into a shared queue for Agent 2 to consume.

Works in two modes:
  - tail mode  : monitors a live file (like `tail -f`)
  - batch mode : reads a static file all at once (for testing / CICIDS CSV)

To swap in LangChain later, replace the AgentBase class with:
    from langchain.agents import AgentExecutor
"""

import os
import time
import queue
import threading
from pathlib import Path
from datetime import datetime


class LogCollectorAgent:
    """
    Agent 1 — reads new log lines and puts them into a queue.

    Parameters
    ----------
    log_path   : path to the log file to monitor
    out_queue  : queue.Queue shared with Agent 2 (LogAnalyzerAgent)
    poll_interval : seconds between file-size checks (default 1s)
    """

    def __init__(self, log_path: str, out_queue: queue.Queue, poll_interval: float = 1.0):
        self.log_path      = Path(log_path)
        self.out_queue     = out_queue
        self.poll_interval = poll_interval
        self._stop_event   = threading.Event()
        self._thread       = None
        self.lines_collected = 0

    # ── public API ──────────────────────────────────────

    def run_batch(self):
        """
        Read the entire log file at once (for offline/test use).
        Each line is placed on the queue immediately.
        """
        if not self.log_path.exists():
            print(f"[Collector] File not found: {self.log_path}")
            return

        print(f"[Collector] Batch mode — reading {self.log_path.name}")
        with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    self.out_queue.put({"raw": line, "source": str(self.log_path), "ts": datetime.now()})
                    self.lines_collected += 1

        self.out_queue.put(None)  # sentinel — signals end of stream
        print(f"[Collector] Batch complete. {self.lines_collected} lines queued.")

    def start_tail(self):
        """
        Start watching the file for new lines in a background thread.
        Non-blocking — returns immediately.
        """
        self._thread = threading.Thread(target=self._tail_loop, daemon=True)
        self._thread.start()
        print(f"[Collector] Tailing {self.log_path.name} (every {self.poll_interval}s)...")

    def stop(self):
        """Signal the tail thread to stop."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)
        print(f"[Collector] Stopped. Total lines collected: {self.lines_collected}")

    # ── internal ────────────────────────────────────────

    def _tail_loop(self):
        """Poll the file for new lines indefinitely."""
        # Wait for file to exist
        while not self.log_path.exists():
            print(f"[Collector] Waiting for {self.log_path.name}...")
            time.sleep(2)

        with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
            # Jump to end so we only catch NEW lines
            f.seek(0, 2)

            while not self._stop_event.is_set():
                line = f.readline()
                if line:
                    line = line.strip()
                    if line:
                        self.out_queue.put({
                            "raw"    : line,
                            "source" : str(self.log_path),
                            "ts"     : datetime.now()
                        })
                        self.lines_collected += 1
                else:
                    time.sleep(self.poll_interval)

    def status(self) -> dict:
        return {
            "agent"           : "LogCollector",
            "file"            : str(self.log_path),
            "lines_collected" : self.lines_collected,
            "queue_size"      : self.out_queue.qsize(),
            "running"         : self._thread.is_alive() if self._thread else False,
        }
