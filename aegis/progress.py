"""Scan progress / ETA tracking for the GUI status bar."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

EmitFn = Callable[[dict[str, Any]], None]


class ProgressTracker:
    def __init__(self, total: int, emit: EmitFn | None = None) -> None:
        self.total = max(int(total), 0)
        self.emit = emit
        self.index = 0
        self.filename = ""
        self.durations: list[float] = []
        self._file_t0: float | None = None

    def begin_file(self, index: int, name: str) -> None:
        self.index = index
        self.filename = name
        self._file_t0 = time.monotonic()
        self._push(f"Processing [{name}]...")

    def waiting(self, remaining: float) -> None:
        name = self.filename or "file"
        self._push(
            f"Processing [{name}]... Waiting {remaining:.1f}s (API Rate Protection)",
            wait_seconds=remaining,
        )

    def end_file(self) -> None:
        if self._file_t0 is not None:
            self.durations.append(max(time.monotonic() - self._file_t0, 0.0))
            self._file_t0 = None
        if self.filename:
            self._push(f"Finished [{self.filename}]")

    def eta_seconds(self) -> float:
        done = len(self.durations)
        avg = (sum(self.durations) / done) if done else 16.0
        in_flight = self._file_t0 is not None
        current_elapsed = (time.monotonic() - self._file_t0) if in_flight else 0.0
        current_remain = max(avg - current_elapsed, 0.0) if in_flight else 0.0
        others = max(self.total - done - (1 if in_flight else 0), 0)
        return current_remain + others * avg

    def _push(self, status: str, wait_seconds: float = 0.0) -> None:
        if not self.emit:
            return
        total = self.total or 1
        self.emit(
            {
                "type": "progress",
                "total": self.total,
                "index": self.index,
                "filename": self.filename,
                "status": status,
                "fraction": min(self.index / total, 1.0) if self.total else 0.0,
                "eta_seconds": self.eta_seconds(),
                "wait_seconds": wait_seconds,
            }
        )
