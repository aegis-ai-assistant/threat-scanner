"""Quota protection: delay between public-tier API requests."""

from __future__ import annotations

import time
from collections.abc import Callable
from threading import Lock

TickFn = Callable[[float], None]


class RateLimiter:
    def __init__(
        self,
        delay_seconds: float,
        enabled: bool = True,
        on_tick: TickFn | None = None,
    ) -> None:
        self.delay_seconds = delay_seconds
        self.enabled = enabled and delay_seconds > 0
        self.on_tick = on_tick
        self._lock = Lock()
        self._last = 0.0

    def wait(self, log=None) -> None:
        if not self.enabled:
            return
        with self._lock:
            announced = False
            while True:
                remaining = self.delay_seconds - (time.monotonic() - self._last)
                if remaining <= 0:
                    break
                if self.on_tick:
                    try:
                        self.on_tick(remaining)
                    except Exception:
                        pass
                if log and not announced:
                    log(f"  Quota protection: waiting {remaining:.1f}s before next API request...")
                    announced = True
                time.sleep(min(0.2, remaining))
            self._last = time.monotonic()
