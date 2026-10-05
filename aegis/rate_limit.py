"""Quota protection: each service waits on its own clock."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from threading import Lock

TickFn = Callable[[float], None]

SERVICE_VIRUSTOTAL = "virustotal"
SERVICE_HYBRID = "hybrid"
SERVICE_METADEFENDER = "metadefender"

_SERVICE_LABEL = {
    SERVICE_VIRUSTOTAL: "VirusTotal",
    SERVICE_HYBRID: "Hybrid Analysis",
    SERVICE_METADEFENDER: "MetaDefender",
}


class RateLimiter:
    """Separate cooldown for each service, started when that service responds.

    A VirusTotal response does not delay the next Hybrid Analysis request, and
    a Hybrid Analysis response does not delay the next VirusTotal request.
    """

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
        self._last: dict[str, float] = {}

    def wait(self, service: str, log=None) -> None:
        """Pause until this service's cooldown, measured from its last response, has elapsed."""
        if not self.enabled:
            return
        label = _SERVICE_LABEL.get(service, service)
        announced = False
        while True:
            with self._lock:
                last = self._last.get(service)
                if last is None:
                    return
                remaining = self.delay_seconds - (time.monotonic() - last)
            if remaining <= 0:
                return
            if self.on_tick:
                try:
                    self.on_tick(remaining)
                except Exception:
                    pass
            if log and not announced:
                log(f"  Quota protection: waiting {remaining:.1f}s before the next {label} request...")
                announced = True
            time.sleep(min(0.2, remaining))

    def mark(self, service: str) -> None:
        """Start this service's cooldown. Call when its response has come back."""
        if not self.enabled:
            return
        with self._lock:
            self._last[service] = time.monotonic()

    @contextmanager
    def guard(self, service: str, log=None) -> Iterator[None]:
        """Wait for this service, run the request, then start its timer."""
        self.wait(service, log)
        try:
            yield
        finally:
            self.mark(service)
