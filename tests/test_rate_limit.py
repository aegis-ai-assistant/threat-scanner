"""Each lookup service keeps its own cooldown, started when that service responds."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from aegis.intel.gemini import generate_text
from aegis.rate_limit import SERVICE_HYBRID, SERVICE_VIRUSTOTAL, RateLimiter


class SplitClockTests(unittest.TestCase):
    def _limiter(self) -> tuple[RateLimiter, dict[str, float], list[float]]:
        clock = {"now": 100.0}
        sleeps: list[float] = []

        def monotonic() -> float:
            return clock["now"]

        def sleep(seconds: float) -> None:
            sleeps.append(seconds)
            clock["now"] += seconds

        limiter = RateLimiter(15, enabled=True)
        patcher_now = patch("aegis.rate_limit.time.monotonic", monotonic)
        patcher_sleep = patch("aegis.rate_limit.time.sleep", sleep)
        patcher_now.start()
        patcher_sleep.start()
        self.addCleanup(patcher_now.stop)
        self.addCleanup(patcher_sleep.stop)
        return limiter, clock, sleeps

    def test_a_response_starts_only_that_services_timer(self) -> None:
        limiter, clock, sleeps = self._limiter()
        with limiter.guard(SERVICE_VIRUSTOTAL):
            clock["now"] += 2  # the request itself takes time; the timer starts after it
        with limiter.guard(SERVICE_HYBRID):
            clock["now"] += 1
        self.assertEqual(sleeps, [])

        with limiter.guard(SERVICE_VIRUSTOTAL):
            pass
        self.assertAlmostEqual(sum(sleeps), 14, delta=0.05)

        hybrid_before = sum(sleeps)
        with limiter.guard(SERVICE_HYBRID):
            pass
        self.assertGreater(sum(sleeps), hybrid_before)

    def test_hybrid_does_not_wait_out_a_fresh_virustotal_response(self) -> None:
        limiter, clock, sleeps = self._limiter()
        with limiter.guard(SERVICE_VIRUSTOTAL):
            pass
        clock["now"] += 1
        with limiter.guard(SERVICE_HYBRID):
            pass
        self.assertEqual(sleeps, [])
        with limiter.guard(SERVICE_VIRUSTOTAL):
            pass
        self.assertAlmostEqual(sum(sleeps), 14, delta=0.01)


class GoogleAiDelayTests(unittest.TestCase):
    def test_repeated_google_calls_do_not_pause(self) -> None:
        sleeps: list[float] = []

        def answer(*_args, **_kwargs):
            return 200, "ok", None

        with (
            patch("aegis.intel.gemini._generate_once", answer),
            patch("aegis.rate_limit.time.sleep", lambda seconds: sleeps.append(seconds)),
        ):
            generate_text("key", "system", "one")
            generate_text("key", "system", "two")
        self.assertEqual(sleeps, [])


if __name__ == "__main__":
    unittest.main()
