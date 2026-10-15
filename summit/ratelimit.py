"""Thread-safe client-side rate limiting.

Keeps summit polite: `--rate 5` means "at most 5 requests per second"
across all worker threads, enforced with one shared slot queue. The
clock and sleep function are injectable so the behavior is unit-testable
without real time.
"""

from __future__ import annotations

import threading
import time
from typing import Callable


class RateLimiter:
    """Serialize request starts so they are at least `interval` seconds apart."""

    def __init__(
        self,
        interval: float,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.interval = max(0.0, interval)
        self._clock = clock
        self._sleeper = sleeper
        self._lock = threading.Lock()
        self._next_slot = self._clock()

    def wait(self) -> None:
        if self.interval <= 0:
            return
        with self._lock:
            now = self._clock()
            target = max(now, self._next_slot)
            self._next_slot = target + self.interval
        delay = target - self._clock()
        if delay > 0:
            self._sleeper(delay)
