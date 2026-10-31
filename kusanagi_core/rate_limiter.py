"""
Thread-safe rate limiter.

Serializes outbound requests so at most one request fires every
`delay` seconds. Works correctly with multi-threading: threads
that would fire too soon block on the shared lock and are released
in order.
"""

import threading
import time


class RateLimiter:
    def __init__(self, delay_seconds=0.0):
        self.delay = max(0.0, float(delay_seconds))
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self):
        """Sleep if needed to enforce the delay between requests."""
        if self.delay <= 0:
            return
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
            self._last = time.monotonic()