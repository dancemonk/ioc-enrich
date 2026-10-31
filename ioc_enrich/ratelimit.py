"""A simple 'N calls per minute' limiter, safe to share between threads."""

import threading
import time


class RateLimiter:
    """Keeps calls at least 60/per_minute seconds apart.

    VirusTotal's free key allows 4 requests per minute, so calls are spaced
    15 seconds apart. The first call never waits.
    """

    def __init__(self, per_minute: int, clock=time.monotonic, sleep=time.sleep):
        self.interval = 60.0 / per_minute
        self.clock = clock
        self.sleep = sleep
        self.last_call = None
        self.lock = threading.Lock()

    def wait(self) -> None:
        with self.lock:
            if self.last_call is not None:
                remaining = self.last_call + self.interval - self.clock()
                if remaining > 0:
                    self.sleep(remaining)
            self.last_call = self.clock()
