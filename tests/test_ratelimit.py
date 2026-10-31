import unittest

from ioc_enrich.ratelimit import RateLimiter


class FakeTime:
    def __init__(self):
        self.now = 1000.0
        self.sleeps = []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class RateLimiterTest(unittest.TestCase):
    def test_four_per_minute_spaces_15s(self):
        t = FakeTime()
        limiter = RateLimiter(4, clock=t.clock, sleep=t.sleep)
        for _ in range(3):
            limiter.wait()
        self.assertEqual(t.sleeps, [15.0, 15.0])

    def test_sixty_per_minute(self):
        t = FakeTime()
        limiter = RateLimiter(60, clock=t.clock, sleep=t.sleep)
        limiter.wait()
        limiter.wait()
        self.assertEqual(t.sleeps, [1.0])

    def test_no_sleep_when_enough_time_passed(self):
        t = FakeTime()
        limiter = RateLimiter(4, clock=t.clock, sleep=t.sleep)
        limiter.wait()
        t.now += 20
        limiter.wait()
        self.assertEqual(t.sleeps, [])


if __name__ == "__main__":
    unittest.main()
