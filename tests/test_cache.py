import tempfile
import unittest
from datetime import date
from pathlib import Path

from ioc_enrich.cache import Cache
from ioc_enrich.models import IOC, SourceResult

DAY = 86400
IOC1 = IOC("domain", "www.taibeinan.cc")


class CacheTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.now = 1_790_000_000.0
        self.cache = Cache(Path(self.tmp.name) / "sub" / "cache.sqlite", ttl_days=7, now=lambda: self.now)

    def tearDown(self):
        self.cache.close()
        self.tmp.cleanup()

    def test_put_get_roundtrip(self):
        result = SourceResult("VT", "ok", date(2026, 10, 30), fields={"malicious": 1, "words": ["malware"]}, flagged=True)
        self.cache.put("VT", IOC1, result)
        got = self.cache.get("VT", IOC1)
        self.assertEqual(got.fields, result.fields)
        self.assertEqual(got.fetched_on, date(2026, 10, 30))
        self.assertTrue(got.cached)
        self.assertTrue(got.flagged)
        self.assertIsNone(self.cache.get("OTX", IOC1))

    def test_ttl(self):
        self.cache.put("VT", IOC1, SourceResult("VT", "not_listed", date(2026, 10, 30)))
        self.now += 6 * DAY
        self.assertIsNotNone(self.cache.get("VT", IOC1))
        self.now += 1 * DAY + 1
        self.assertIsNone(self.cache.get("VT", IOC1))

    def test_not_checked_never_stored(self):
        self.cache.put("VT", IOC1, SourceResult("VT", "not_checked", date(2026, 10, 30), reason="quota"))
        self.assertIsNone(self.cache.get("VT", IOC1))

    def test_vt_call_counter_per_utc_day(self):
        for _ in range(3):
            self.cache.add_vt_call()
        self.assertEqual(self.cache.vt_calls_today(), 3)
        self.now += DAY
        self.assertEqual(self.cache.vt_calls_today(), 0)


if __name__ == "__main__":
    unittest.main()
