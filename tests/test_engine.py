import ipaddress
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

from ioc_enrich import engine
from ioc_enrich.cache import Cache
from ioc_enrich.config import Keys
from ioc_enrich.engine import RunOptions
from ioc_enrich.extract import extract
from ioc_enrich.lookup_plan import build_plan, keyed_sources
from ioc_enrich.http import RateLimited
from ioc_enrich.models import IOC
from tests.fakes import FakeHttp, json_response, text_response
from tests.test_extract import SAMPLE, TLDS
from tests.test_ratelimit import FakeTime

FIX = Path(__file__).parent / "fixtures"
VT = "https://www.virustotal.com/api/v3/"
RANGES = {"Cloudflare": [ipaddress.IPv4Network("172.64.0.0/13")]}
RDAP_TLDS = {"info", "cc"}
ALL_KEYS = Keys(vt="TESTKEY123", abusech="A", otx="O", abuseipdb="B")
TODAY = date(2026, 10, 31)


def fixture(name):
    return json_response(json.loads((FIX / name).read_text()))


def sample_routes():
    return {
        ("GET", VT + "domains/"): fixture("vt_domain.json"),
        ("GET", VT + "domains/www.independent.ie"): fixture("vt_domain_nodate.json"),
        ("GET", VT + "domains/independent.ie"): fixture("vt_domain_age.json"),
        ("GET", VT + "ip_addresses/"): fixture("vt_ip.json"),
        ("POST", "https://threatfox-api.abuse.ch/api/v1/"): fixture("tf_none.json"),
        ("POST", "https://urlhaus-api.abuse.ch/v1/host/"): fixture("uh_none.json"),
        ("GET", "https://otx.alienvault.com/api/v1/indicators/"): fixture("otx_general.json"),
        ("GET", "https://api.abuseipdb.com/api/v2/check?"): fixture("abuseipdb_check.json"),
        ("GET", "https://rdap.org/domain/"): fixture("rdap_domain.json"),
        ("GET", "https://internetdb.shodan.io/"): fixture("internetdb_host.json"),
    }


class EngineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = Cache(Path(self.tmp.name) / "c.sqlite")
        self.time = FakeTime()
        self.iocs = extract(SAMPLE, TLDS).iocs
        self.planned = self.make_plan()

    def tearDown(self):
        self.cache.close()
        self.tmp.cleanup()

    def make_plan(self, keys=ALL_KEYS, **options):
        return build_plan(self.iocs, allowlist=set(), cdn_ranges=RANGES, rdap_tlds=RDAP_TLDS,
                          keyed_sources=keyed_sources(keys), **options)

    def run_engine(self, http, keys=ALL_KEYS, no_vt=False, deep=False, **opts):
        plan = self.make_plan(keys, no_vt=no_vt, deep=deep)
        return engine.run(plan, keys, http, self.cache, RunOptions(**opts),
                          today=lambda: TODAY, sleep=self.time.sleep, clock=self.time.clock)

    def by_source(self, results, value, source):
        return [r for r in results[self.ioc(value)] if r.source == source]

    def ioc(self, value):
        return next(p.ioc for p in self.planned.items if p.ioc.value == value)

    def vt_urls(self, http):
        return [url for method, url, _, _ in http.calls if url.startswith(VT)]

    def test_sample_run(self):
        http = FakeHttp(sample_routes())
        results = self.run_engine(http)
        self.assertCountEqual(self.vt_urls(http), [
            VT + "domains/www.grinswakebthu.info", VT + "domains/www.taibeinan.cc",
            VT + "domains/www.independent.ie", VT + "ip_addresses/146.59.71.167",
            VT + "domains/independent.ie"])
        cdn_vt = self.by_source(results, "172.64.155.76", "VT")[0]
        self.assertEqual((cdn_vt.status, cdn_vt.reason), ("skipped", "shared CDN"))
        rdap_urls = [u for _, u, _, _ in http.calls if u.startswith("https://rdap.org/")]
        self.assertCountEqual(rdap_urls, ["https://rdap.org/domain/grinswakebthu.info", "https://rdap.org/domain/taibeinan.cc"])
        age = self.by_source(results, "www.independent.ie", "VT-age")[0]
        self.assertEqual(age.fields["creation_date"], "2001-01-12")
        self.assertNotIn(self.ioc("172.16.8.49"), results)   # private: skipped entirely

    def test_estimate(self):
        cost = engine.estimate(self.make_plan(), self.cache, RunOptions())
        self.assertEqual((cost.vt_calls, cost.vt_age_calls_max, cost.seconds), (4, 1, 75))
        self.assertEqual(cost.describe(5), "5 IOCs → 4 VirusTotal lookups (+ up to 1 for domain age), about 1 min 15 s")

    def test_describe_without_waiting(self):
        self.assertEqual(engine.Cost(0, 0, 3, 0).describe(2), "2 IOCs → 0 VirusTotal lookups, no wait")
        self.assertEqual(engine.Cost(2, 0, 3, 30).describe(2), "2 IOCs → 2 VirusTotal lookups, about 30 s")
        self.assertEqual(engine.Cost(4, 0, 3, 60).describe(1), "1 IOC → 4 VirusTotal lookups, about 1 min")

    def test_second_run_uses_cache(self):
        self.run_engine(FakeHttp(sample_routes()))
        http = FakeHttp(sample_routes())
        results = self.run_engine(http)
        self.assertEqual(http.calls, [])
        vt = self.by_source(results, "www.taibeinan.cc", "VT")[0]
        self.assertTrue(vt.cached)
        self.assertEqual(engine.estimate(self.make_plan(), self.cache, RunOptions()).vt_calls, 0)

    def test_429_once_then_ok(self):
        routes = sample_routes()
        routes[("GET", VT + "ip_addresses/")] = [RateLimited(None), fixture("vt_ip.json")]
        results = self.run_engine(FakeHttp(routes))
        self.assertIn(60, self.time.sleeps)
        self.assertEqual(self.by_source(results, "146.59.71.167", "VT")[0].status, "ok")

    def test_three_429_means_quota(self):
        routes = sample_routes()
        routes[("GET", VT)] = RateLimited(30.0)
        for key in [k for k in routes if k[1].startswith(VT) and k[1] != VT]:
            del routes[key]
        results = self.run_engine(FakeHttp(routes))
        for value in ["www.grinswakebthu.info", "www.taibeinan.cc", "www.independent.ie", "146.59.71.167"]:
            vt = self.by_source(results, value, "VT")[0]
            self.assertEqual((vt.status, vt.reason), ("not_checked", "quota"))
        self.assertEqual(self.time.sleeps.count(30.0), 2)
        self.assertEqual(self.by_source(results, "146.59.71.167", "AbuseIPDB")[0].status, "ok")

    def test_daily_limit_reached_no_wait(self):
        for _ in range(500):
            self.cache.add_vt_call()
        routes = sample_routes()
        routes[("GET", VT)] = RateLimited(None)
        for key in [k for k in routes if k[1].startswith(VT) and k[1] != VT]:
            del routes[key]
        results = self.run_engine(FakeHttp(routes))
        self.assertNotIn(60, self.time.sleeps)
        self.assertEqual(self.by_source(results, "www.taibeinan.cc", "VT")[0].reason, "quota")

    def test_long_retry_after_is_not_waited(self):
        # Review finding 2: a daily-limit 429 (Retry-After of hours) must not stall the run
        routes = sample_routes()
        routes[("GET", "https://api.abuseipdb.com/api/v2/check?")] = RateLimited(3600.0)
        routes[("GET", VT + "ip_addresses/")] = RateLimited(3600.0)
        results = self.run_engine(FakeHttp(routes))
        self.assertTrue(all(s <= 120 for s in self.time.sleeps), self.time.sleeps)
        abuse = self.by_source(results, "146.59.71.167", "AbuseIPDB")[0]
        self.assertEqual((abuse.status, abuse.reason), ("not_checked", "rate limited (retry after 3600 s)"))
        vt = self.by_source(results, "146.59.71.167", "VT")[0]
        self.assertEqual((vt.status, vt.reason), ("not_checked", "quota"))

    def test_deep_counts_every_vt_request(self):
        # Review finding 4: each relationship request is paced and counted
        routes = sample_routes()
        for value in ["www.taibeinan.cc", "www.grinswakebthu.info", "www.independent.ie"]:
            routes[("GET", VT + f"domains/{value}/resolutions")] = fixture("vt_resolutions.json")
        routes[("GET", VT + "ip_addresses/146.59.71.167/resolutions")] = json_response({}, status=500)
        http = FakeHttp(routes)
        results = self.run_engine(http, deep=True)
        self.assertEqual(self.cache.vt_calls_today(), len(self.vt_urls(http)))
        failed = self.by_source(results, "146.59.71.167", "VT-related:resolutions")[0]
        self.assertEqual(failed.status, "not_checked")
        self.assertIsNone(self.cache.get("VT-related:resolutions", self.ioc("146.59.71.167")))

    def test_ctrl_c_running_lookups_reach_cache_before_return(self):
        # Review finding 6: answers in flight at Ctrl-C must be cached before run() returns
        import threading
        import time as real_time

        def slow_none():
            real_time.sleep(0.3)
            return fixture("uh_none.json")

        class CtrlC(FakeHttp):
            def _answer(self, method, url, body, headers):
                if url.startswith(VT) and threading.current_thread() is threading.main_thread():
                    raise KeyboardInterrupt
                return super()._answer(method, url, body, headers)

        routes = sample_routes()
        routes[("POST", "https://urlhaus-api.abuse.ch/v1/host/")] = slow_none
        http = CtrlC(routes)
        with self.assertRaises(KeyboardInterrupt):
            self.run_engine(http)
        started = [body["host"] for _, url, body, _ in http.calls if url.endswith("/v1/host/")]
        self.assertTrue(started)
        for host in started:
            ioc = next(p.ioc for p in self.planned.items if p.ioc.value == host)
            self.assertIsNotNone(self.cache.get("URLhaus", ioc), host)

    def test_cancel_stops_after_current_lookup(self):
        import threading
        cancel = threading.Event()
        def first_vt_then_cancel():
            cancel.set()                      # the analyst presses Stop during the first VT request
            return fixture("vt_domain.json")
        routes = sample_routes()
        routes[("GET", VT + "domains/")] = first_vt_then_cancel
        http = FakeHttp(routes)
        plan = self.make_plan()
        results = engine.run(plan, ALL_KEYS, http, self.cache, RunOptions(), today=lambda: TODAY,
                             sleep=self.time.sleep, clock=self.time.clock, cancel=cancel)
        self.assertEqual(len(self.vt_urls(http)), 1)          # no further VT request after Stop
        self.assertTrue(any(r.source == "VT" for rs in results.values() for r in rs))

    def test_missing_key(self):
        results = self.run_engine(FakeHttp(sample_routes()), keys=Keys(vt="K", otx="O", abuseipdb="B"))
        tf = self.by_source(results, "www.taibeinan.cc", "ThreatFox")[0]
        self.assertEqual((tf.status, tf.reason), ("not_checked", "no key"))
        self.assertEqual(self.by_source(results, "www.taibeinan.cc", "OTX")[0].status, "ok")

    def test_source_errors_do_not_stop_run(self):
        # Review Focus 4
        routes = sample_routes()
        routes[("POST", "https://urlhaus-api.abuse.ch/v1/host/")] = TimeoutError("timed out")
        routes[("POST", "https://threatfox-api.abuse.ch/api/v1/")] = text_response("<html>oops</html>", status=500)
        routes[("GET", "https://otx.alienvault.com/api/v1/indicators/")] = text_response("not json")
        results = self.run_engine(FakeHttp(routes))
        uh = self.by_source(results, "www.taibeinan.cc", "URLhaus")[0]
        tf = self.by_source(results, "www.taibeinan.cc", "ThreatFox")[0]
        otx = self.by_source(results, "www.taibeinan.cc", "OTX")[0]
        self.assertEqual((uh.status, uh.reason), ("not_checked", "error: TimeoutError"))
        self.assertEqual((tf.status, tf.reason), ("not_checked", "error: HTTP 500"))
        self.assertEqual((otx.status, otx.reason), ("not_checked", "error: JSONDecodeError"))
        self.assertEqual(self.by_source(results, "www.taibeinan.cc", "VT")[0].status, "ok")

    def test_no_vt(self):
        http = FakeHttp(sample_routes())
        results = self.run_engine(http, no_vt=True)
        self.assertEqual(self.vt_urls(http), [])
        vt = self.by_source(results, "www.taibeinan.cc", "VT")[0]
        self.assertEqual((vt.status, vt.reason), ("not_checked", "--no-vt"))
        self.assertEqual(engine.estimate(self.make_plan(no_vt=True), self.cache, RunOptions()).vt_calls, 0)

    def test_deep(self):
        routes = sample_routes()
        routes[("GET", VT + "domains/www.taibeinan.cc/resolutions")] = fixture("vt_resolutions.json")
        routes[("GET", VT + "domains/www.grinswakebthu.info/resolutions")] = fixture("vt_resolutions.json")
        routes[("GET", VT + "domains/www.independent.ie/resolutions")] = fixture("vt_resolutions.json")
        routes[("GET", VT + "ip_addresses/146.59.71.167/resolutions")] = fixture("vt_resolutions.json")
        results = self.run_engine(FakeHttp(routes), deep=True)
        related = self.by_source(results, "www.taibeinan.cc", "VT-related:resolutions")[0]
        self.assertEqual(related.fields["resolutions"], ["2026-08-01 146.59.71.167"])
        fresh = Cache(Path(self.tmp.name) / "c2.sqlite")
        self.assertEqual(engine.estimate(self.make_plan(deep=True), fresh, RunOptions()).vt_calls, 8)
        fresh.close()

    def test_no_dns_lookups(self):
        with mock.patch("socket.getaddrinfo", side_effect=AssertionError("DNS lookup attempted")), \
             mock.patch("socket.gethostbyname", side_effect=AssertionError("DNS lookup attempted")):
            self.iocs = extract(SAMPLE, TLDS).iocs
            self.run_engine(FakeHttp(sample_routes()))


if __name__ == "__main__":
    unittest.main()
