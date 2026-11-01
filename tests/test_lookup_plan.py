import ipaddress
import tempfile
import unittest
from datetime import date
from pathlib import Path

from ioc_enrich.config import Keys
from ioc_enrich.extract import extract
from ioc_enrich.lookup_plan import SOURCES_BY_TYPE, build_plan, keyed_sources, load_allowlist
from ioc_enrich.models import IOC, SourceResult
from tests.test_extract import SAMPLE, TLDS

RANGES = {"Cloudflare": [ipaddress.IPv4Network("172.64.0.0/13")]}
RDAP_TLDS = {"info", "cc"}
TODAY = date(2026, 10, 31)
SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def make_plan(iocs=None, **options):
    iocs = extract(SAMPLE, TLDS).iocs if iocs is None else iocs
    options.setdefault("allowlist", set())
    return build_plan(iocs, cdn_ranges=RANGES, rdap_tlds=RDAP_TLDS, **options)


def item(plan, value):
    return next(i for i in plan.items if i.ioc.value == value)


def outcomes(planned_ioc):
    """{source: (outcome, reason)} for one IOC's up-front lookups."""
    return {lk.source: (lk.outcome, lk.reason) for lk in planned_ioc.lookups}


def answer(source, status="ok", **fields):
    return SourceResult(source, status, TODAY, fields=fields)


class SkipAndCdnTest(unittest.TestCase):
    def test_sample_plan(self):
        plan = make_plan()
        self.assertEqual(item(plan, "172.16.8.49").skip, "private")
        self.assertEqual(item(plan, "172.16.8.49").lookups, [])
        self.assertEqual(item(plan, "172.64.155.76").cdn, "Cloudflare")
        self.assertIsNone(item(plan, "146.59.71.167").cdn)
        self.assertIsNone(item(plan, "www.taibeinan.cc").skip)

    def test_allowlist_covers_subdomains_only(self):
        iocs = [IOC("domain", "www.independent.ie"), IOC("domain", "notindependent.ie"),
                IOC("url", "http://www.independent.ie/x")]
        plan = make_plan(iocs, allowlist={"independent.ie"})
        self.assertEqual([i.skip for i in plan.items], ["allowlisted", None, "allowlisted"])

    def test_url_with_private_host_is_skipped(self):
        # Internal URLs must never be sent to VT
        iocs = [IOC("url", "http://192.168.1.10/admin/login.php"), IOC("url", "http://127.0.0.1:8080/x"),
                IOC("url", "http://146.59.71.167/a")]
        self.assertEqual([i.skip for i in make_plan(iocs).items], ["private", "private", None])

    def test_load_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "allowlist.txt"
            path.write_text("# known good\nIndependent.ie\n\nmicrosoft.com\n")
            self.assertEqual(load_allowlist(path), {"independent.ie", "microsoft.com"})
            self.assertEqual(load_allowlist(Path(tmp) / "missing.txt"), set())


class OutcomeTest(unittest.TestCase):
    def test_sources_by_type_and_rdap_applicability(self):
        plan = make_plan()
        self.assertEqual(outcomes(item(plan, "www.taibeinan.cc")),
                         {s: ("ask", "") for s in SOURCES_BY_TYPE["domain"]})
        # .ie has no RDAP server: the lookup is left out, not "not checked"
        self.assertNotIn("RDAP", outcomes(item(plan, "www.independent.ie")))

    def test_cdn_ip_skips_vt(self):
        self.assertEqual(outcomes(item(make_plan(), "172.64.155.76"))["VT"], ("skipped", "shared CDN"))

    def test_no_vt(self):
        plan = make_plan(no_vt=True)
        self.assertEqual(outcomes(item(plan, "www.taibeinan.cc"))["VT"], ("not_checked", "--no-vt"))
        self.assertEqual(outcomes(item(plan, "172.64.155.76"))["VT"], ("not_checked", "--no-vt"))
        self.assertEqual(outcomes(item(plan, "www.taibeinan.cc"))["ThreatFox"], ("ask", ""))

    def test_missing_keys(self):
        plan = make_plan(keyed_sources={"VT"})
        found = outcomes(item(plan, "www.taibeinan.cc"))
        self.assertEqual(found["ThreatFox"], ("not_checked", "no key"))
        self.assertEqual(found["VT"], ("ask", ""))
        self.assertEqual(found["RDAP"], ("ask", ""))          # RDAP needs no key

    def test_internetdb_asked_for_every_public_ip_without_a_key(self):
        plan = make_plan(keyed_sources=set())
        self.assertEqual(outcomes(item(plan, "146.59.71.167"))["InternetDB"], ("ask", ""))
        self.assertEqual(outcomes(item(plan, "172.64.155.76"))["InternetDB"], ("ask", ""))   # shared CDN too
        self.assertNotIn("InternetDB", outcomes(item(plan, "www.taibeinan.cc")))           # IPs only
        self.assertEqual(item(plan, "172.16.8.49").lookups, [])                            # private: never sent

    def test_dry_run_assumes_every_key(self):
        found = outcomes(item(make_plan(keyed_sources=None), "146.59.71.167"))
        self.assertTrue(all(outcome == "ask" for outcome, _ in found.values()))

    def test_keyed_sources(self):
        self.assertEqual(keyed_sources(Keys(vt="x", otx="y")), {"VT", "OTX"})
        self.assertEqual(keyed_sources(Keys(abusech="z")), {"ThreatFox", "URLhaus", "MalwareBazaar"})


class FollowUpTest(unittest.TestCase):
    def test_possible_follow_ups(self):
        plan = make_plan()
        age = plan.possible_follow_ups(IOC("domain", "www.independent.ie"))
        self.assertEqual([(lk.source, lk.cache_name, lk.cache_ioc) for lk in age],
                         [("VT-age", "VT-age", IOC("domain", "independent.ie"))])
        self.assertEqual(plan.possible_follow_ups(IOC("domain", "www.taibeinan.cc")), [])

    def test_possible_follow_ups_deep(self):
        plan = make_plan([IOC("domain", "www.taibeinan.cc"), IOC("sha256", SHA)], deep=True)
        self.assertEqual([lk.cache_name for lk in plan.possible_follow_ups(IOC("domain", "www.taibeinan.cc"))],
                         ["VT-related:resolutions"])
        self.assertEqual([lk.relationship for lk in plan.possible_follow_ups(IOC("sha256", SHA))],
                         ["contacted_domains", "contacted_ips"])

    def test_no_follow_ups_when_vt_not_asked(self):
        plan = make_plan(no_vt=True, deep=True)
        self.assertEqual(plan.possible_follow_ups(IOC("domain", "www.independent.ie")), [])

    def test_follow_ups_depend_on_answer(self):
        plan = make_plan()
        vt = next(lk for lk in item(plan, "www.independent.ie").lookups if lk.source == "VT")
        self.assertEqual([lk.source for lk in plan.follow_ups(vt, answer("VT", creation_date=None))], ["VT-age"])
        self.assertEqual(plan.follow_ups(vt, answer("VT", creation_date="2001-01-12")), [])
        self.assertEqual(plan.follow_ups(vt, answer("VT", "not_checked")), [])


class CompletenessTest(unittest.TestCase):
    def full_answers(self, plan, value, **vt_fields):
        return [answer(lk.source, **(vt_fields if lk.source == "VT" else {}))
                for lk in item(plan, value).lookups]

    def test_unanswered_up_front_lookup(self):
        plan = make_plan()
        ioc = IOC("domain", "www.taibeinan.cc")
        results = {ioc: [a for a in self.full_answers(plan, "www.taibeinan.cc") if a.source != "URLhaus"]}
        self.assertEqual([lk.source for lk in plan.unanswered(results)
                          if lk.ioc == ioc], ["URLhaus"])
        self.assertFalse(plan.is_complete(ioc, results))

    def test_pending_age_call_is_unanswered(self):
        plan = make_plan()
        ioc = IOC("domain", "www.independent.ie")
        results = {ioc: self.full_answers(plan, "www.independent.ie", creation_date=None)}
        self.assertEqual([lk.source for lk in plan.unanswered(results) if lk.ioc == ioc], ["VT-age"])

    def test_pending_related_call_is_unanswered(self):
        # Drifted bug: Ctrl-C backfill used to forget pending --deep lookups
        plan = make_plan(deep=True)
        ioc = IOC("domain", "www.taibeinan.cc")
        results = {ioc: self.full_answers(plan, "www.taibeinan.cc")}
        self.assertEqual([lk.source for lk in plan.unanswered(results) if lk.ioc == ioc],
                         ["VT-related:resolutions"])

    def test_complete_rows(self):
        plan = make_plan()
        cdn = IOC("ip", "172.64.155.76")
        results = {cdn: [answer(lk.source, "skipped" if lk.outcome == "skipped" else "ok")
                         for lk in item(plan, "172.64.155.76").lookups]}
        self.assertTrue(plan.is_complete(cdn, results))
        results[cdn][0] = answer(results[cdn][0].source, "not_checked")
        self.assertFalse(plan.is_complete(cdn, results))

    def test_skipped_iocs_have_nothing_unanswered(self):
        plan = make_plan()
        self.assertNotIn(IOC("ip", "172.16.8.49"), [lk.ioc for lk in plan.unanswered({})])


class ProgressTest(unittest.TestCase):
    def test_counts_answers_and_due_follow_ups(self):
        plan = make_plan([IOC("domain", "www.independent.ie"), IOC("ip", "146.59.71.167")])
        self.assertEqual(plan.progress({}), {"done": 0, "total": 10, "vt_done": 0, "vt_total": 2, "reused": 0})
        ie = IOC("domain", "www.independent.ie")
        # VT answered without a creation date: the VT-age follow-up becomes due (+1 VT lookup)
        results = {ie: [answer("VT", creation_date=None), answer("OTX")]}
        self.assertEqual(plan.progress(results), {"done": 2, "total": 11, "vt_done": 1, "vt_total": 3, "reused": 0})

    def test_cached_lookups_are_not_counted_as_sent(self):
        # Bug: "Sending to VirusTotal · 6 of 8" after the plan promised 3 new VT requests
        plan = make_plan([IOC("domain", "www.independent.ie"), IOC("ip", "146.59.71.167")])
        ip = IOC("ip", "146.59.71.167")
        reused = {(ip, "VT"), (ip, "OTX")}
        results = {ip: [answer("VT"), answer("OTX")]}
        self.assertEqual(plan.progress(results, reused=reused),
                         {"done": 0, "total": 8, "vt_done": 0, "vt_total": 1, "reused": 2})


if __name__ == "__main__":
    unittest.main()
