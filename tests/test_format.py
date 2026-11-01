import unittest
from datetime import date

from ioc_enrich.lookup_plan import PlannedIOC
from ioc_enrich.format import checked_on, enrichment, flagged_by, plan_status, screen_line
from ioc_enrich.models import IOC, SourceResult

D = date(2026, 10, 31)
INCIDENT = date(2026, 8, 9)
DOM = IOC("domain", "www.grinswakebthu.info")


def R(source, status="ok", fields=None, reason="", flagged=False, fetched=D, cached=False):
    return SourceResult(source, status, fetched, reason=reason, fields=fields or {}, flagged=flagged, cached=cached)


def vt(m, total=92, words=(), created=None):
    return R("VT", fields={"malicious": m, "suspicious": 0, "total": total, "words": list(words),
                           "creation_date": created}, flagged=m > 0)


class EnrichmentTest(unittest.TestCase):
    def test_full_domain_string(self):
        results = [R("OTX", "not_listed", {"pulses": 0}), R("RDAP", fields={"created": "2026-05-15", "registrar": "X"}),
                   vt(2, words=["malicious", "malware"]), R("URLhaus", "not_listed"), R("ThreatFox", "not_listed")]
        self.assertEqual(enrichment(DOM, results, INCIDENT),
                         "ThreatFox: not listed; VT 2/92 (malicious, malware); URLhaus: not listed; "
                         "OTX: 0 pulses; created 2026-05-15 via RDAP (86 d before incident)")

    def test_vt_age_fallback(self):
        ioc = IOC("domain", "www.independent.ie")
        results = [vt(0), R("VT-age", fields={"creation_date": "2001-01-12"})]
        self.assertEqual(enrichment(ioc, results, INCIDENT), "VT 0/92; created 2001-01-12 via VT (9340 d before incident)")

    def test_age_variants(self):
        self.assertEqual(enrichment(DOM, [R("RDAP", fields={"created": "2026-08-12"})], INCIDENT),
                         "created 2026-08-12 via RDAP (3 d after incident)")
        self.assertEqual(enrichment(DOM, [R("RDAP", fields={"created": "2026-05-15"})], None),
                         "created 2026-05-15 via RDAP")
        self.assertEqual(enrichment(DOM, [vt(0)], INCIDENT), "VT 0/92; age n/a")
        self.assertEqual(enrichment(DOM, [vt(0, created="2026-05-01")], None), "VT 0/92; created 2026-05-01 via VT")

    def test_unchecked_age_lookup_says_why(self):
        # Bug found in the browser: a stopped VT-age lookup read as plain "age n/a"
        ioc = IOC("domain", "www.independent.ie")
        results = [vt(0), R("VT-age", "not_checked", reason="stopped")]
        self.assertEqual(enrichment(ioc, results, INCIDENT), "VT 0/92; age not checked (stopped)")

    def test_ip_parts(self):
        ip = IOC("ip", "146.59.71.167")
        results = [R("AbuseIPDB", fields={"score": 35, "reports": 12}, flagged=True), R("OTX", fields={"pulses": 1}, flagged=True),
                   R("URLhaus", fields={"kind": "host", "url_count": 3, "threat": "malware_download"}, flagged=True),
                   R("ThreatFox", fields={"families": ["XLoader", "Formbook"]}, flagged=True), vt(1, words=["malware"])]
        self.assertEqual(enrichment(ip, results, None),
                         "ThreatFox: XLoader, Formbook; VT 1/92 (malware); URLhaus: 3 URLs (malware_download); "
                         "OTX: 1 pulse; AbuseIPDB: 35% (12 reports)")
        self.assertEqual(enrichment(ip, [R("AbuseIPDB", fields={"score": 0, "reports": 1})], None), "AbuseIPDB: 0% (1 report)")

    def test_hash_and_url_parts(self):
        h = IOC("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        results = [R("MalwareBazaar", fields={"signature": "AgentTesla"}, flagged=True), R("VT", "not_listed"),
                   R("URLhaus", fields={"kind": "payload", "url_count": 2, "signature": "Mozi"}, flagged=True)]
        self.assertEqual(enrichment(h, results, None),
                         "VT: not found; URLhaus: payload on 2 URLs (Mozi); MalwareBazaar: AgentTesla")
        url = IOC("url", "http://x.com/a")
        self.assertEqual(enrichment(url, [R("URLhaus", fields={"kind": "url", "threat": "malware_download", "url_status": "online"}, flagged=True)], None),
                         "URLhaus: malware_download (online)")

    def test_not_checked_states(self):
        ip = IOC("ip", "172.64.155.76")
        results = [R("VT", "skipped", reason="shared CDN"), R("ThreatFox", "not_checked", reason="no key"),
                   R("AbuseIPDB", "not_checked", reason="quota")]
        self.assertEqual(enrichment(ip, results, None),
                         "ThreatFox: not checked (no key); VT: skipped (shared CDN); AbuseIPDB: not checked (quota)")
        self.assertEqual(enrichment(ip, [R("VT", "not_checked", reason="--no-vt")], None), "VT: off (--no-vt)")


class FlaggedByTest(unittest.TestCase):
    def test_flagged(self):
        results = [R("AbuseIPDB", fields={"score": 35, "reports": 12}, flagged=True), vt(2),
                   R("ThreatFox", fields={"families": ["XLoader"]}, flagged=True), R("OTX", fields={"pulses": 2}, flagged=True)]
        self.assertEqual(flagged_by(results), "flagged by: VT 2/92, ThreatFox, OTX 2 pulses, AbuseIPDB 12 reports")

    def test_none_and_not_checked(self):
        self.assertEqual(flagged_by([vt(0), R("OTX", "not_listed", {"pulses": 0})]), "flagged by: none")
        self.assertEqual(flagged_by([R("VT", "not_checked", reason="quota")]), "not checked")
        # Info-only answers (RDAP, InternetDB) cannot flag, so they never make "flagged by: none"
        idb = R("InternetDB", fields={"ports": [80], "vulns": [], "tags": [], "hostnames": []})
        self.assertEqual(flagged_by([idb, R("VT", "not_checked", reason="no key")]), "not checked")
        self.assertEqual(flagged_by([R("RDAP", fields={"created": "2026-05-16"})]), "not checked")
        self.assertEqual(flagged_by([idb, vt(0)]), "flagged by: none")


class CheckedOnTest(unittest.TestCase):
    def test_checked_on_oldest(self):
        results = [vt(0), R("OTX", "not_listed", fetched=date(2026, 10, 26), cached=True),
                   R("ThreatFox", "not_checked", reason="x", fetched=date(2026, 1, 1))]
        self.assertEqual(checked_on(results, D), date(2026, 10, 26))
        self.assertEqual(checked_on([], D), D)


class ScreenLineTest(unittest.TestCase):
    def test_lines(self):
        line = screen_line(PlannedIOC(DOM), [vt(2), R("OTX", "not_listed", {"pulses": 0}, cached=True)], None)
        self.assertTrue(line.startswith("domain www[.]grinswakebthu[.]info"))
        self.assertIn("flagged by: VT 2/92  |  VT 2/92; OTX: 0 pulses", line)
        self.assertTrue(line.endswith("(cached)"))
        private = screen_line(PlannedIOC(IOC("ip", "172.16.8.49"), skip="private"), [], None)
        self.assertEqual(private.split(), ["ip", "172[.]16[.]8[.]49", "skipped", "(private)"])
        cdn = screen_line(PlannedIOC(IOC("ip", "172.64.155.76"), cdn="Cloudflare"), [R("VT", "skipped", reason="shared CDN")], None)
        self.assertIn("[shared CDN (Cloudflare) - do not block]", cdn)
        allow = screen_line(PlannedIOC(IOC("domain", "www.independent.ie"), skip="allowlisted"), [], None)
        self.assertIn("allowlisted - not checked", allow)


class PlanStatusTest(unittest.TestCase):
    def test_hidden_reasons_are_left_out(self):
        from ioc_enrich.lookup_plan import Lookup
        ioc = IOC("domain", "www.taibeinan.cc")
        item = PlannedIOC(ioc, lookups=[Lookup(ioc, "VT", "VT", ioc, "not_checked", "no key"),
                                        Lookup(ioc, "OTX", "OTX", ioc, "not_checked", "--no-vt"),
                                        Lookup(ioc, "RDAP", "RDAP", ioc)])
        self.assertEqual(plan_status(item), "would ask: RDAP · not checked: VT (no key), OTX (--no-vt)")
        self.assertEqual(plan_status(item, hide_reasons={"no key"}), "would ask: RDAP · not checked: OTX (--no-vt)")


class SourceStatesTest(unittest.TestCase):
    def test_states_per_source(self):
        from ioc_enrich.format import source_states
        from ioc_enrich.lookup_plan import Lookup
        ioc = IOC("domain", "www.taibeinan.cc")
        lk = lambda s, outcome="ask", reason="": Lookup(ioc, s, s, ioc, outcome, reason)
        item = PlannedIOC(ioc, lookups=[lk("ThreatFox"), lk("VT"), lk("URLhaus", "not_checked", "no key"),
                                        lk("OTX", "not_checked", "--no-vt"), lk("RDAP")])
        results = [R("ThreatFox", "not_listed"), vt(2, words=["malware"]),
                   R("RDAP", fields={"created": "2026-05-16", "registrar": "X"})]
        states = source_states(item, results)
        self.assertEqual([(s["short"], s["state"]) for s in states],
                         [("TF", "clean"), ("VT", "flagged"), ("OTX", "not_checked"), ("RDAP", "info")])
        self.assertEqual(states[1]["name"], "VirusTotal")
        self.assertEqual(states[1]["detail"], "VT 2/92 (malware)")
        self.assertEqual(states[2]["detail"], "not checked (VirusTotal switched off)")   # no-key sources: banner

    def test_planned_before_answers(self):
        from ioc_enrich.format import source_states
        from ioc_enrich.lookup_plan import Lookup
        ioc = IOC("ip", "172.64.155.76")
        item = PlannedIOC(ioc, cdn="Cloudflare", lookups=[Lookup(ioc, "VT", "VT", ioc, "skipped", "shared CDN"),
                                                         Lookup(ioc, "OTX", "OTX", ioc)])
        self.assertEqual([(s["short"], s["state"], s["detail"]) for s in source_states(item, [])],
                         [("VT", "skipped", "skipped (shared CDN)"), ("OTX", "planned", "new request")])


class CachedChipTest(unittest.TestCase):
    def test_planned_lookup_with_cached_answer(self):
        from ioc_enrich.format import source_states
        from ioc_enrich.lookup_plan import Lookup
        ioc = IOC("domain", "www.taibeinan.cc")
        item = PlannedIOC(ioc, lookups=[Lookup(ioc, "VT", "VT", ioc), Lookup(ioc, "OTX", "OTX", ioc)])
        states = source_states(item, [], cached={"VT"})
        self.assertEqual([(s["short"], s["state"], s["detail"]) for s in states],
                         [("VT", "cached", "cached answer, no new request"), ("OTX", "planned", "new request")])


class EvidenceTierTest(unittest.TestCase):
    def test_strong_and_weak(self):
        from ioc_enrich.format import result_kind
        otx = R("OTX", fields={"pulses": 2}, flagged=True)
        abuse = R("AbuseIPDB", fields={"score": 35, "reports": 12}, flagged=True)
        self.assertEqual(result_kind([vt(2), otx]), "flag")                       # VT flagged: strong
        self.assertEqual(result_kind([vt(0), otx]), "weak")                       # only OTX: weak
        self.assertEqual(result_kind([otx, abuse]), "weak")                       # OTX + AbuseIPDB: still weak
        self.assertEqual(result_kind([R("ThreatFox", fields={"families": ["X"]}, flagged=True)]), "flag")
        self.assertEqual(result_kind([vt(0)]), "clean")
        idb = R("InternetDB", fields={"ports": [80], "vulns": [], "tags": [], "hostnames": []})
        self.assertEqual(result_kind([idb, R("VT", "not_checked", reason="no key")]), "info")   # only info answered
        self.assertEqual(result_kind([idb, vt(0)]), "clean")

    def test_chip_strength(self):
        from ioc_enrich.format import source_states
        from ioc_enrich.lookup_plan import Lookup
        ioc = IOC("ip", "146.59.71.167")
        item = PlannedIOC(ioc, lookups=[Lookup(ioc, "VT", "VT", ioc), Lookup(ioc, "OTX", "OTX", ioc)])
        states = source_states(item, [vt(1), R("OTX", fields={"pulses": 2}, flagged=True)])
        self.assertEqual([(s["short"], s["state"], s.get("strength")) for s in states],
                         [("VT", "flagged", "strong"), ("OTX", "flagged", "weak")])


class StrongGapTest(unittest.TestCase):
    # Bug: "weak signal" also covered "the strong sources were never asked"
    def test_gaps_name_unchecked_strong_sources(self):
        from ioc_enrich.format import strong_gaps
        otx = R("OTX", fields={"pulses": 2}, flagged=True)
        self.assertEqual(strong_gaps([R("VT", "not_checked", reason="--no-vt"), otx]), ["VT not asked (VirusTotal switched off)"])
        self.assertEqual(strong_gaps([R("VT", "skipped", reason="shared CDN"), R("ThreatFox", "not_checked", reason="no key")]),
                         ["TF not asked (no key)", "VT not asked (shared CDN)"])   # one phrase for every gap
        self.assertEqual(strong_gaps([vt(1), otx]), [])
        self.assertEqual(strong_gaps([R("OTX", "not_checked", reason="no key")]), [])   # OTX is not a strong source


class DistilledRowTest(unittest.TestCase):
    """Each fact once: numbers on the chips, other facts in Details."""

    def test_flagged_chips_carry_their_number(self):
        from ioc_enrich.format import source_states
        from ioc_enrich.lookup_plan import Lookup
        ioc = IOC("ip", "146.59.71.167")
        lk = lambda s: Lookup(ioc, s, s, ioc)
        item = PlannedIOC(ioc, lookups=[lk("ThreatFox"), lk("VT"), lk("OTX"), lk("AbuseIPDB")])
        results = [R("ThreatFox", fields={"families": ["XLoader", "Formbook"]}, flagged=True), vt(2),
                   R("OTX", fields={"pulses": 2}, flagged=True),
                   R("AbuseIPDB", fields={"score": 35, "reports": 12}, flagged=True)]
        metrics = {s["short"]: s.get("metric") for s in source_states(item, results)}
        self.assertEqual(metrics, {"TF": "XLoader", "VT": "2/92", "OTX": "2", "AIPDB": "12"})

    def test_row_details_only_what_chips_do_not_show(self):
        from ioc_enrich.format import row_details
        dom = IOC("domain", "www.taibeinan.cc")
        results = [vt(2), R("RDAP", fields={"created": "2026-05-16", "registrar": "Gname.com Pte. Ltd."})]
        self.assertEqual(row_details(dom, results, INCIDENT),
                         ["created 2026-05-16 via RDAP (85 d before incident)", "registrar Gname.com Pte. Ltd."])
        ip = IOC("ip", "146.59.71.167")
        self.assertEqual(row_details(ip, [R("AbuseIPDB", fields={"score": 35, "reports": 12}, flagged=True)], None),
                         ["AbuseIPDB score 35%"])
        self.assertEqual(row_details(ip, [R("VT", "not_checked", reason="error: TimeoutError"),
                                          R("OTX", "not_checked", reason="error: TimeoutError")], None),
                         ["not checked: OTX (error: TimeoutError)"])   # VT's gap is named by the headline, not repeated


class WebWordingTest(unittest.TestCase):
    def test_no_cli_flags_in_page_texts(self):
        from ioc_enrich.format import row_details, source_states
        from ioc_enrich.lookup_plan import Lookup
        ioc = IOC("ip", "146.59.71.167")
        item = PlannedIOC(ioc, lookups=[Lookup(ioc, "VT", "VT", ioc, "not_checked", "--no-vt")])
        results = [R("VT", "not_checked", reason="--no-vt")]
        self.assertEqual(source_states(item, results)[0]["detail"], "not checked (VirusTotal switched off)")
        self.assertEqual(row_details(ioc, results, None), [])   # the headline already says "VT not asked (…)"


class InternetDbTextTest(unittest.TestCase):
    IP = IOC("ip", "146.59.71.167")

    def idb(self, **fields):
        base = {"ports": [], "vulns": [], "tags": [], "hostnames": []}
        return R("InternetDB", fields={**base, **fields})

    def test_enrichment_part(self):
        r = self.idb(ports=[22, 80, 443], vulns=["CVE-2017-15906"], tags=["vpn"])
        self.assertEqual(enrichment(self.IP, [r], None),
                         "InternetDB: ports 22 80 443, 1 vuln (CVE-2017-15906), tag vpn")

    def test_long_lists_are_shortened(self):
        r = self.idb(ports=list(range(1, 13)), vulns=[f"CVE-2020-{n}" for n in range(5)], tags=["cdn", "cloud"])
        self.assertEqual(enrichment(self.IP, [r], None),
                         "InternetDB: ports 1 2 3 4 5 6 7 8 9 10 +2, "
                         "5 vulns (CVE-2020-0, CVE-2020-1, CVE-2020-2, +2), tags cdn cloud")

    def test_no_open_ports_and_not_listed(self):
        self.assertEqual(enrichment(self.IP, [self.idb()], None), "InternetDB: no open ports seen")
        self.assertEqual(enrichment(self.IP, [R("InternetDB", "not_listed")], None), "InternetDB: no data")

    def test_comes_after_the_threat_intel_sources(self):
        abuse = R("AbuseIPDB", fields={"score": 35, "reports": 12}, flagged=True)
        text = enrichment(self.IP, [self.idb(ports=[80]), abuse], None)
        self.assertEqual(text, "AbuseIPDB: 35% (12 reports); InternetDB: ports 80")

    def test_web_chip_and_details(self):
        from ioc_enrich.format import row_details, source_states
        from ioc_enrich.lookup_plan import Lookup
        item = PlannedIOC(self.IP, lookups=[Lookup(self.IP, "InternetDB", "InternetDB", self.IP)])
        r = self.idb(ports=[22, 443], vulns=["CVE-2017-15906"], tags=["vpn"])
        [chip] = source_states(item, [r])
        self.assertEqual((chip["short"], chip["name"], chip["state"]), ("IDB", "Shodan InternetDB", "info"))
        self.assertEqual(chip["detail"], "ports 22 443, 1 vuln (CVE-2017-15906), tag vpn")
        self.assertIn("open ports 22 443 · 1 vuln (CVE-2017-15906) · tag vpn", row_details(self.IP, [r], None))


if __name__ == "__main__":
    unittest.main()
