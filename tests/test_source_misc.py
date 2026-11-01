import json
import unittest
from datetime import date
from pathlib import Path

from ioc_enrich.models import IOC
from ioc_enrich.sources import KEY_FIELD, LOOKUPS, abuseipdb, internetdb, otx, rdap
from tests.fakes import FakeHttp, json_response

FIX = Path(__file__).parent / "fixtures"
TODAY = date(2026, 10, 31)
OTX = "https://otx.alienvault.com/api/v1/indicators/"
ABUSE = "https://api.abuseipdb.com/api/v2/check?"


def fixture(name):
    return json_response(json.loads((FIX / name).read_text()))


class OtxTest(unittest.TestCase):
    def test_hostname_vs_domain(self):
        http = FakeHttp({("GET", OTX): fixture("otx_general.json")})
        r = otx.lookup(IOC("domain", "www.taibeinan.cc"), "K", http, TODAY)
        otx.lookup(IOC("domain", "taibeinan.cc"), "K", http, TODAY)
        self.assertEqual(http.calls[0][1], OTX + "hostname/www.taibeinan.cc/general")
        self.assertEqual(http.calls[1][1], OTX + "domain/taibeinan.cc/general")
        self.assertEqual(http.calls[0][3]["X-OTX-API-KEY"], "K")
        self.assertEqual((r.status, r.fields["pulses"], r.flagged), ("ok", 2, True))

    def test_url_is_quoted_and_zero_pulses(self):
        http = FakeHttp({("GET", OTX): json_response({"pulse_info": {"count": 0}})})
        r = otx.lookup(IOC("url", "http://x.com/a?b=1"), "K", http, TODAY)
        self.assertEqual(http.calls[0][1], OTX + "url/http%3A%2F%2Fx.com%2Fa%3Fb%3D1/general")
        self.assertEqual((r.status, r.fields["pulses"], r.flagged), ("not_listed", 0, False))

    def test_types(self):
        http = FakeHttp({("GET", OTX): json_response({}, status=404)})
        otx.lookup(IOC("ip", "1.2.3.4"), "K", http, TODAY)
        r = otx.lookup(IOC("md5", "d41d8cd98f00b204e9800998ecf8427e"), "K", http, TODAY)
        self.assertTrue(http.calls[0][1].startswith(OTX + "IPv4/"))
        self.assertTrue(http.calls[1][1].startswith(OTX + "file/"))
        self.assertEqual(r.status, "not_listed")


class AbuseIpdbTest(unittest.TestCase):
    def test_check(self):
        http = FakeHttp({("GET", ABUSE): fixture("abuseipdb_check.json")})
        r = abuseipdb.lookup(IOC("ip", "146.59.71.167"), "K", http, TODAY)
        self.assertEqual(http.calls[0][1], ABUSE + "ipAddress=146.59.71.167&maxAgeInDays=90")
        self.assertEqual(http.calls[0][3], {"Key": "K", "Accept": "application/json"})
        self.assertEqual((r.fields["score"], r.fields["reports"], r.flagged), (35, 12, True))

    def test_no_reports_not_flagged(self):
        http = FakeHttp({("GET", ABUSE): json_response({"data": {"abuseConfidenceScore": 0, "totalReports": 0}})})
        r = abuseipdb.lookup(IOC("ip", "1.2.3.4"), "K", http, TODAY)
        self.assertEqual((r.status, r.flagged), ("ok", False))


IDB = "https://internetdb.shodan.io/"


class InternetDbTest(unittest.TestCase):
    def test_lookup_needs_no_key_and_never_flags(self):
        http = FakeHttp({("GET", IDB): fixture("internetdb_host.json")})
        r = internetdb.lookup(IOC("ip", "146.59.71.167"), None, http, TODAY)
        self.assertEqual(http.calls[0][1], IDB + "146.59.71.167")
        self.assertEqual(r.status, "ok")
        self.assertEqual(r.fields, {"ports": [22, 80, 443], "vulns": ["CVE-2017-15906"], "tags": ["vpn"],
                                    "hostnames": ["vps-1234.example.net"]})
        self.assertFalse(r.flagged)                     # open ports are information, not a flag
        self.assertIs(LOOKUPS["InternetDB"], internetdb.lookup)
        self.assertIsNone(KEY_FIELD["InternetDB"])

    def test_404_is_not_listed(self):
        http = FakeHttp({("GET", IDB): json_response({"detail": "No information available"}, status=404)})
        self.assertEqual(internetdb.lookup(IOC("ip", "1.2.3.4"), None, http, TODAY).status, "not_listed")

    def test_http_error_is_not_checked(self):
        http = FakeHttp({("GET", IDB): json_response({}, status=500)})
        r = internetdb.lookup(IOC("ip", "1.2.3.4"), None, http, TODAY)
        self.assertEqual((r.status, r.reason), ("not_checked", "error: HTTP 500"))

    def test_odd_shapes_are_ignored(self):
        # Wrong types from the API must never break the enrichment text
        data = {"ports": "22", "vulns": None, "tags": [1, "cdn"], "hostnames": [{"x": 1}]}
        http = FakeHttp({("GET", IDB): json_response(data)})
        r = internetdb.lookup(IOC("ip", "1.2.3.4"), None, http, TODAY)
        self.assertEqual(r.fields, {"ports": [], "vulns": [], "tags": ["cdn"], "hostnames": []})


class RdapTest(unittest.TestCase):
    def test_registered_domain_queried(self):
        http = FakeHttp({("GET", "https://rdap.org/domain/"): fixture("rdap_domain.json")})
        r = rdap.lookup(IOC("domain", "www.taibeinan.cc"), None, http, TODAY)
        self.assertEqual(http.calls[0][1], "https://rdap.org/domain/taibeinan.cc")
        self.assertEqual(r.fields, {"created": "2026-05-16", "registrar": "Gname.com Pte. Ltd."})
        self.assertFalse(r.flagged)

    def test_malformed_registration_date_is_unknown(self):
        # Bug: a non-ISO eventDate later crashed the enrichment text (and the whole run's output)
        for event_date, expected in [("16-05-2026T00:00:00Z", None), ("2026-05-16", "2026-05-16"), ("", None)]:
            data = {"events": [{"eventAction": "registration", "eventDate": event_date}]}
            http = FakeHttp({("GET", "https://rdap.org/domain/"): json_response(data)})
            r = rdap.lookup(IOC("domain", "x.cc"), None, http, TODAY)
            self.assertEqual(r.fields["created"], expected, event_date)

    def test_404(self):
        http = FakeHttp({("GET", "https://rdap.org/domain/"): json_response({}, status=404)})
        self.assertEqual(rdap.lookup(IOC("domain", "x.cc"), None, http, TODAY).status, "not_listed")


class RegistryTest(unittest.TestCase):
    def test_all_sources_registered(self):
        self.assertEqual(set(LOOKUPS), {"VT", "ThreatFox", "URLhaus", "MalwareBazaar", "OTX", "AbuseIPDB", "RDAP", "InternetDB"})


if __name__ == "__main__":
    unittest.main()
