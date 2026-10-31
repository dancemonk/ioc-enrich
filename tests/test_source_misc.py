import json
import unittest
from datetime import date
from pathlib import Path

from ioc_enrich.models import IOC
from ioc_enrich.sources import LOOKUPS, abuseipdb, otx, rdap
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
        self.assertEqual(set(LOOKUPS), {"VT", "ThreatFox", "URLhaus", "MalwareBazaar", "OTX", "AbuseIPDB", "RDAP"})


if __name__ == "__main__":
    unittest.main()
