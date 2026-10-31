import json
import unittest
from datetime import date
from pathlib import Path

from ioc_enrich.http import RateLimited
from ioc_enrich.models import IOC
from ioc_enrich.sources import vt
from tests.fakes import FakeHttp, json_response

FIX = Path(__file__).parent / "fixtures"
TODAY = date(2026, 10, 31)
API = "https://www.virustotal.com/api/v3/"
SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def fixture(name):
    return json_response(json.loads((FIX / name).read_text()))


class VtTest(unittest.TestCase):
    def test_domain(self):
        http = FakeHttp({("GET", API + "domains/"): fixture("vt_domain.json")})
        r = vt.lookup(IOC("domain", "www.grinswakebthu.info"), "K", http, TODAY)
        self.assertEqual((r.status, r.fields["malicious"] + r.fields["suspicious"], r.fields["total"]), ("ok", 2, 92))
        self.assertEqual(r.fields["words"], ["malicious", "malware"])
        self.assertEqual(r.fields["creation_date"], "2026-05-15")
        self.assertTrue(r.flagged)
        method, url, _, headers = http.calls[0]
        self.assertEqual((method, url, headers["x-apikey"]), ("GET", API + "domains/www.grinswakebthu.info", "K"))

    def test_clean_ip_not_flagged_words_empty(self):
        http = FakeHttp({("GET", API + "ip_addresses/"): fixture("vt_ip.json")})
        r = vt.lookup(IOC("ip", "146.59.71.167"), "K", http, TODAY)
        self.assertEqual(r.fields["malicious"], 1)
        self.assertIsNone(r.fields["creation_date"])

    def test_url_uses_id_without_padding(self):
        url = "http://www.independent.ie/ujvq/"
        self.assertNotIn("=", vt.url_id(url))
        http = FakeHttp({("GET", API + "urls/"): fixture("vt_url.json")})
        r = vt.lookup(IOC("url", url), "K", http, TODAY)
        self.assertEqual(http.calls[0][1], API + "urls/" + vt.url_id(url))
        self.assertTrue(r.flagged)

    def test_file_uses_threat_label(self):
        http = FakeHttp({("GET", API + "files/"): fixture("vt_file.json")})
        r = vt.lookup(IOC("sha256", SHA), "K", http, TODAY)
        self.assertEqual(r.fields["words"], ["trojan.xloader/formbook"])

    def test_404_not_listed(self):
        http = FakeHttp({("GET", API + "files/"): json_response({"error": {"code": "NotFoundError"}}, status=404)})
        r = vt.lookup(IOC("sha256", SHA), "K", http, TODAY)
        self.assertEqual(r.status, "not_listed")
        self.assertFalse(r.flagged)

    def test_other_error_not_checked(self):
        http = FakeHttp({("GET", API + "files/"): json_response({"error": {"code": "WrongCredentialsError"}}, status=401)})
        r = vt.lookup(IOC("sha256", SHA), "K", http, TODAY)
        self.assertEqual((r.status, r.reason), ("not_checked", "error: HTTP 401"))

    def test_rate_limit_passes_through(self):
        http = FakeHttp({("GET", API + "files/"): RateLimited(30.0)})
        with self.assertRaises(RateLimited):
            vt.lookup(IOC("sha256", SHA), "K", http, TODAY)

    def test_lookup_age(self):
        http = FakeHttp({("GET", API + "domains/"): fixture("vt_domain_age.json")})
        r = vt.lookup_age("independent.ie", "K", http, TODAY)
        self.assertEqual((r.source, r.fields["creation_date"]), ("VT-age", "2001-01-12"))
        self.assertEqual(http.calls[0][1], API + "domains/independent.ie")

    def test_related(self):
        http = FakeHttp({("GET", API + "domains/"): fixture("vt_resolutions.json"),
                         ("GET", API + "files/"): [fixture("vt_contacted_domains.json"), fixture("vt_contacted_ips.json")]})
        r = vt.lookup_related(IOC("domain", "www.grinswakebthu.info"), "resolutions", "K", http, TODAY)
        self.assertEqual(http.calls[0][1], API + "domains/www.grinswakebthu.info/resolutions?limit=10")
        self.assertEqual(r.fields, {"resolutions": ["2026-08-01 146.59.71.167"]})
        r1 = vt.lookup_related(IOC("sha256", SHA), "contacted_domains", "K", http, TODAY)
        r2 = vt.lookup_related(IOC("sha256", SHA), "contacted_ips", "K", http, TODAY)
        self.assertEqual((r1.fields, r2.fields), ({"contacted_domains": ["evil.example"]}, {"contacted_ips": ["203.0.113.9"]}))
        self.assertEqual(len(http.calls), 3)          # one request per call
        self.assertEqual(vt.relationships_for(IOC("sha256", SHA)), ["contacted_domains", "contacted_ips"])
        self.assertEqual(vt.relationships_for(IOC("ip", "1.2.3.4")), ["resolutions"])
        self.assertEqual(vt.relationships_for(IOC("url", "http://x.com/")), [])

    def test_related_failure_not_checked(self):
        http = FakeHttp({("GET", API + "files/"): json_response({}, status=500)})
        r = vt.lookup_related(IOC("sha256", SHA), "contacted_ips", "K", http, TODAY)
        self.assertEqual((r.status, r.reason), ("not_checked", "error: HTTP 500"))


if __name__ == "__main__":
    unittest.main()
