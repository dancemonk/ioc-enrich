import json
import unittest
from datetime import date
from pathlib import Path

from ioc_enrich.models import IOC
from ioc_enrich.sources import bazaar, threatfox, urlhaus
from tests.fakes import FakeHttp, json_response

FIX = Path(__file__).parent / "fixtures"
TODAY = date(2026, 10, 31)
TF = "https://threatfox-api.abuse.ch/api/v1/"
UH = "https://urlhaus-api.abuse.ch/v1/"
MB = "https://mb-api.abuse.ch/api/v1/"
SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"


def fixture(name):
    return json_response(json.loads((FIX / name).read_text()))


class ThreatFoxTest(unittest.TestCase):
    def test_hit_domain_exact_match(self):
        http = FakeHttp({("POST", TF): fixture("tf_hit.json")})
        r = threatfox.lookup(IOC("domain", "www.x.com"), "K", http, TODAY)
        self.assertEqual((r.status, r.fields["families"], r.flagged), ("ok", ["Formbook", "XLoader"], True))
        _, _, body, headers = http.calls[0]
        self.assertEqual(body, {"query": "search_ioc", "search_term": "www.x.com", "exact_match": True})
        self.assertEqual(headers["Auth-Key"], "K")

    def test_none(self):
        http = FakeHttp({("POST", TF): fixture("tf_none.json")})
        self.assertEqual(threatfox.lookup(IOC("ip", "1.2.3.4"), "K", http, TODAY).status, "not_listed")

    def test_hash_query(self):
        http = FakeHttp({("POST", TF): fixture("tf_none.json")})
        threatfox.lookup(IOC("sha256", SHA), "K", http, TODAY)
        self.assertEqual(http.calls[0][2], {"query": "search_hash", "hash": SHA})

    def test_sha1_refused(self):
        with self.assertRaises(ValueError):
            threatfox.lookup(IOC("sha1", SHA1), "K", FakeHttp(), TODAY)

    def test_bad_key(self):
        http = FakeHttp({("POST", TF): json_response({"query_status": "unknown_auth_key"})})
        r = threatfox.lookup(IOC("domain", "x.com"), "K", http, TODAY)
        self.assertEqual((r.status, r.reason), ("not_checked", "error: unknown_auth_key"))


class UrlhausTest(unittest.TestCase):
    def test_host(self):
        http = FakeHttp({("POST", UH + "host/"): fixture("uh_host_hit.json")})
        r = urlhaus.lookup(IOC("domain", "x.com"), "K", http, TODAY)
        self.assertEqual(r.fields, {"kind": "host", "url_count": 3, "threat": "malware_download"})
        self.assertTrue(r.flagged)
        self.assertEqual(http.calls[0][2], {"host": "x.com"})

    def test_url(self):
        http = FakeHttp({("POST", UH + "url/"): fixture("uh_url_hit.json")})
        r = urlhaus.lookup(IOC("url", "http://x.com/a"), "K", http, TODAY)
        self.assertEqual(r.fields, {"kind": "url", "threat": "malware_download", "url_status": "online"})

    def test_payload(self):
        http = FakeHttp({("POST", UH + "payload/"): fixture("uh_payload_hit.json")})
        r = urlhaus.lookup(IOC("sha256", SHA), "K", http, TODAY)
        self.assertEqual(r.fields, {"kind": "payload", "url_count": 2, "signature": "Mozi"})
        self.assertEqual(http.calls[0][2], {"sha256_hash": SHA})

    def test_none(self):
        http = FakeHttp({("POST", UH + "host/"): fixture("uh_none.json")})
        self.assertEqual(urlhaus.lookup(IOC("ip", "1.2.3.4"), "K", http, TODAY).status, "not_listed")


class BazaarTest(unittest.TestCase):
    def test_hit(self):
        http = FakeHttp({("POST", MB): fixture("mb_hit.json")})
        r = bazaar.lookup(IOC("sha256", SHA), "K", http, TODAY)
        self.assertEqual((r.status, r.fields["signature"], r.flagged), ("ok", "AgentTesla", True))
        self.assertEqual(http.calls[0][2], {"query": "get_info", "hash": SHA})

    def test_none(self):
        http = FakeHttp({("POST", MB): fixture("mb_none.json")})
        self.assertEqual(bazaar.lookup(IOC("md5", SHA[:32]), "K", http, TODAY).status, "not_listed")


if __name__ == "__main__":
    unittest.main()
