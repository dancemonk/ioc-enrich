import ipaddress
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from ioc_enrich import lists
from ioc_enrich.update_lists import update_lists
from tests.fakes import FakeHttp, json_response, text_response

FIXTURES = Path(__file__).parent / "fixtures"

RANGES = {"Cloudflare": [ipaddress.IPv4Network("172.64.0.0/13"), ipaddress.IPv4Network("104.16.0.0/13")]}


class RegisteredDomainTest(unittest.TestCase):
    def test_two_labels(self):
        self.assertEqual(lists.registered_domain("www.taibeinan.cc"), "taibeinan.cc")
        self.assertEqual(lists.registered_domain("independent.ie"), "independent.ie")

    def test_two_part_suffix(self):
        self.assertEqual(lists.registered_domain("a.b.bbc.co.uk"), "bbc.co.uk")


class CdnTest(unittest.TestCase):
    def test_cdn_provider(self):
        self.assertEqual(lists.cdn_provider("172.64.155.76", RANGES), "Cloudflare")
        self.assertIsNone(lists.cdn_provider("146.59.71.167", RANGES))


class RdapBootstrapTest(unittest.TestCase):
    def test_parse_bootstrap(self):
        data = json.loads((FIXTURES / "rdap_dns.json").read_text())
        self.assertEqual(lists.rdap_tlds_from_bootstrap(data), {"info", "cc", "tv"})


class UpdateListsTest(unittest.TestCase):
    def test_writes_three_files_with_header(self):
        http = FakeHttp({
            ("GET", "https://data.iana.org/TLD/"): text_response("# Version 2026103100\nCOM\nIE\nCC\n"),
            ("GET", "https://data.iana.org/rdap/"): json_response(json.loads((FIXTURES / "rdap_dns.json").read_text())),
            ("GET", "https://www.cloudflare.com/ips-v4"): text_response("173.245.48.0/20\n104.16.0.0/13\n"),
            ("GET", "https://api.fastly.com/"): json_response({"addresses": ["23.235.32.0/20"], "ipv6_addresses": []}),
            ("GET", "https://ip-ranges.amazonaws.com/"): json_response({"prefixes": [
                {"ip_prefix": "13.32.0.0/15", "service": "CLOUDFRONT"},
                {"ip_prefix": "3.5.140.0/22", "service": "AMAZON"}]}),
        })
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            summary = update_lists(http, out, date(2026, 10, 31), min_tlds=1)
            self.assertEqual(len(summary), 3)
            tlds = (out / "tlds.txt").read_text().splitlines()
            self.assertTrue(tlds[0].startswith("# fetched 2026-10-31 from https://data.iana.org/TLD/"))
            self.assertEqual(lists.load_tlds(out), {"com", "ie", "cc"})
            self.assertEqual(lists.load_rdap_tlds(out), {"info", "cc", "tv"})
            ranges = lists.load_cdn_ranges(out)
            self.assertEqual([str(n) for n in ranges["CloudFront"]], ["13.32.0.0/15"])
            self.assertEqual(lists.cdn_provider("104.16.1.1", ranges), "Cloudflare")
            self.assertEqual(lists.cdn_provider("23.235.33.1", ranges), "Fastly")


class UpdateListsValidationTest(unittest.TestCase):
    # Review finding 7: a bad download must not replace good lists
    def test_bad_reply_writes_nothing(self):
        http = FakeHttp({("GET", "https://data.iana.org/TLD/"): text_response("<html>503</html>", status=503)})
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "tlds.txt").write_text("old")
            with self.assertRaises(ValueError):
                update_lists(http, out, date(2026, 10, 31))
            self.assertEqual((out / "tlds.txt").read_text(), "old")

    def test_too_few_tlds_rejected(self):
        http = FakeHttp({
            ("GET", "https://data.iana.org/TLD/"): text_response("COM\n"),
            ("GET", "https://data.iana.org/rdap/"): json_response(json.loads((FIXTURES / "rdap_dns.json").read_text())),
            ("GET", "https://www.cloudflare.com/ips-v4"): text_response("173.245.48.0/20\n"),
            ("GET", "https://api.fastly.com/"): json_response({"addresses": ["23.235.32.0/20"]}),
            ("GET", "https://ip-ranges.amazonaws.com/"): json_response({"prefixes": []}),
        })
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                update_lists(http, Path(tmp), date(2026, 10, 31), min_tlds=1000)
            self.assertEqual(list(Path(tmp).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
