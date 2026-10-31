import io
import unittest
import urllib.error
from unittest import mock

from ioc_enrich import http as http_module
from ioc_enrich.http import BlockedEndpoint, HttpClient, RateLimited, _SafeRedirect, check_allowed

H = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
VT = "https://www.virustotal.com/api/v3"


class CheckAllowedTest(unittest.TestCase):
    def test_blocked(self):
        blocked = [
            ("POST", f"{VT}/urls", None),
            ("POST", f"{VT}/files", None),
            ("GET", f"{VT}/files/upload_url", None),
            ("GET", f"{VT}/files/{H}/download", None),
            ("GET", f"{VT}/files/{H}/download_url", None),
            ("POST", f"{VT}/domains/x.com/analyse", None),
            ("GET", f"{VT}/domains/x.com/comments", None),
            ("POST", "https://mb-api.abuse.ch/api/v1/", {"query": "get_file", "sha256_hash": H}),
            ("POST", "https://threatfox-api.abuse.ch/api/v1/", {"query": "submit_ioc"}),
            ("GET", "https://urlhaus-api.abuse.ch/v1/download/abc", None),
            ("POST", "https://urlhaus-api.abuse.ch/v1/download/", {}),
            ("GET", "http://www.grinswakebthu.info/", None),
            ("POST", "https://otx.alienvault.com/api/v1/indicators/submit_url", {}),
            ("POST", "https://api.abuseipdb.com/api/v2/report", {}),
        ]
        for method, url, body in blocked:
            with self.subTest(url=url, body=body):
                with self.assertRaises(BlockedEndpoint):
                    check_allowed(method, url, body)

    def test_allowed(self):
        allowed = [
            ("GET", f"{VT}/domains/www.taibeinan.cc", None),
            ("GET", f"{VT}/ip_addresses/146.59.71.167", None),
            ("GET", f"{VT}/urls/aHR0cDovL3guY29tLw", None),
            ("GET", f"{VT}/files/{H}", None),
            ("GET", f"{VT}/domains/x.com/resolutions?limit=10", None),
            ("GET", f"{VT}/files/{H}/contacted_ips?limit=10", None),
            ("POST", "https://threatfox-api.abuse.ch/api/v1/", {"query": "search_ioc", "search_term": "x"}),
            ("POST", "https://threatfox-api.abuse.ch/api/v1/", {"query": "search_hash", "hash": H}),
            ("POST", "https://urlhaus-api.abuse.ch/v1/host/", {"host": "x.com"}),
            ("POST", "https://urlhaus-api.abuse.ch/v1/url/", {"url": "http://x.com/"}),
            ("POST", "https://urlhaus-api.abuse.ch/v1/payload/", {"sha256_hash": H}),
            ("POST", "https://mb-api.abuse.ch/api/v1/", {"query": "get_info", "hash": H}),
            ("GET", "https://otx.alienvault.com/api/v1/indicators/hostname/www.x.com/general", None),
            ("GET", "https://api.abuseipdb.com/api/v2/check?ipAddress=1.2.3.4&maxAgeInDays=90", None),
            ("GET", "https://rdap.org/domain/taibeinan.cc", None),
            ("GET", "https://data.iana.org/TLD/tlds-alpha-by-domain.txt", None),
            # IOC values that merely contain a forbidden word are still lookups:
            ("GET", f"{VT}/domains/download.example.com", None),
            ("GET", "https://otx.alienvault.com/api/v1/indicators/hostname/submit.example.com/general", None),
        ]
        for method, url, body in allowed:
            with self.subTest(url=url):
                check_allowed(method, url, body)


class RedirectTest(unittest.TestCase):
    # Review finding 3: redirects must not carry keys or skip check_allowed
    def handler_redirect(self, url, new_url, headers):
        req = urllib.request.Request(url, headers=headers)
        return _SafeRedirect().redirect_request(req, io.BytesIO(), 302, "Found", {}, new_url)

    def test_keyed_request_redirect_refused(self):
        with self.assertRaises(BlockedEndpoint):
            self.handler_redirect(f"{VT}/files/{H}", "https://elsewhere.example/x", {"x-apikey": "K"})
        with self.assertRaises(BlockedEndpoint):
            self.handler_redirect("https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/general",
                                  "https://otx.alienvault.com/other", {"X-OTX-API-KEY": "K"})

    def test_rdap_redirect_needs_https(self):
        new = self.handler_redirect("https://rdap.org/domain/taibeinan.cc", "https://tld-rdap.verisign.com/cc/v1/domain/taibeinan.cc", {})
        self.assertEqual(new.full_url, "https://tld-rdap.verisign.com/cc/v1/domain/taibeinan.cc")
        with self.assertRaises(BlockedEndpoint):
            self.handler_redirect("https://rdap.org/domain/taibeinan.cc", "http://plain.example/x", {})


class HttpClientTest(unittest.TestCase):
    def test_blocked_before_network(self):
        with mock.patch.object(http_module._OPENER, "open") as urlopen:
            with self.assertRaises(BlockedEndpoint):
                HttpClient().get("http://www.grinswakebthu.info/")
            urlopen.assert_not_called()

    def test_429_raises_rate_limited(self):
        err = urllib.error.HTTPError(f"{VT}/files/{H}", 429, "Too Many", {"Retry-After": "30"}, io.BytesIO(b"{}"))
        with mock.patch.object(http_module._OPENER, "open", side_effect=err):
            with self.assertRaises(RateLimited) as ctx:
                HttpClient().get(f"{VT}/files/{H}", {"x-apikey": "K"})
        self.assertEqual(ctx.exception.retry_after, 30.0)

    def test_404_is_a_response(self):
        err = urllib.error.HTTPError(f"{VT}/files/{H}", 404, "Not Found", {}, io.BytesIO(b'{"error":{}}'))
        with mock.patch.object(http_module._OPENER, "open", side_effect=err):
            self.assertEqual(HttpClient().get(f"{VT}/files/{H}").status, 404)


if __name__ == "__main__":
    unittest.main()
