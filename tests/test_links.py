import unittest

from ioc_enrich.links import manual_links
from ioc_enrich.models import IOC

SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class LinksTest(unittest.TestCase):
    def test_domain(self):
        self.assertEqual(manual_links(IOC("domain", "www.taibeinan.cc")), [
            ("VirusTotal", "https://www.virustotal.com/gui/domain/www.taibeinan.cc"),
            ("tria.ge", "https://tria.ge/s?q=domain:www.taibeinan.cc"),
            ("ThreatFox", "https://threatfox.abuse.ch/browse.php?search=ioc%3Awww.taibeinan.cc"),
            ("URLhaus", "https://urlhaus.abuse.ch/browse.php?search=www.taibeinan.cc"),
            ("OTX", "https://otx.alienvault.com/indicator/hostname/www.taibeinan.cc"),
        ])

    def test_ip(self):
        links = dict(manual_links(IOC("ip", "146.59.71.167")))
        self.assertEqual(links["VirusTotal"], "https://www.virustotal.com/gui/ip-address/146.59.71.167")
        self.assertEqual(links["AbuseIPDB"], "https://www.abuseipdb.com/check/146.59.71.167")
        self.assertEqual(links["OTX"], "https://otx.alienvault.com/indicator/ip/146.59.71.167")
        self.assertEqual(links["Shodan"], "https://www.shodan.io/host/146.59.71.167")

    def test_url(self):
        links = dict(manual_links(IOC("url", "http://x.com/a?b=1")))
        self.assertEqual(links["VirusTotal"], "https://www.virustotal.com/gui/search/http%3A%2F%2Fx.com%2Fa%3Fb%3D1")
        self.assertEqual(links["tria.ge"], "https://tria.ge/s?q=url:http%3A%2F%2Fx.com%2Fa%3Fb%3D1")
        self.assertEqual(links["URLhaus"], "https://urlhaus.abuse.ch/browse.php?search=http%3A%2F%2Fx.com%2Fa%3Fb%3D1")
        self.assertNotIn("AbuseIPDB", links)
        self.assertNotIn("Shodan", links)

    def test_hash(self):
        links = dict(manual_links(IOC("sha256", SHA)))
        self.assertEqual(links["VirusTotal"], f"https://www.virustotal.com/gui/file/{SHA}")
        self.assertEqual(links["MalwareBazaar"], f"https://bazaar.abuse.ch/browse.php?search=sha256%3A{SHA}")
        self.assertEqual(links["tria.ge"], f"https://tria.ge/s?q=sha256:{SHA}")
        self.assertEqual(links["OTX"], f"https://otx.alienvault.com/indicator/file/{SHA}")


if __name__ == "__main__":
    unittest.main()
