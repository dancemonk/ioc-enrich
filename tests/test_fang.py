import unittest

from ioc_enrich.fang import defang, refang
from ioc_enrich.models import IOC


class RefangTest(unittest.TestCase):
    def test_refang_variants(self):
        self.assertEqual(refang("hxxp://www.taibeinan[.]cc/lqjm/"), "http://www.taibeinan.cc/lqjm/")
        self.assertEqual(refang("HXXPS://a(.)b[.]c"), "https://a.b.c")
        self.assertEqual(refang("1.2.3[.]4[:]8080"), "1.2.3.4:8080")
        self.assertEqual(refang("x[dot]com"), "x.com")

    def test_plain_text_unchanged(self):
        self.assertEqual(refang("www.example.com"), "www.example.com")


class DefangTest(unittest.TestCase):
    def test_defang_domain_ip(self):
        self.assertEqual(defang(IOC("domain", "www.independent.ie")), "www[.]independent[.]ie")
        self.assertEqual(defang(IOC("ip", "146.59.71.167")), "146[.]59[.]71[.]167")

    def test_defang_url_host_and_port_only(self):
        self.assertEqual(defang(IOC("url", "http://1.2.3.4:8080/a.php")), "hxxp://1[.]2[.]3[.]4[:]8080/a.php")
        self.assertEqual(defang(IOC("url", "https://www.independent.ie/ujvq/")), "hxxps://www[.]independent[.]ie/ujvq/")

    def test_defang_hash_unchanged(self):
        h = "d41d8cd98f00b204e9800998ecf8427e"
        self.assertEqual(defang(IOC("md5", h)), h)

    def test_roundtrip(self):
        for ioc in [IOC("domain", "www.taibeinan.cc"), IOC("ip", "172.64.155.76"),
                    IOC("url", "http://1.2.3.4:8080/a.php?x=1")]:
            self.assertEqual(refang(defang(ioc)), ioc.value)


if __name__ == "__main__":
    unittest.main()
