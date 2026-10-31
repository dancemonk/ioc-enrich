import unittest

from ioc_enrich.extract import extract

# Small fixed TLD set: tests never read the live-fetched data file.
TLDS = {"com", "info", "cc", "ie", "zip", "py", "uk"}

SAMPLE = ("www.grinswakebthu[.]info, www.taibeinan[.]cc, www.independent[.]ie, "
          "146.59.71[.]167, 172.64.155[.]76, 172.16.8[.]49")


def pairs(result):
    return [(i.type, i.value) for i in result.iocs]


class ExtractTest(unittest.TestCase):
    def test_sample(self):
        self.assertEqual(pairs(extract(SAMPLE, TLDS)), [
            ("domain", "www.grinswakebthu.info"), ("domain", "www.taibeinan.cc"),
            ("domain", "www.independent.ie"), ("ip", "146.59.71.167"),
            ("ip", "172.64.155.76"), ("ip", "172.16.8.49")])

    def test_url_yields_url_and_host(self):
        self.assertEqual(pairs(extract("hxxp://www.independent[.]ie/ujvq/", TLDS)), [
            ("url", "http://www.independent.ie/ujvq/"), ("domain", "www.independent.ie")])

    def test_hashes(self):
        md5 = "D41D8CD98F00B204E9800998ECF8427E"
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = extract(f"{md5} {sha1} {sha256} {sha256[:63]}", TLDS)
        self.assertEqual(pairs(result), [("md5", md5.lower()), ("sha1", sha1), ("sha256", sha256)])

    def test_punctuation_wrapping(self):
        # Review Focus 1
        result = extract("see (hxxp://a[.]com/c). and `www.x[.]com`, done", TLDS)
        self.assertEqual(pairs(result), [("url", "http://a.com/c"), ("domain", "a.com"), ("domain", "www.x.com")])

    def test_case_and_trailing_dot_dedupe(self):
        # Review Focus 2
        self.assertEqual(pairs(extract("WWW.Example.COM. www.example.com", TLDS)),
                         [("domain", "www.example.com")])

    def test_ip_with_port_and_ip_url(self):
        # Review Focus 3
        result = extract("146.59.71[.]167:443 hxxp://1.2.3[.]4:8080/x", TLDS)
        self.assertEqual(pairs(result), [("ip", "146.59.71.167"), ("url", "http://1.2.3.4:8080/x"), ("ip", "1.2.3.4")])

    def test_filenames_ignored(self):
        result = extract("report.pdf frame.time loader.py evil[.]zip", TLDS)
        self.assertEqual(pairs(result), [("domain", "evil.zip")])
        self.assertEqual(result.ignored, [("loader.py", "looks like filename")])

    def test_www_filename_like_tld_accepted(self):
        self.assertEqual(pairs(extract("www.shop.py", TLDS)), [("domain", "www.shop.py")])

    def test_ipv6_ignored(self):
        result = extract("2001:db8::1", TLDS)
        self.assertEqual(result.iocs, [])
        self.assertEqual(result.ignored, [("2001:db8::1", "IPv6 not supported yet")])

    def test_tshark_line(self):
        line = ("11032 2026-08-09 02:13:23 172.16.8.49 172.64.155.76 HTTP POST /ujvq/ "
                "HTTP/1.1 www.independent.ie")
        self.assertEqual(pairs(extract(line, TLDS)), [
            ("ip", "172.16.8.49"), ("ip", "172.64.155.76"), ("domain", "www.independent.ie")])


if __name__ == "__main__":
    unittest.main()
