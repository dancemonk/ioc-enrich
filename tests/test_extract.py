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


class TicketShapesTest(unittest.TestCase):
    """Token shapes analysts paste every day."""

    def test_host_with_path_and_no_scheme(self):
        result = extract("evil[.]com/gate.php 45.9.148[.]12/bins/mips", TLDS)
        self.assertEqual(pairs(result), [("domain", "evil.com"), ("ip", "45.9.148.12")])

    def test_cidr_and_file_paths_are_not_hosts(self):
        result = extract("45.9.148.0/24 /usr/bin/curl scripts/run.sh HTTP/1.1", TLDS)
        self.assertEqual(pairs(result), [])

    def test_labelled_values(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        result = extract(f"md5:{md5} src_ip=8.8.4.4 url=hxxp://evil[.]com/x", TLDS)
        self.assertEqual(pairs(result), [
            ("md5", md5), ("ip", "8.8.4.4"), ("url", "http://evil.com/x"), ("domain", "evil.com")])

    def test_email_gives_its_domain(self):
        self.assertEqual(pairs(extract("From: billing@evil-pay[.]com", TLDS)),
                         [("domain", "evil-pay.com")])

    def test_markdown_link(self):
        self.assertEqual(pairs(extract("[evil.com](http://evil.com/x)", TLDS)), [
            ("domain", "evil.com"), ("url", "http://evil.com/x")])

    def test_domain_with_port(self):
        self.assertEqual(pairs(extract("evil[.]com:8443", TLDS)), [("domain", "evil.com")])

    def test_url_query_keeps_commas_and_semicolons(self):
        result = extract("see http://evil.com/a?x=1,2;sid=3, then 1.2.3.4,5.6.7.8;9.9.9.9", TLDS)
        self.assertEqual(pairs(result), [
            ("url", "http://evil.com/a?x=1,2;sid=3"), ("domain", "evil.com"),
            ("ip", "1.2.3.4"), ("ip", "5.6.7.8"), ("ip", "9.9.9.9")])

    def test_comma_separated_urls(self):
        self.assertEqual(pairs(extract("hxxp://a[.]com/x,hxxp://b[.]com/y", TLDS)), [
            ("url", "http://a.com/x"), ("domain", "a.com"), ("url", "http://b.com/y"), ("domain", "b.com")])

    def test_url_keeps_userinfo(self):
        # "http://paypal.com@evil.com/" is a classic disguise: the host is evil.com
        self.assertEqual(pairs(extract("hxxp://paypal[.]com@evil[.]com:8080/x", TLDS)), [
            ("url", "http://paypal.com@evil.com:8080/x"), ("domain", "evil.com")])

    def test_arpa_names_are_ignored(self):
        tlds = TLDS | {"arpa"}
        result = extract("5.1.168.192.in-addr.arpa http://router.home.arpa/admin", tlds)
        self.assertEqual(pairs(result), [])
        self.assertEqual([reason for _, reason in result.ignored], ["reverse DNS or local name (.arpa)"] * 2)


if __name__ == "__main__":
    unittest.main()
