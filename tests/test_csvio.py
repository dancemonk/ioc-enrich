import tempfile
import unittest
from datetime import date, datetime
from pathlib import Path

from ioc_enrich.csvio import COLUMNS, build_rows, default_output_name, read_rows, row_key, write_rows
from ioc_enrich.lookup_plan import Lookup, LookupPlan, PlannedIOC
from ioc_enrich.models import IOC, SourceResult

FIX = Path(__file__).parent / "fixtures" / "iocs_sample.csv"
TODAY = date(2026, 10, 31)
GRIN = IOC("domain", "www.grinswakebthu.info")


def plan_of(*items):
    """A plan whose IOCs expect exactly the sources answered in each test."""
    return LookupPlan(list(items), rdap_tlds={"info"})


def planned(ioc, sources=("ThreatFox", "VT", "RDAP"), **kw):
    return PlannedIOC(ioc, lookups=[Lookup(ioc, s, s, ioc) for s in sources], **kw)


def complete_results():
    return [SourceResult("ThreatFox", "not_listed", TODAY),
            SourceResult("VT", "ok", TODAY, fields={"malicious": 2, "suspicious": 0, "total": 92,
                                                     "words": ["malware"], "creation_date": None}, flagged=True),
            SourceResult("RDAP", "ok", TODAY, fields={"created": "2026-05-15", "registrar": "X"})]


class CsvTest(unittest.TestCase):
    def setUp(self):
        self.existing = read_rows(FIX)

    def test_row_key(self):
        self.assertEqual(row_key("domain", "WWW.Grinswakebthu[.]info"), ("domain", "www.grinswakebthu.info"))

    def test_row_key_type_case_and_url_path(self):
        self.assertEqual(row_key("MD5", "D41D8CD98F00B204E9800998ECF8427E"),
                         ("md5", "d41d8cd98f00b204e9800998ecf8427e"))
        self.assertEqual(row_key("url", "hxxp://Evil[.]com/Path"), ("url", "http://evil.com/Path"))
        self.assertNotEqual(row_key("url", "http://evil.com/Path"), row_key("url", "http://evil.com/path"))

    def test_merge_complete_updates_only_tool_columns(self):
        before = next(r for r in self.existing if r["value"] == "www.grinswakebthu[.]info").copy()
        rows, notes = build_rows(plan_of(planned(GRIN)), {GRIN: complete_results()}, self.existing, None, TODAY)
        after = next(r for r in rows if r["value"] == "www.grinswakebthu[.]info")
        for column in ["type", "value", "first_seen_utc", "frame", "context", "role", "confidence"]:
            self.assertEqual(after[column], before[column])
        self.assertEqual(after["enrichment"],
                         "ThreatFox: not listed; VT 2/92 (malware); created 2026-05-15 via RDAP (86 d before incident)")
        self.assertEqual(after["checked_on"], "2026-10-31")
        self.assertEqual(notes, [])
        self.assertEqual(len(rows), len(self.existing))
        self.assertEqual(rows[0], self.existing[0])           # user_agent row untouched

    def test_incomplete_keeps_old(self):
        results = complete_results() + [SourceResult("OTX", "not_checked", TODAY, reason="quota")]
        before = next(r for r in self.existing if r["value"] == "www.grinswakebthu[.]info")["enrichment"]
        rows, notes = build_rows(plan_of(planned(GRIN, ("ThreatFox", "VT", "RDAP", "OTX"))), {GRIN: results}, self.existing, None, TODAY)
        after = next(r for r in rows if r["value"] == "www.grinswakebthu[.]info")
        self.assertEqual(after["enrichment"], before)
        self.assertEqual(notes, ["kept old enrichment (incomplete run): www[.]grinswakebthu[.]info"])

    def test_new_rows_appended(self):
        cdn = IOC("ip", "104.21.76.210")
        private = IOC("ip", "172.16.8.49")
        plan = plan_of(planned(cdn, ("VT",), cdn="Cloudflare"), PlannedIOC(private, skip="private"))
        results = {cdn: [SourceResult("VT", "skipped", TODAY, reason="shared CDN")]}
        rows, _ = build_rows(plan, results, self.existing, date(2026, 8, 9), TODAY)
        self.assertEqual(len(rows), len(self.existing) + 1)
        new = rows[-1]
        self.assertEqual((new["type"], new["value"], new["role"]),
                         ("ip", "104[.]21[.]76[.]210", "shared CDN (Cloudflare) - do not block"))
        self.assertEqual(new["enrichment"], "VT: skipped (shared CDN)")
        self.assertEqual(new["first_seen_utc"], "")

    def test_allowlisted_row(self):
        ioc = IOC("domain", "www.example.com")
        rows, _ = build_rows(plan_of(PlannedIOC(ioc, skip="allowlisted")), {}, None, None, TODAY)
        self.assertEqual(rows[0]["enrichment"], "allowlisted - not checked")

    def test_write_refuses_overwrite_and_roundtrips(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.csv"
            write_rows(out, self.existing)
            self.assertEqual(read_rows(out), self.existing)
            with self.assertRaises(FileExistsError):
                write_rows(out, self.existing)

    def test_excel_bom_accepted(self):
        # Review finding 13: Excel saves UTF-8 CSVs with a BOM
        with tempfile.TemporaryDirectory() as tmp:
            bom = Path(tmp) / "excel.csv"
            bom.write_bytes(b"\xef\xbb\xbf" + FIX.read_bytes())
            self.assertEqual(read_rows(bom), self.existing)

    def test_rows_with_wrong_field_count_rejected_up_front(self):
        header = ",".join(COLUMNS) + "\n"
        for body in ["md5\n", "md5,d41d8cd98f00b204e9800998ecf8427e,,,,,,,,extra\n"]:
            with tempfile.TemporaryDirectory() as tmp:
                bad = Path(tmp) / "bad.csv"
                bad.write_text(header + "ip,1.2.3.4,,,,,,,\n" + body)
                with self.assertRaisesRegex(ValueError, "line 3"):
                    read_rows(bad)

    def test_failed_write_leaves_no_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.csv"
            with self.assertRaises(ValueError):
                write_rows(out, [{**dict.fromkeys(COLUMNS, ""), None: "extra"}])
            self.assertFalse(out.exists())

    def test_header_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.csv"
            bad.write_text("type,value\nip,1.2.3.4\n")
            with self.assertRaises(ValueError):
                read_rows(bad)

    def test_default_name(self):
        self.assertEqual(default_output_name(datetime(2026, 10, 31, 14, 5)), "ioc-enrich-2026-10-31-1405.csv")
        self.assertEqual(COLUMNS[-2:], ["enrichment", "checked_on"])


if __name__ == "__main__":
    unittest.main()
