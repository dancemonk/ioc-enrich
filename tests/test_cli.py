import io
import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from ioc_enrich.cache import Cache
from ioc_enrich.cli import Deps, main
from ioc_enrich.csvio import read_rows
from tests.fakes import FakeHttp
from tests.test_engine import VT, sample_routes
from tests.test_extract import SAMPLE

FIX = Path(__file__).parent / "fixtures"
ENV = {"VT_API_KEY": "TESTKEY123", "ABUSECH_AUTH_KEY": "A", "OTX_API_KEY": "O", "ABUSEIPDB_API_KEY": "B"}


class InterruptingHttp(FakeHttp):
    """Raises KeyboardInterrupt (Ctrl-C) on the Nth request."""

    def __init__(self, routes, on_call):
        super().__init__(routes)
        self.on_call = on_call

    def _answer(self, method, url, body, headers):
        if len(self.calls) + 1 == self.on_call:
            self.calls.append((method, url, body, headers))
            raise KeyboardInterrupt
        return super()._answer(method, url, body, headers)


class CliHarness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.cache = Cache(self.dir / "c.sqlite")
        self.sleeps = []

    def tearDown(self):
        self.cache.close()
        self.tmp.cleanup()

    def cli(self, argv, http=None, stdin_text=SAMPLE, env=None):
        http = http or FakeHttp(sample_routes())
        out, err = io.StringIO(), io.StringIO()
        deps = Deps(http=http, cache=self.cache, now=lambda: datetime(2026, 10, 31, 14, 5),
                    sleep=self.sleeps.append)
        base = ["--keys", str(self.dir / "nokeys.env"), "--allowlist", str(self.dir / "noallow.txt")]
        code = main(base + argv, stdin=io.StringIO(stdin_text), stdout=out, stderr=err,
                    env=ENV if env is None else env, deps=deps)
        return code, out.getvalue(), err.getvalue(), http


class CliTest(CliHarness):
    def test_dry_run_without_keys_or_network(self):
        code, out, _, http = self.cli(["--dry-run"], env={})
        self.assertEqual(code, 0)
        self.assertEqual(http.calls, [])
        self.assertIn("skipped (private)", out)
        self.assertIn("shared CDN (Cloudflare) - do not block", out)
        self.assertIn("4 VirusTotal lookups", out)
        self.assertIn("https://www.virustotal.com/gui/domain/www.taibeinan.cc", out)
        self.assertEqual(list(self.dir.glob("*.csv")), [])

    def test_dry_run_no_vt_does_not_list_vt(self):
        # Drifted bug: dry run ignored --no-vt
        code, out, _, _ = self.cli(["--dry-run", "--no-vt"], env={})
        self.assertEqual(code, 0)
        self.assertNotIn("would ask: ThreatFox, VT", out)
        self.assertIn("not checked: VT (--no-vt)", out)
        self.assertIn("0 VirusTotal lookups", out)

    def test_full_run_writes_csv_and_hides_keys(self):
        out_path = self.dir / "out.csv"
        code, out, err, _ = self.cli(["-o", str(out_path), "--incident-date", "2026-08-09"])
        self.assertEqual(code, 0)
        rows = read_rows(out_path)
        self.assertEqual(len(rows), 5)
        self.assertIn("flagged by:", out)
        self.assertIn(f"Wrote {out_path} (5 rows)", out)
        self.assertNotIn("TESTKEY123", out + err)
        cdn = next(r for r in rows if r["value"] == "172[.]64[.]155[.]76")
        self.assertEqual(cdn["role"], "shared CDN (Cloudflare) - do not block")
        taibeinan = next(r for r in rows if r["value"] == "www[.]taibeinan[.]cc")
        self.assertIn("created 2026-05-16 via RDAP (85 d before incident)", taibeinan["enrichment"])

    def test_refuses_overwrite_before_any_lookup(self):
        out_path = self.dir / "exists.csv"
        out_path.write_text("x")
        code, _, err, http = self.cli(["-o", str(out_path)])
        self.assertEqual(code, 1)
        self.assertIn("refusing to overwrite", err)
        self.assertEqual(http.calls, [])

    def test_missing_output_folder_refused_before_any_lookup(self):
        code, _, err, http = self.cli(["-o", str(self.dir / "nodir" / "x.csv")])
        self.assertEqual(code, 1)
        self.assertIn("folder does not exist", err)
        self.assertEqual(http.calls, [])

    def test_write_failure_after_run_is_reported_not_raised(self):
        out_path = self.dir / "race.csv"

        class CreatesOutput(FakeHttp):          # another run grabs the same name meanwhile
            def _answer(self, method, url, body, headers):
                out_path.touch()
                return super()._answer(method, url, body, headers)

        code, _, err, _ = self.cli(["-o", str(out_path)], http=CreatesOutput(sample_routes()))
        self.assertEqual(code, 1)
        self.assertIn("cannot write", err)
        self.assertIn("answers are cached", err)

    def test_vt_limits_must_be_positive(self):
        for flag in ["--vt-per-minute", "--vt-daily-limit"]:
            with self.assertRaises(SystemExit):
                self.cli([flag, "0", "--dry-run"])

    def test_merge_recheck_adds_no_rows(self):
        merge = self.dir / "urls.csv"
        merge.write_text("type,value,first_seen_utc,frame,context,role,confidence,enrichment,checked_on\n"
                         "url,hxxp://www.independent[.]ie/ujvq/,,,,,,,\n")
        out_path = self.dir / "rechecked.csv"
        code, _, _, _ = self.cli(["--merge", str(merge), "-o", str(out_path)], stdin_text="")
        self.assertEqual(code, 0)
        self.assertEqual([r["type"] for r in read_rows(out_path)], ["url"])

    def test_merge_without_input_rechecks_file_rows(self):
        out_path = self.dir / "merged.csv"
        code, out, _, http = self.cli(["--merge", str(FIX / "iocs_sample.csv"), "-o", str(out_path)], stdin_text="")
        self.assertEqual(code, 0)
        vt_urls = sorted(u for _, u, _, _ in http.calls if u.startswith(VT))
        self.assertEqual(vt_urls, sorted([VT + "domains/www.independent.ie", VT + "domains/independent.ie",
                                          VT + "domains/www.grinswakebthu.info", VT + "domains/www.taibeinan.cc",
                                          VT + "ip_addresses/146.59.71.167"]))
        rows = read_rows(out_path)
        self.assertEqual(len(rows), 6)
        self.assertEqual(rows[0]["type"], "user_agent")

    def test_empty_input(self):
        code, _, err, _ = self.cli([], stdin_text="nothing to see here")
        self.assertEqual(code, 2)
        self.assertIn("No IOCs found in input.", err)

    def test_ctrl_c_writes_partial_csv(self):
        # Review Focus 5
        out_path = self.dir / "partial.csv"
        http = InterruptingHttp(sample_routes(), on_call=2)
        code, out, _, _ = self.cli(["-o", str(out_path)], http=http)
        self.assertEqual(code, 130)
        self.assertIn("Interrupted.", out)
        text = out_path.read_text()
        self.assertIn("not checked (interrupted)", text)

    def test_help(self):
        out = io.StringIO()
        with self.assertRaises(SystemExit) as ctx:
            main(["--help"], stdout=out)
        self.assertEqual(ctx.exception.code, 0)




class MainThreadInterruptHttp(FakeHttp):
    """A real Ctrl-C arrives on the main thread (the VT loop), not in a worker."""

    def __init__(self, routes, on_vt_call):
        super().__init__(routes)
        self.on_vt_call = on_vt_call
        self.vt_seen = 0

    def _answer(self, method, url, body, headers):
        import threading
        if url.startswith(VT) and threading.current_thread() is threading.main_thread():
            self.vt_seen += 1
            if self.vt_seen == self.on_vt_call:
                raise KeyboardInterrupt
        return super()._answer(method, url, body, headers)


class InterruptResumeTest(CliHarness):
    def test_ctrl_c_answers_are_cached_and_rerun_resumes(self):
        # Review finding 6
        http1 = MainThreadInterruptHttp(sample_routes(), on_vt_call=2)
        code, _, err, _ = self.cli(["-o", str(self.dir / "first.csv")], http=http1)
        self.assertEqual(code, 130)
        self.assertNotIn("closed database", err)
        def request_ids(http):   # POST endpoints share a URL, so include the body
            return {(url, json.dumps(body, sort_keys=True)) for _, url, body, _ in http.calls
                    if not url.startswith(VT)}
        answered = request_ids(http1)
        self.assertTrue(answered)
        http2 = FakeHttp(sample_routes())
        code, _, _, _ = self.cli(["-o", str(self.dir / "second.csv")], http=http2)
        self.assertEqual(code, 0)
        self.assertEqual(request_ids(http2) & answered, set())

    def test_merge_missing_file_is_friendly(self):
        code, _, err, _ = self.cli(["--merge", str(self.dir / "nope.csv")], stdin_text="")
        self.assertEqual(code, 2)
        self.assertIn("cannot read", err)


if __name__ == "__main__":
    unittest.main()
