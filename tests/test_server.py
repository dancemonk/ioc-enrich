import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

from ioc_enrich.cache import Cache
from ioc_enrich.cli import Deps
from ioc_enrich.config import Keys
from ioc_enrich.server import make_server
from tests.fakes import FakeHttp
from tests.test_engine import sample_routes
from tests.test_extract import SAMPLE

TOKEN = "test-token-123"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # never use a proxy for 127.0.0.1


class ServerHarness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = Cache(Path(self.tmp.name) / "c.sqlite")
        deps = Deps(http=FakeHttp(sample_routes()), cache=self.cache,
                    now=lambda: datetime(2026, 10, 31, 14, 5), sleep=lambda s: None)
        keys = getattr(self, "KEYS", Keys(vt="K", abusech="A", otx="O", abuseipdb="B"))
        self.http = deps.http
        self.server = make_server(0, TOKEN, deps, keys=keys)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.cache.close()
        self.tmp.cleanup()

    def request(self, path, body=None, headers=None, token=TOKEN):
        url = f"http://127.0.0.1:{self.port}{path}"
        all_headers = {"X-Token": token} if token else {}
        all_headers.update(headers or {})
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            all_headers["Content-Type"] = "application/json"
        try:
            with OPENER.open(urllib.request.Request(url, data=data, headers=all_headers), timeout=5) as reply:
                return reply.status, reply.read(), dict(reply.headers)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, error.read(), dict(error.headers)


class ServerTest(ServerHarness):
    def test_bound_to_localhost_only(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_page_needs_token(self):
        self.assertEqual(self.request("/", token=None)[0], 403)
        self.assertEqual(self.request("/?t=wrong", token=None)[0], 403)
        status, body, headers = self.request(f"/?t={TOKEN}", token=None)
        self.assertEqual(status, 200)
        self.assertIn(TOKEN.encode(), body)
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")

    def test_page_accessibility_basics(self):
        page = self.request(f"/?t={TOKEN}", token=None)[1].decode()
        self.assertIn('<label for="text"', page)                       # paste box has a visible label
        self.assertRegex(page, r'id="message"[^>]*aria-live="polite"')  # run progress / Done announced
        self.assertRegex(page, r'id="cost"[^>]*aria-live="polite"')
        self.assertIn("<caption", page)
        self.assertEqual(page.count('scope="col"'), 4)
        self.assertIn(":focus-visible", page)                           # designed focus ring
        self.assertIn("aria-expanded", page)                            # links toggles say open/closed
        self.assertIn("Manual-check links for ", page)                  # toggles named by their row
        self.assertIn("(opens in a new tab)", page)
        self.assertIn("--control-border", page)                         # input borders >= 3:1
        self.assertIn("createElementNS", page)                          # drawn status icons, not glyphs
        self.assertNotRegex(page, r"border-left:\s*[2-9]px")           # craft-floor: no thick side stripe

    def test_api_rejects_bad_token_host_origin(self):
        body = {"text": SAMPLE}
        self.assertEqual(self.request("/api/plan", body, token="wrong")[0], 403)
        self.assertEqual(self.request("/api/plan", body, headers={"Host": "evil.com"})[0], 403)
        self.assertEqual(self.request("/api/plan", body, headers={"Origin": "https://evil.com"})[0], 403)
        ok = self.request("/api/plan", body, headers={"Origin": f"http://127.0.0.1:{self.port}"})
        self.assertEqual(ok[0], 200)

    def test_plan(self):
        status, body, _ = self.request("/api/plan", {"text": SAMPLE})
        data = json.loads(body)
        self.assertEqual(status, 200)
        self.assertIn("4 VirusTotal lookups", data["cost"])
        self.assertEqual(len(data["rows"]), 6)
        # Numbers the page uses to say what Run will do (OPSEC gate)
        self.assertEqual((data["iocs"], data["lookups"], data["vt_calls"], data["vt_calls_max"]), (5, 23, 4, 5))
        taibeinan = next(r for r in data["rows"] if r["value"] == "www[.]taibeinan[.]cc")
        self.assertEqual(taibeinan["kind"], "plan")
        self.assertEqual({s["state"] for s in taibeinan["sources"]}, {"planned"})

    def test_hidden_really_hides_and_results_survive_edits(self):
        page = self.request(f"/?t={TOKEN}", token=None)[1].decode()
        # Bug: display:flex on .table-tools / .bottom overrode the hidden attribute
        self.assertIn("[hidden] { display: none !important; }", page)
        # Editing after a run keeps the results and previews the next run instead
        self.assertIn('id="next-run"', page)
        edit_path = page.split("function schedulePlan()")[1].split("\n}")[0]
        self.assertNotIn("currentJob = null", edit_path)                 # editing never drops the last results

    def test_page_polish_details(self):
        page = self.request(f"/?t={TOKEN}", token=None)[1].decode()
        self.assertIn("Incident date <span", page)                       # says what the date is for
        self.assertRegex(page, r"@media \(pointer: coarse\)[^}]*\.toggle")   # 44px links toggles on touch
        self.assertIn(".hint { display: none; }", page)                  # no keyboard hint on phones
        self.assertIn('info: { icon: "info", words: "registration data" }', page)

    def test_page_has_flagged_only_filter(self):
        page = self.request(f"/?t={TOKEN}", token=None)[1].decode()
        self.assertIn("Flagged only", page)
        self.assertNotIn("startsWith(\"flagged by", page)          # no more parsing of status prose

    def test_plan_gives_counts_for_both_switch_positions(self):
        # Bug: toggling VirusTotal showed the old Run label until the plan came back
        data = json.loads(self.request("/api/plan", {"text": SAMPLE})[1])
        self.assertEqual((data["counts"]["on"]["vt_calls"], data["counts"]["on"]["lookups"]), (4, 23))
        self.assertEqual((data["counts"]["off"]["vt_calls"], data["counts"]["off"]["lookups"]), (0, 19))

    def test_plan_counts_with_vt_off(self):
        data = json.loads(self.request("/api/plan", {"text": SAMPLE, "no_vt": True})[1])
        self.assertEqual((data["vt_calls"], data["vt_calls_max"]), (0, 0))
        self.assertEqual(data["lookups"], 19)

    def test_page_has_visible_virustotal_switch(self):
        page = self.request(f"/?t={TOKEN}", token=None)[1].decode()
        self.assertRegex(page, r"<legend[^>]*>VirusTotal</legend>")
        self.assertEqual(page.count('type="radio" name="vt"'), 2)   # on / off
        self.assertNotIn('id="novt"', page)

    def test_run_poll_csv(self):
        status, body, _ = self.request("/api/run", {"text": SAMPLE, "incident_date": "2026-08-09"})
        job = json.loads(body)["job"]
        for _ in range(100):
            data = json.loads(self.request(f"/api/job/{job}")[1])
            if data["done"]:
                break
            time.sleep(0.05)
        self.assertTrue(data["done"])
        self.assertEqual(len(data["rows"]), 6)
        taibeinan = next(r for r in data["rows"] if r["value"] == "www[.]taibeinan[.]cc")
        self.assertIn("flagged by", taibeinan["status"])
        self.assertTrue(taibeinan["links"])
        # Structured status: the page never parses the status text
        self.assertEqual(taibeinan["kind"], "flag")
        states = {s["short"]: s["state"] for s in taibeinan["sources"]}
        self.assertEqual(states, {"TF": "clean", "VT": "flagged", "UH": "clean", "OTX": "flagged", "RDAP": "info"})
        private = next(r for r in data["rows"] if r["value"] == "172[.]16[.]8[.]49")
        self.assertEqual((private["kind"], private["skip"], private["sources"]), ("skip", "private", []))
        cdn = next(r for r in data["rows"] if r["value"] == "172[.]64[.]155[.]76")
        self.assertEqual(cdn["cdn"], "Cloudflare")
        # Evidence tiers: OTX/AbuseIPDB alone is a weak signal, VT/ThreatFox/URLhaus/MalwareBazaar strong
        self.assertEqual(cdn["kind"], "weak")
        self.assertEqual(cdn["gaps"], ["VT not asked (shared CDN)"])  # shared CDN: VT deliberately not asked
        ie = next(r for r in data["rows"] if r["value"] == "www[.]independent[.]ie")
        self.assertEqual(ie["kind"], "weak")
        self.assertEqual(ie["gaps"], [])                              # every strong source answered: really weak
        self.assertEqual(ie["details"], ["created 2001-01-12 via VT (9340 d before incident)"])   # only what chips don't show
        status, csv_body, headers = self.request(f"/api/job/{job}/csv")
        self.assertEqual(status, 200)
        self.assertTrue(csv_body.startswith(b"type,value,first_seen_utc"))
        self.assertIn("attachment", headers["Content-Disposition"])

    def test_odd_bodies_get_400_not_a_dropped_connection(self):
        # Bug: non-object JSON and a non-text incident_date crashed the handler
        for path in ["/api/plan", "/api/run"]:
            for body in [b"[]", b'"x"', b"null", b'{"text": "1.2.3[.]4", "incident_date": 5}']:
                with self.subTest(path=path, body=body):
                    self.assertEqual(self.request(path, body)[0], 400)

    def test_bad_content_length_gets_400(self):
        import http.client
        for length in ["abc", "-5", "-1"]:
            with self.subTest(length=length):
                conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
                conn.putrequest("POST", "/api/plan")
                conn.putheader("X-Token", TOKEN)
                conn.putheader("Content-Length", length)
                conn.endheaders()
                self.assertEqual(conn.getresponse().status, 400)
                conn.close()

    def test_body_limit(self):
        self.assertEqual(self.request("/api/plan", b"x" * (2 * 1024 * 1024))[0], 413)

    def test_unknown_job(self):
        self.assertEqual(self.request("/api/job/nope")[0], 404)




class ServerBusyTest(ServerHarness):
    def test_second_run_refused_while_busy(self):
        # Review finding 5: one VT rate limiter per process → one run at a time
        import threading as th
        gate = th.Event()
        def slow():
            gate.wait(5)
            return sample_routes()[("GET", "https://www.virustotal.com/api/v3/domains/")]
        self.http.routes[("GET", "https://www.virustotal.com/api/v3/domains/")] = slow
        first = self.request("/api/run", {"text": SAMPLE})
        self.assertEqual(first[0], 200)
        second = self.request("/api/run", {"text": SAMPLE})
        self.assertEqual(second[0], 409)
        gate.set()


class ServerCrashTest(ServerHarness):
    def test_crashed_run_marks_unanswered_lookups(self):
        # Drifted bug: a crashed web run left missing sources out of the CSV
        from unittest import mock
        with mock.patch("ioc_enrich.server.run", side_effect=RuntimeError("boom")):
            job = json.loads(self.request("/api/run", {"text": "146.59.71[.]167"})[1])["job"]
            for _ in range(100):
                data = json.loads(self.request(f"/api/job/{job}")[1])
                if data["done"]:
                    break
                time.sleep(0.05)
        self.assertEqual(data["error"], "run failed: RuntimeError")
        self.assertIn("VT: not checked (run failed)", data["rows"][0]["enrichment"])
        csv_body = self.request(f"/api/job/{job}/csv")[1].decode()
        self.assertIn("not checked (run failed)", csv_body)


class MissingKeysTest(ServerHarness):
    KEYS = Keys(otx="O")     # only OTX configured

    def test_plan_reports_missing_keys_once_not_per_row(self):
        data = json.loads(self.request("/api/plan", {"text": SAMPLE})[1])
        self.assertEqual([k["name"] for k in data["missing_keys"]],
                         ["VirusTotal", "abuse.ch (ThreatFox, URLhaus, MalwareBazaar)", "AbuseIPDB"])
        self.assertEqual(data["missing_keys"][0]["env"], "VT_API_KEY")
        self.assertFalse(any("no key" in row["status"] for row in data["rows"]))
        taibeinan = next(r for r in data["rows"] if r["value"] == "www[.]taibeinan[.]cc")
        self.assertEqual(taibeinan["status"], "would ask: OTX, RDAP")

    def test_nothing_to_ask_reports_zero_lookups(self):
        # Only a private IP: Run must have nothing to do (page disables it)
        data = json.loads(self.request("/api/plan", {"text": "172.16.8[.]49"})[1])
        self.assertEqual((data["iocs"], data["lookups"]), (0, 0))


class LiveRunTest(ServerHarness):
    def run_job(self, text):
        return json.loads(self.request("/api/run", {"text": text})[1])["job"]

    def wait_done(self, job):
        for _ in range(100):
            data = json.loads(self.request(f"/api/job/{job}")[1])
            if data["done"]:
                return data
            time.sleep(0.05)
        self.fail("job never finished")

    def test_job_view_reports_progress(self):
        data = self.wait_done(self.run_job(SAMPLE))
        progress = data["progress"]
        self.assertEqual(progress["done"], progress["total"])
        self.assertEqual(progress["vt_done"], progress["vt_total"])
        self.assertGreater(progress["vt_total"], 0)

    def test_rows_with_pending_lookups_say_checking(self):
        # Bug: mid-run, a row with only some answers read "flagged by: none"
        import threading as th
        gate = th.Event()
        def slow():
            gate.wait(5)
            return sample_routes()[("GET", "https://www.virustotal.com/api/v3/domains/")]
        self.http.routes[("GET", "https://www.virustotal.com/api/v3/domains/")] = slow
        job = self.run_job("www.taibeinan[.]cc")
        time.sleep(0.3)                                   # other sources answered, VT still waiting
        row = json.loads(self.request(f"/api/job/{job}")[1])["rows"][0]
        gate.set()
        self.assertEqual(row["kind"], "checking")
        self.assertNotIn("flagged by", row["status"])
        self.assertIn("planned", {s["state"] for s in row["sources"]})   # chips show what is still pending
        self.wait_done(job)

    def test_stop_marks_unanswered_lookups(self):
        import threading as th
        gate = th.Event()
        def slow():
            gate.wait(5)
            return sample_routes()[("GET", "https://www.virustotal.com/api/v3/domains/")]
        self.http.routes[("GET", "https://www.virustotal.com/api/v3/domains/")] = slow
        job = self.run_job(SAMPLE)
        status, body, _ = self.request(f"/api/job/{job}/stop", {})
        self.assertEqual(status, 200)
        gate.set()
        data = self.wait_done(job)
        self.assertTrue(data["stopped"])
        self.assertIn("not checked (stopped)", " ".join(r["enrichment"] for r in data["rows"]))

    def test_progress_counts_only_new_requests(self):
        self.wait_done(self.run_job("146.59.71[.]167"))
        progress = self.wait_done(self.run_job("146.59.71[.]167"))["progress"]   # everything cached now
        self.assertEqual((progress["vt_total"], progress["total"], progress["reused"]), (0, 0, 5))

    def test_page_explains_evidence_tiers(self):
        page = self.request(f"/?t={TOKEN}", token=None)[1].decode()
        self.assertIn("weak signal", page)
        self.assertIn("Strong: VirusTotal (VT), ThreatFox (TF), URLhaus (UH), MalwareBazaar (MB)", page)
        self.assertIn("so far", page)                                   # strong source not asked yet
        self.assertIn("::placeholder", page)                             # themed placeholder (was 3.9:1 in dark)
        self.assertIn("color-scheme: light dark", page)                  # dark date picker icon visible

    def test_page_results_layout(self):
        page = self.request(f"/?t={TOKEN}", token=None)[1].decode()
        self.assertIn("table-layout: fixed", page)                     # opening links no longer reflows the table
        self.assertNotIn("white-space: nowrap; }", page.split("td.mono")[1][:80])   # long URLs wrap, no sideways scroll
        self.assertIn("textarea.compact", page)                          # smaller paste box once results are shown
        self.assertIn('<span>Incident date <span class="field-hint">', page)   # label text stays together on phones

    def test_page_stale_states(self):
        page = self.request(f"/?t={TOKEN}", token=None)[1].decode()
        self.assertIn('$("nocache").checked = false', page)       # Ignore cache does not stick into the next run
        self.assertIn("function inputKey", page)                  # cache choice not part of "results are stale"
        self.assertNotIn("Updating the plan…", page)              # next-run line no longer flips back and forth
        self.assertIn('event.key === "Escape"', page)             # Esc stops a running check

    def test_page_round_six_fixes(self):
        page = self.request(f"/?t={TOKEN}", token=None)[1].decode()
        self.assertIn("Nothing flagged yet", page)                       # no false "clean" while a run is going
        self.assertNotIn("textarea.compact:focus", page)                  # the box never shrinks on blur (no 76px jump)
        self.assertIn('$("text").addEventListener("focus"', page)        # it grows when you click in, and stays big
        self.assertIn("table.plan-view th:nth-child(3) { width: auto; }", page)   # Type column stays 72px in plan view

    def test_page_says_each_fact_once(self):
        page = self.request(f"/?t={TOKEN}", token=None)[1].decode()
        self.assertIn('<th scope="col">Details</th>', page)
        self.assertIn("Flagged · strong", page)
        self.assertIn("source.metric", page)                     # chip shows its number, e.g. "VT 2/92"

    def test_page_amber_means_virustotal(self):
        page = self.request(f"/?t={TOKEN}", token=None)[1].decode()
        self.assertIn("--weak:", page)                                  # weak signal has its own colour token
        self.assertNotIn(".chip-flagged.chip-weak { color: var(--warn)", page)
        self.assertIn('id="run-label"', page)                           # Run keeps its "sends out" icon
        self.assertIn("VirusTotal lookup ", page)                       # one unit in labels and progress
        self.assertIn("IOCs done", page)                                # other sources counted in IOCs

    def test_page_last_small_fixes(self):
        page = self.request(f"/?t={TOKEN}", token=None)[1].decode()
        self.assertRegex(page, r"\.links a \{[^}]*min-height: 24px")             # expanded links were 19px tall
        self.assertRegex(page, r"@media \(pointer: coarse\)[^}]*\.links a")      # 44px on touch screens
        self.assertIn('$("incident").addEventListener("change", schedulePlan)', page)   # date edits refresh the plan

    def test_page_amber_only_for_virustotal(self):
        page = self.request(f"/?t={TOKEN}", token=None)[1].decode()
        self.assertIn("#message.tone-warn { color: var(--text); }", page)    # Ignored / Stopped are not amber
        self.assertNotIn("border: 1px solid var(--warn)", page)              # keys banner is not amber
        self.assertIn(".links { font-family: system-ui", page)               # links panel wraps like text
        self.assertNotIn('.replace(" not checked", " not asked")', page)     # gap wording comes from the server

    def test_page_opsec_details(self):
        page = self.request(f"/?t={TOKEN}", token=None)[1].decode()
        self.assertRegex(page, r'id="message"[^>]*tabindex="-1"')           # focus target after a run
        self.assertIn("also adds the IOC to its public data", page)          # VT manual link warning
        self.assertIn("reused from the cache", page)

    def test_plan_marks_cached_lookups(self):
        self.wait_done(self.run_job("146.59.71[.]167"))
        data = json.loads(self.request("/api/plan", {"text": "146.59.71[.]167"})[1])
        states = {s["short"]: s["state"] for s in data["rows"][0]["sources"]}
        self.assertEqual(states["VT"], "cached")

    def test_page_has_stop_and_progress(self):
        page = self.request(f"/?t={TOKEN}", token=None)[1].decode()
        self.assertIn('id="stop"', page)
        self.assertIn("VirusTotal lookup ", page)
        self.assertIn("catch", page)                       # fetch failures are handled, not left hanging


if __name__ == "__main__":
    unittest.main()
