"""`ioc-enrich serve`: a small local web page over the same engine.

Safety:
- Listens on 127.0.0.1 only (not reachable from other machines).
- Every request needs the random token printed at startup.
- Host and Origin headers must be this server, so another website open in
  your browser cannot drive it and spend your API quota.
- Request logging is switched off, so the token never lands in a log.
"""

import json
import os
import re
import secrets
import threading
import time
from datetime import date, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from ioc_enrich.config import DEFAULT_KEYS_FILE, Keys, load_keys, missing_keys
from ioc_enrich.csvio import build_rows, rows_to_csv_text
from ioc_enrich.engine import RunOptions, estimate, run
from ioc_enrich.extract import extract
from ioc_enrich.fang import defang
from ioc_enrich.format import (enrichment, flagged_by, plan_status, result_kind, row_details, source_states,
                                strong_gaps)
from ioc_enrich.links import manual_links
from ioc_enrich.lists import load_cdn_ranges, load_rdap_tlds, load_tlds
from ioc_enrich.lookup_plan import LookupPlan, PlannedIOC, build_plan, keyed_sources, load_allowlist
from ioc_enrich.models import SourceResult

PAGE = Path(__file__).parent / "web" / "index.html"
MAX_BODY = 1024 * 1024
DEFAULT_ALLOWLIST = Path.home() / ".config" / "ioc-enrich" / "allowlist.txt"
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                               "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class Job:
    """One web-page run, filled in by a background thread."""

    def __init__(self, plan: LookupPlan, incident_date: date | None):
        self.plan = plan
        self.incident_date = incident_date
        self.results: dict = {}
        self.done = False
        self.error = ""
        self.cancel = threading.Event()   # set by the page's Stop button
        self.stopped = False
        self.reused: set = set()          # (ioc, source) answered from the cache: nothing is sent
        self.lock = threading.Lock()


def _options(body: dict) -> RunOptions:
    return RunOptions(no_cache=bool(body.get("no_cache")))


def _incident_date(body: dict) -> date | None:
    value = body.get("incident_date") or ""
    try:
        return date.fromisoformat(value) if value else None
    except ValueError:
        return None


def _skip_status(item: PlannedIOC) -> str | None:
    if item.skip == "private":
        return "skipped (private)"
    if item.skip == "allowlisted":
        return "allowlisted - not checked"
    return None


def make_server(port: int, token: str, deps, keys: Keys | None = None) -> ThreadingHTTPServer:
    jobs: dict[str, Job] = {}
    rdap_tlds = load_rdap_tlds()
    # One run at a time: each run has its own VT rate limiter, so two runs
    # together would go over VT's 4 requests/minute.
    run_lock = threading.Lock()
    active: list[Job] = []

    def current_keys() -> Keys:
        return keys if keys is not None else load_keys(os.environ, DEFAULT_KEYS_FILE)

    def plan_from(body: dict) -> tuple[LookupPlan, list]:
        found = extract(str(body.get("text", "")), load_tlds())
        plan = build_plan(found.iocs, allowlist=load_allowlist(DEFAULT_ALLOWLIST),
                          cdn_ranges=load_cdn_ranges(), rdap_tlds=rdap_tlds,
                          no_vt=bool(body.get("no_vt")), keyed_sources=keyed_sources(current_keys()))
        return plan, found.ignored

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):     # noqa: A002 - stdlib signature
            pass                                   # never log: URLs carry the token

        # ---- helpers -------------------------------------------------------
        def _send(self, status: int, body: bytes, content_type: str, extra: dict | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for name, value in {**SECURITY_HEADERS, **(extra or {})}.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, data) -> None:
            self._send(status, json.dumps(data).encode("utf-8"), "application/json")

        def _allowed(self, query_token: str | None = None) -> bool:
            port_now = self.server.server_address[1]
            hosts = {f"127.0.0.1:{port_now}", f"localhost:{port_now}"}
            if self.headers.get("Host") not in hosts:
                return False
            origin = self.headers.get("Origin")
            if origin is not None and origin not in {f"http://{h}" for h in hosts}:
                return False
            given = query_token if query_token is not None else self.headers.get("X-Token", "")
            return secrets.compare_digest(given or "", token)

        def _body(self) -> dict | None:
            """The request's JSON object, or None after sending a 4xx answer."""
            raw_length = self.headers.get("Content-Length") or "0"
            if not raw_length.isdigit():              # also rejects negative numbers
                self.close_connection = True
                self._json(400, {"error": "bad Content-Length"})
                return None
            length = int(raw_length)
            if length > MAX_BODY:
                # Read and throw away the body in small chunks (no memory use),
                # so the client gets the 413 instead of a broken connection.
                remaining = min(length, 16 * MAX_BODY)
                while remaining > 0:
                    chunk = self.rfile.read(min(65536, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                self.close_connection = True
                self._json(413, {"error": "request too large"})
                return None
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:                        # includes bytes that are not UTF-8
                self._json(400, {"error": "bad JSON"})
                return None
            if not isinstance(data, dict):
                self._json(400, {"error": "request body must be a JSON object"})
                return None
            if not isinstance(data.get("text", ""), str) or not isinstance(data.get("incident_date") or "", str):
                self._json(400, {"error": "text and incident_date must be strings"})
                return None
            return data

        # ---- routes --------------------------------------------------------
        def do_GET(self):
            parts = urlsplit(self.path)
            if parts.path == "/":
                query_token = parse_qs(parts.query).get("t", [""])[0]
                if not self._allowed(query_token):
                    return self._json(403, {"error": "forbidden"})
                page = PAGE.read_text(encoding="utf-8").replace("__TOKEN__", token)
                return self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
            if not self._allowed():
                return self._json(403, {"error": "forbidden"})
            match = re.fullmatch(r"/api/job/([\w-]+)(/csv)?", parts.path)
            job = jobs.get(match.group(1)) if match else None
            if job is None:
                return self._json(404, {"error": "not found"})
            if match.group(2):
                return self._csv(job)
            return self._json(200, self._job_view(job))

        def do_POST(self):
            if not self._allowed():
                return self._json(403, {"error": "forbidden"})
            body = self._body()
            if body is None:
                return
            if self.path == "/api/plan":
                return self._plan(body)
            if self.path == "/api/run":
                return self._run(body)
            match = re.fullmatch(r"/api/job/([\w-]+)/stop", self.path)
            if match and match.group(1) in jobs:
                jobs[match.group(1)].cancel.set()    # the run finishes its current lookup, then stops
                return self._json(200, {"stopping": True})
            return self._json(404, {"error": "not found"})

        def _plan(self, body: dict) -> None:
            plan, ignored = plan_from(body)
            cost = estimate(plan, deps.cache, _options(body))

            def counts(no_vt: bool) -> dict:
                # The same numbers for either VirusTotal switch position, so the page can
                # relabel Run the instant the switch moves (no stale OPSEC label).
                variant, _ = plan_from({**body, "no_vt": no_vt})
                variant_cost = estimate(variant, deps.cache, _options(body))
                return {"iocs": sum(1 for item in variant.items if not item.skip),
                        "lookups": sum(1 for item in variant.items for lk in item.lookups if lk.outcome == "ask"),
                        "vt_calls": variant_cost.vt_calls,
                        "vt_calls_max": variant_cost.vt_calls + variant_cost.vt_age_calls_max}
            # Missing keys go in one banner (missing_keys), not on every row.
            options = _options(body)
            rows = []
            for item in plan.items:
                asks_something = any(lk.outcome == "ask" for lk in item.lookups)
                # Which planned lookups already have a cached answer (no new request will be sent)
                cached = set() if options.no_cache else {
                    lk.source for lk in item.lookups
                    if lk.outcome == "ask" and deps.cache.get(lk.cache_name, lk.cache_ioc)}
                rows.append({"type": item.ioc.type, "value": defang(item.ioc),
                             "status": plan_status(item, hide_reasons={"no key"}),
                             "kind": "skip" if item.skip or not asks_something else "plan",
                             "sources": source_states(item, [], cached), "cdn": item.cdn, "skip": item.skip,
                             "gaps": []})
            checked = sum(1 for item in plan.items if not item.skip)
            lookups = sum(1 for item in plan.items for lk in item.lookups if lk.outcome == "ask")
            self._json(200, {"cost": cost.describe(checked) if plan.items else "",
                             # What Run will do, so the page can say it before anything is sent:
                             "iocs": checked,
                             "lookups": lookups,
                             "vt_calls": cost.vt_calls,
                             "vt_calls_max": cost.vt_calls + cost.vt_age_calls_max,
                             "counts": {"on": counts(False), "off": counts(True)},
                             "missing_keys": missing_keys(current_keys()),
                             "rows": rows, "ignored": [f"{t}: {r}" for t, r in ignored]})

        def _run(self, body: dict) -> None:
            plan, _ = plan_from(body)
            job = Job(plan, _incident_date(body))
            with run_lock:
                if active and not active[0].done:
                    return self._json(409, {"error": "a run is already in progress"})
                active[:] = [job]
            job_id = secrets.token_hex(8)
            jobs[job_id] = job
            if not _options(body).no_cache:   # lookups whose answer is already cached send nothing
                job.reused = {
                    (lk.ioc, lk.source)
                    for item in plan.items for lk in item.lookups + plan.possible_follow_ups(item.ioc)
                    if lk.outcome == "ask" and deps.cache.get(lk.cache_name, lk.cache_ioc)}
            run_keys = current_keys()

            def work():
                def on_result(ioc, result):
                    with job.lock:
                        job.results.setdefault(ioc, []).append(result)

                def mark_unanswered(reason):
                    with job.lock:              # say so in the rows and the CSV
                        for lookup in plan.unanswered(job.results):
                            job.results.setdefault(lookup.ioc, []).append(SourceResult(
                                lookup.source, "not_checked", deps.now().date(), reason=reason))
                try:
                    run(plan, run_keys, deps.http, deps.cache, _options(body), on_result=on_result,
                        today=lambda: deps.now().date(), sleep=deps.sleep, clock=deps.clock,
                        cancel=job.cancel)
                    if job.cancel.is_set():
                        job.stopped = True
                        mark_unanswered("stopped")
                except Exception as error:      # shown on the page instead of a silent stop
                    job.error = f"run failed: {type(error).__name__}"
                    mark_unanswered("run failed")
                finally:
                    job.done = True

            threading.Thread(target=work, daemon=True).start()
            self._json(200, {"job": job_id})

        def _job_view(self, job: Job) -> dict:
            with job.lock:
                results = {ioc: list(r) for ioc, r in job.results.items()}
            # While the run goes on, a row with lookups still pending must not look like a verdict.
            pending = set() if job.done else {lk.ioc for lk in job.plan.unanswered(results)}
            rows = []
            for item in job.plan.items:
                found = results.get(item.ioc, [])
                status = _skip_status(item)
                if status is not None:
                    kind = "skip"
                elif found and item.ioc not in pending:
                    status, kind = flagged_by(found), result_kind(found)
                else:
                    status, kind = ("checking..." if not job.done else "not checked"), ("checking" if not job.done else "skip")
                text = enrichment(item.ioc, found, job.incident_date) if found and not item.skip else ""
                links = [] if item.skip == "private" else manual_links(item.ioc)
                rows.append({"type": item.ioc.type, "value": defang(item.ioc), "status": status, "kind": kind,
                             "gaps": strong_gaps(found),
                             "details": row_details(item.ioc, found, job.incident_date) if found and not item.skip else [],
                             "sources": source_states(item, found), "cdn": item.cdn, "skip": item.skip,
                             "enrichment": text, "links": links})
            return {"done": job.done, "error": job.error, "stopped": job.stopped,
                    "progress": job.plan.progress(results, reused=job.reused), "rows": rows}

        def _csv(self, job: Job) -> None:
            with job.lock:
                results = {ioc: list(r) for ioc, r in job.results.items()}
            rows, _ = build_rows(job.plan, results, None, job.incident_date, deps.now().date())
            name = f"ioc-enrich-{deps.now():%Y-%m-%d-%H%M}.csv"
            self._send(200, rows_to_csv_text(rows).encode("utf-8"), "text/csv; charset=utf-8",
                       {"Content-Disposition": f'attachment; filename="{name}"'})

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve(port: int = 8765) -> int:
    from ioc_enrich.cli import default_deps

    token = secrets.token_urlsafe(24)
    deps = default_deps()
    server = make_server(port, token, deps)
    print(f"Open http://127.0.0.1:{port}/?t={token}")
    print("Press Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        deps.cache.close()
    return 0
