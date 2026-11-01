"""Command line: `ioc-enrich [FILE] ...`, `ioc-enrich serve`, `ioc-enrich keys`, `ioc-enrich update-lists`."""

import argparse
import sys
import threading
import time
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Callable

from ioc_enrich import __version__
from ioc_enrich.cache import DEFAULT_CACHE_FILE, Cache
from ioc_enrich.config import DEFAULT_KEYS_FILE, load_keys
from ioc_enrich.csvio import build_rows, default_output_name, read_rows, ref_date, row_key, write_rows
from ioc_enrich.engine import RunOptions, estimate, run
from ioc_enrich.extract import extract
from ioc_enrich.fang import defang
from ioc_enrich.format import plan_status, screen_line
from ioc_enrich.links import manual_links
from ioc_enrich.lists import load_cdn_ranges, load_rdap_tlds, load_tlds
from ioc_enrich.lookup_plan import LookupPlan, build_plan, keyed_sources, load_allowlist
from ioc_enrich.models import IOC, SourceResult

DEFAULT_ALLOWLIST = Path.home() / ".config" / "ioc-enrich" / "allowlist.txt"
LOOKUP_TYPES = {"domain", "ip", "url", "md5", "sha1", "sha256"}

EPILOG = """\
commands:
  ioc-enrich [FILE] [options]   enrich IOCs from FILE or stdin (default)
  ioc-enrich serve [--port N]   local web page on 127.0.0.1
  ioc-enrich keys               save your API keys (asks for each one)
  ioc-enrich update-lists       refresh bundled TLD / RDAP / CDN lists

example:
  echo "www.taibeinan[.]cc 146.59.71[.]167" | ioc-enrich --dry-run

Lookup only: never contacts an IOC, never submits anything for scanning.
API keys: run `ioc-enrich keys`, or set env vars VT_API_KEY, ABUSECH_AUTH_KEY,
OTX_API_KEY, ABUSEIPDB_API_KEY, or write ~/.config/ioc-enrich/keys.env
"""


@dataclass
class Deps:
    """Things tests replace with fakes."""
    http: object
    cache: Cache
    now: Callable[[], datetime] = datetime.now
    sleep: Callable[[float], None] | None = None   # None: real waits that end early on Ctrl-C
    clock: Callable[[], float] = time.monotonic


def default_deps() -> Deps:
    from ioc_enrich.http import HttpClient
    return Deps(http=HttpClient(), cache=Cache(DEFAULT_CACHE_FILE))


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ioc-enrich",
        description="Look up IOCs (domains, IPv4, URLs, hashes) in public threat-intel APIs "
                    "and write the results in iocs.csv format.",
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("file", nargs="?", type=Path, help="text file with IOCs (default: stdin)")
    p.add_argument("-o", "--output", type=Path, help="CSV to write (never overwritten; default ioc-enrich-YYYY-MM-DD-HHMM.csv)")
    p.add_argument("--merge", type=Path, metavar="CSV", help="existing iocs.csv to merge into (your columns are never changed)")
    p.add_argument("--incident-date", type=date.fromisoformat, metavar="YYYY-MM-DD",
                   help="reference date for domain age, used when a row has no first_seen_utc")
    p.add_argument("--no-vt", action="store_true", help="do not ask VirusTotal (VT adds every queried IOC to its dataset)")
    p.add_argument("--no-cache", action="store_true", help="ignore cached results (7-day cache)")
    p.add_argument("--deep", action="store_true", help="also fetch a few VT relationships (costs extra VT calls)")
    p.add_argument("--dry-run", action="store_true", help="show what would be queried and the VT cost; send nothing")
    p.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST, help="known-good domains, one per line")
    p.add_argument("--keys", type=Path, default=DEFAULT_KEYS_FILE, help="keys file (NAME=value lines)")
    p.add_argument("--vt-per-minute", type=int, default=4, help="VT rate limit (default 4, free key)")
    p.add_argument("--vt-daily-limit", type=int, default=500, help="VT daily quota (default 500, free key)")
    p.add_argument("--version", action="version", version=f"ioc-enrich {__version__}")
    return p


def _read_input(args, stdin, existing) -> str:
    if args.file:
        return args.file.read_text(encoding="utf-8")
    text = "" if stdin is None or stdin.isatty() else stdin.read()
    if not text.strip() and existing:
        # --merge with no input: re-check the lookup-able rows of the file.
        text = "\n".join(row["value"] for row in existing if row["type"] in LOOKUP_TYPES)
    return text


def _section(out, title: str, lines: list[str]) -> None:
    if lines:
        print(f"\n{title}:", file=out)
        for line in lines:
            print(f"  {line}", file=out)


def _links_section(out, plan: LookupPlan) -> None:
    lines = []
    for item in plan.items:
        if item.skip == "private":
            continue
        lines.append(defang(item.ioc))
        lines.extend(f"    {label}: {url}" for label, url in manual_links(item.ioc))
    _section(out, "Manual-check links", lines)


def _dry_run(out, plan: LookupPlan, cost, ignored) -> int:
    print("Dry run: nothing is sent, no keys are read.\n", file=out)
    per_source: dict[str, int] = {}
    for item in plan.items:
        print(f"{item.ioc.type:<7}{defang(item.ioc):<33} {plan_status(item)}", file=out)
        for lookup in item.lookups:
            if lookup.outcome == "ask":
                per_source[lookup.source] = per_source.get(lookup.source, 0) + 1
    _section(out, "Ignored", [f"{token}: {reason}" for token, reason in ignored])
    checked = sum(1 for item in plan.items if not item.skip)
    print(f"\nCost: {cost.describe(checked)}", file=out)
    print("Queries per source (before cache): " + ", ".join(f"{s} {n}" for s, n in per_source.items()), file=out)
    _links_section(out, plan)
    return 0


def _mark_unanswered(plan: LookupPlan, results, reason: str, today: date) -> None:
    """Every planned lookup without an answer becomes 'not checked (<reason>)'."""
    for lookup in plan.unanswered(results):
        results.setdefault(lookup.ioc, []).append(SourceResult(lookup.source, "not_checked", today, reason=reason))


def _enrich(args, stdin, out, err, env, deps: Deps) -> int:
    try:
        existing = read_rows(args.merge) if args.merge else None
        text = _read_input(args, stdin, existing)
    except (OSError, ValueError, UnicodeDecodeError) as error:
        print(f"cannot read input: {error}", file=err)
        return 2
    found = extract(text, load_tlds())
    if not found.iocs:
        print("No IOCs found in input.", file=err)
        return 2

    allowlist, cdn_ranges, rdap_tlds = load_allowlist(args.allowlist), load_cdn_ranges(), load_rdap_tlds()

    def make_plan(sources_with_keys: set[str] | None) -> LookupPlan:
        return build_plan(found.iocs, allowlist=allowlist, cdn_ranges=cdn_ranges, rdap_tlds=rdap_tlds,
                          no_vt=args.no_vt, deep=args.deep, keyed_sources=sources_with_keys)

    opts = RunOptions(no_cache=args.no_cache, vt_per_minute=args.vt_per_minute,
                      vt_daily_limit=args.vt_daily_limit)
    if args.dry_run:
        plan = make_plan(None)            # no keys are read in a dry run
        return _dry_run(out, plan, estimate(plan, deps.cache, opts), found.ignored)

    output = args.output or Path(default_output_name(deps.now()))
    if output.exists():
        print(f"refusing to overwrite {output} (choose another -o path)", file=err)
        return 1

    today = deps.now().date()
    keys = load_keys(env, args.keys)
    plan = make_plan(keyed_sources(keys))
    cost = estimate(plan, deps.cache, opts)
    print(f"Checking: {cost.describe(sum(1 for item in plan.items if not item.skip))}", file=out)

    collected: dict[IOC, list[SourceResult]] = {}
    lock = threading.Lock()

    def on_result(ioc: IOC, result: SourceResult) -> None:
        with lock:
            collected.setdefault(ioc, []).append(result)
            print(f"  ... {result.source:<13} {defang(ioc)}", file=err)

    interrupted = False
    try:
        run(plan, keys, deps.http, deps.cache, opts, on_result=on_result,
            today=lambda: today, sleep=deps.sleep, clock=deps.clock)
    except KeyboardInterrupt:
        interrupted = True
        with lock:
            _mark_unanswered(plan, collected, "interrupted", today)

    with lock:
        results = {ioc: list(found_results) for ioc, found_results in collected.items()}
    rows_by_key = {row_key(r["type"], r["value"]): r for r in existing or []}

    print("", file=out)
    for item in plan.items:
        ref = ref_date(rows_by_key.get(row_key(item.ioc.type, item.ioc.value)), args.incident_date)
        print(screen_line(item, results.get(item.ioc, []), ref), file=out)

    _section(out, "Ignored", [f"{token}: {reason}" for token, reason in found.ignored])
    _section(out, "Not checked", [
        f"{defang(ioc)}: {r.source} ({r.reason})"
        for ioc, found_results in results.items() for r in found_results if r.status == "not_checked"])
    _section(out, "Related (VT --deep)", [
        f"{defang(ioc)}: " + "; ".join(f"{name}: {', '.join(values) or 'none'}" for name, values in r.fields.items())
        for ioc, found_results in results.items() for r in found_results
        if r.source.startswith("VT-related") and r.status == "ok"])
    _links_section(out, plan)

    rows, notes = build_rows(plan, results, existing, args.incident_date, today)
    write_rows(output, rows)
    print(f"\nWrote {output} ({len(rows)} rows)", file=out)
    for note in notes:
        print(f"  {note}", file=out)
    if interrupted:
        print("Interrupted. Answers so far are cached; rerun the same command to continue.", file=out)
        return 130
    return 0


def main(argv: list[str] | None = None, *, stdin=None, stdout=None, stderr=None,
         env=None, deps: Deps | None = None) -> int:
    import os

    argv = sys.argv[1:] if argv is None else argv
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    if argv and argv[0] == "serve":
        from ioc_enrich.server import serve
        port_parser = argparse.ArgumentParser(prog="ioc-enrich serve")
        port_parser.add_argument("--port", type=int, default=8765)
        return serve(port_parser.parse_args(argv[1:]).port)
    if argv and argv[0] == "keys":
        from ioc_enrich.setup_keys import main as keys_main
        return keys_main(argv[1:], out=out, env=os.environ if env is None else env)
    if argv and argv[0] == "update-lists":
        from ioc_enrich.update_lists import main as update_main
        return update_main()

    args = _parser().parse_args(argv)
    own_deps = deps is None
    deps = deps or default_deps()
    try:
        return _enrich(args, stdin if stdin is not None else sys.stdin, out, err,
                       os.environ if env is None else env, deps)
    finally:
        if own_deps:
            deps.cache.close()
