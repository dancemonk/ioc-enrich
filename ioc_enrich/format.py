"""Turn lookup results into the short text that goes into the CSV and the screen."""

from datetime import date

from ioc_enrich.fang import defang
from ioc_enrich.lookup_plan import PlannedIOC
from ioc_enrich.models import IOC, SourceResult

# Order of the parts in the enrichment cell (see docs/design.md).
PART_ORDER = ["ThreatFox", "VT", "URLhaus", "MalwareBazaar", "OTX", "AbuseIPDB", "InternetDB"]
# Order in the "flagged by" line: VT first, as in the design's example.
FLAG_ORDER = ["VT", "ThreatFox", "URLhaus", "MalwareBazaar", "OTX", "AbuseIPDB"]
# Sources that describe an IOC but can never flag it. Their answers alone are not a "none".
INFO_SOURCES = {"RDAP", "InternetDB"}
# OTX's general section lists at most 50 pulses and its count stops there too.
OTX_PULSE_CAP = 50


def _plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def _pulse_count(pulses: int) -> str:
    return f"{pulses}+" if pulses >= OTX_PULSE_CAP else str(pulses)


def _pulses(pulses: int) -> str:
    return f"{_pulse_count(pulses)} pulse{'' if pulses == 1 else 's'}"


def _shortened(items: list, limit: int, sep: str) -> str:
    """'22 80 443' or, past the limit, '1 2 3 +9'."""
    shown = sep.join(str(item) for item in items[:limit])
    return shown + (f"{sep}+{len(items) - limit}" if len(items) > limit else "")


def _host_parts(fields: dict) -> list[str]:
    """InternetDB facts: ['ports 22 80 443', '1 vuln (CVE-2017-15906)', 'tag vpn']."""
    parts = []
    if fields.get("ports"):
        parts.append("ports " + _shortened(fields["ports"], 10, " "))
    if fields.get("vulns"):
        parts.append(f"{_plural(len(fields['vulns']), 'vuln')} ({_shortened(fields['vulns'], 3, ', ')})")
    if fields.get("tags"):
        parts.append(("tag " if len(fields["tags"]) == 1 else "tags ") + " ".join(fields["tags"]))
    return parts


def _vt_score(fields: dict) -> str:
    return f"VT {fields['malicious'] + fields['suspicious']}/{fields['total']}"


def _found_text(result: SourceResult) -> str:
    """Text for a source that answered (status ok or not_listed)."""
    f = result.fields
    source = result.source
    if result.status == "not_listed":
        if source == "VT":
            return "VT: not found"
        if source == "OTX":
            return "OTX: 0 pulses"
        if source == "InternetDB":
            return "InternetDB: no data"
        return f"{source}: not listed"
    if source == "VT":
        words = f" ({', '.join(f['words'])})" if f.get("words") else ""
        return _vt_score(f) + words
    if source == "ThreatFox":
        return "ThreatFox: " + (", ".join(f.get("families") or []) or "listed")
    if source == "URLhaus":
        if f.get("kind") == "url":
            return f"URLhaus: {f.get('threat') or 'listed'} ({f.get('url_status') or 'unknown'})"
        if f.get("kind") == "host":
            return f"URLhaus: {_plural(f.get('url_count', 0), 'URL')} ({f.get('threat') or 'unknown'})"
        return f"URLhaus: payload on {_plural(f.get('url_count', 0), 'URL')} ({f.get('signature') or 'unknown'})"
    if source == "MalwareBazaar":
        return f"MalwareBazaar: {f.get('signature') or 'listed'}"
    if source == "OTX":
        return f"OTX: {_pulses(f.get('pulses', 0))}"
    if source == "AbuseIPDB":
        return f"AbuseIPDB: {f.get('score', 0)}% ({_plural(f.get('reports', 0), 'report')})"
    if source == "InternetDB":
        return "InternetDB: " + (", ".join(_host_parts(f)) or "no open ports seen")
    return source


def _part(result: SourceResult) -> str:
    if result.status == "skipped":
        return f"{result.source}: skipped ({result.reason})"
    if result.status == "not_checked":
        if result.reason == "--no-vt":
            return "VT: off (--no-vt)"
        return f"{result.source}: not checked ({result.reason})"
    return _found_text(result)


def _age_part(results: list[SourceResult], ref_date: date | None) -> str:
    """'created 2026-05-15 via RDAP (86 d before incident)' or 'age n/a'."""
    created, via = None, None
    for source, field in (("RDAP", "created"), ("VT-age", "creation_date"), ("VT", "creation_date")):
        for result in results:
            if result.source == source and result.status == "ok" and result.fields.get(field):
                created, via = result.fields[field], "RDAP" if source == "RDAP" else "VT"
                break
        if created:
            break
    if not created:
        age_lookup = next((r for r in results if r.source == "VT-age" and r.status == "not_checked"), None)
        if age_lookup:                      # say why, instead of a bare "n/a"
            return f"age not checked ({age_lookup.reason})"
        return "age n/a"
    text = f"created {created} via {via}"
    if ref_date:
        days = (ref_date - date.fromisoformat(created)).days
        text += f" ({days} d before incident)" if days >= 0 else f" ({-days} d after incident)"
    return text


def enrichment(ioc: IOC, results: list[SourceResult], ref_date: date | None) -> str:
    """The CSV 'enrichment' cell for one IOC."""
    by_source = {r.source: r for r in results}
    parts = [_part(by_source[name]) for name in PART_ORDER if name in by_source]
    if ioc.type == "domain":
        rdap = by_source.get("RDAP")
        if rdap and rdap.status == "not_checked":
            parts.append(_part(rdap))
        parts.append(_age_part(results, ref_date))
    return "; ".join(parts)


def flagged_by(results: list[SourceResult]) -> str:
    """Which sources flagged the IOC — facts, not a verdict.

    Rules: VT malicious+suspicious >= 1; listed in ThreatFox/URLhaus/MalwareBazaar;
    OTX >= 1 pulse; AbuseIPDB >= 1 report.
    """
    by_source = {r.source: r for r in results}
    labels = []
    for name in FLAG_ORDER:
        result = by_source.get(name)
        if not result or not result.flagged:
            continue
        if name == "VT":
            labels.append(_vt_score(result.fields))
        elif name == "OTX":
            labels.append(f"OTX {_pulses(result.fields['pulses'])}")
        elif name == "AbuseIPDB":
            labels.append(f"AbuseIPDB {_plural(result.fields['reports'], 'report')}")
        else:
            labels.append(name)
    if labels:
        return "flagged by: " + ", ".join(labels)
    if any(r.status in ("ok", "not_listed") and r.source not in INFO_SOURCES for r in results):
        return "flagged by: none"
    return "not checked"


def checked_on(results: list[SourceResult], today: date) -> date:
    """Date of the oldest answer used (a cached answer keeps its own date)."""
    dates = [r.fetched_on for r in results if r.status in ("ok", "not_listed", "skipped")]
    return min(dates) if dates else today


def screen_line(planned: PlannedIOC, results: list[SourceResult], ref_date: date | None) -> str:
    """One summary line per IOC for the terminal."""
    head = f"{planned.ioc.type:<7}{defang(planned.ioc):<33} "
    if planned.skip == "private":
        return head + "skipped (private)"
    if planned.skip == "allowlisted":
        return head + "allowlisted - not checked"
    line = f"{head}{flagged_by(results)}  |  {enrichment(planned.ioc, results, ref_date)}"
    if planned.cdn:
        line += f"  [shared CDN ({planned.cdn}) - do not block]"
    if any(r.cached for r in results):
        line += "  (cached)"
    return line


def plan_status(item: PlannedIOC, hide_reasons: set[str] = frozenset()) -> str:
    """What the plan intends for one IOC, e.g. for the dry run:
    'would ask: ThreatFox, URLhaus, OTX · not checked: VT (--no-vt)'.

    hide_reasons: "not checked" reasons shown elsewhere (the web page shows
    missing keys once in a banner instead of on every row)."""
    if item.skip == "private":
        return "skipped (private)"
    if item.skip == "allowlisted":
        return "allowlisted - not checked"
    asks = [lk.source for lk in item.lookups if lk.outcome == "ask"]
    text = "would ask: " + (", ".join(asks) or "nothing")
    not_checked = [f"{lk.source} ({lk.reason})" for lk in item.lookups
                   if lk.outcome == "not_checked" and lk.reason not in hide_reasons]
    if not_checked:
        text += " · not checked: " + ", ".join(not_checked)
    if item.cdn:
        vt_skipped = any(lk.source == "VT" and lk.outcome == "skipped" for lk in item.lookups)
        text += f"  [shared CDN ({item.cdn}) - do not block{'; VT skipped' if vt_skipped else ''}]"
    return text


# Short label and full name per source, for the web page's source chips.
SOURCE_NAMES = {
    "VT": ("VT", "VirusTotal"),
    "ThreatFox": ("TF", "ThreatFox"),
    "URLhaus": ("UH", "URLhaus"),
    "MalwareBazaar": ("MB", "MalwareBazaar"),
    "OTX": ("OTX", "AlienVault OTX"),
    "AbuseIPDB": ("AIPDB", "AbuseIPDB"),
    "RDAP": ("RDAP", "RDAP"),
    "InternetDB": ("IDB", "Shodan InternetDB"),
}


def source_states(item: PlannedIOC, results: list[SourceResult], cached: set[str] = frozenset()) -> list[dict]:
    """One entry per planned source: what it said (or will be asked), as data, not prose.

    state: "flagged" | "clean" | "info" (RDAP or InternetDB answered) | "planned" | "cached" | "skipped" | "not_checked".
    cached: sources whose answer is already in the cache (plan view: no new request will be sent).
    Sources without an API key are left out: the page shows missing keys once, in a banner.
    """
    answers = {r.source: r for r in results}
    states = []
    for lookup in item.lookups:
        if lookup.outcome == "not_checked" and lookup.reason == "no key":
            continue
        answer = answers.get(lookup.source)
        status = answer.status if answer else lookup.outcome
        reason = answer.reason if answer else lookup.reason
        if answer is None and status == "ask" and lookup.source in cached:
            state, detail = "cached", "cached answer, no new request"
        elif answer is None and status == "ask":
            state, detail = "planned", "new request"
        elif status == "skipped":
            state, detail = "skipped", f"skipped ({reason})"
        elif status == "not_checked":
            state, detail = "not_checked", f"not checked ({_web_reason(reason)})"
        elif lookup.source == "RDAP":
            created = answer.fields.get("created")
            state, detail = "info", f"created {created}" if created else "no registration date"
        elif lookup.source == "InternetDB":
            text = _found_text(answer).removeprefix("InternetDB: ")
            state, detail = "info", text
        else:
            state, detail = ("flagged" if answer.flagged else "clean"), _found_text(answer)
            detail = detail.removeprefix(f"{lookup.source}: ")   # the chip already names the source
        short, name = SOURCE_NAMES[lookup.source]
        entry = {"source": lookup.source, "short": short, "name": name, "state": state, "detail": detail}
        if state == "flagged":
            entry["strength"] = "strong" if lookup.source in STRONG_SOURCES else "weak"
            entry["metric"] = _chip_metric(answer)
        states.append(entry)
    return states


# Evidence strength (a fact about the sources, not a verdict):
# strong = at least one of these flagged it; weak = only OTX pulses and/or AbuseIPDB reports.
STRONG_SOURCES = {"VT", "ThreatFox", "URLhaus", "MalwareBazaar"}


def result_kind(results: list[SourceResult]) -> str:
    """'flag' (strong evidence), 'weak' (only OTX/AbuseIPDB flagged), 'clean' (answered,
    nobody flagged), 'info' (only RDAP/InternetDB answered) or 'skip' (nothing answered)."""
    if any(r.flagged and r.source in STRONG_SOURCES for r in results):
        return "flag"
    if any(r.flagged for r in results):
        return "weak"
    answered = [r for r in results if r.status in ("ok", "not_listed")]
    if any(r.source not in INFO_SOURCES for r in answered):
        return "clean"
    return "info" if answered else "skip"


def strong_gaps(results: list[SourceResult]) -> list[str]:
    """Strong sources that were not asked for this IOC, e.g. ["VT not checked"].

    Without them, "weak signal" or "flagged by: none" is only true *so far*:
    the page says so instead of understating a possibly strong hit.
    """
    by_source = {r.source: r for r in results}
    gaps = []
    for name in PART_ORDER:
        result = by_source.get(name)
        if name in STRONG_SOURCES and result and result.status in ("not_checked", "skipped"):
            gaps.append(f"{SOURCE_NAMES[name][0]} not asked ({_web_reason(result.reason)})")   # one phrase for every gap
    return gaps


def flag_summary(rows: list[dict]) -> str:
    """The page's tally line, from rows with "kind" and "gaps".

    Only rows a threat-intel source answered count as checked: an IOC that only
    RDAP or InternetDB described is "info only", never part of "0 of N flagged".
    """
    kinds = [row["kind"] for row in rows]
    strong = kinds.count("flag")
    weak_so_far = sum(1 for row in rows if row["kind"] == "weak" and row["gaps"])
    weak = kinds.count("weak") - weak_so_far
    checked = strong + kinds.count("weak") + kinds.count("clean")
    info = f"; {kinds.count('info')} info only" if "info" in kinds else ""
    if not checked:
        return "No threat-intel source checked these IOCs" + info
    so_far = f", {weak_so_far} weak so far" if weak_so_far else ""
    return (f"{strong + weak + weak_so_far} of {_plural(checked, 'checked IOC')} flagged "
            f"({strong} strong, {weak} weak{so_far}){info}")


def _chip_metric(answer: SourceResult) -> str:
    """The one number or name a flagged chip shows next to its source, e.g. "VT 2/92"."""
    f = answer.fields
    if answer.source == "VT":
        return f"{f['malicious'] + f['suspicious']}/{f['total']}"
    if answer.source == "OTX":
        return _pulse_count(f.get("pulses", 0))
    if answer.source == "AbuseIPDB":
        return str(f.get("reports", ""))
    if answer.source == "ThreatFox":
        return (f.get("families") or [""])[0]
    if answer.source == "MalwareBazaar":
        return f.get("signature") or ""
    if answer.source == "URLhaus":
        return f.get("threat") or f.get("signature") or ""
    return ""


def row_details(ioc: IOC, results: list[SourceResult], ref_date: date | None) -> list[str]:
    """Facts the chips do not already show: domain age, registrar, AbuseIPDB score, open ports,
    and why a lookup was not checked (missing keys are left to the page's banner)."""
    by_source = {r.source: r for r in results}
    details = []
    if ioc.type == "domain":
        details.append(_age_part(results, ref_date))
        rdap = by_source.get("RDAP")
        if rdap and rdap.status == "ok" and rdap.fields.get("registrar"):
            details.append(f"registrar {rdap.fields['registrar']}")
    abuse = by_source.get("AbuseIPDB")
    if abuse and abuse.status == "ok":
        details.append(f"AbuseIPDB score {abuse.fields.get('score', 0)}%")
    host = by_source.get("InternetDB")
    if host and host.status == "ok":
        parts = _host_parts(host.fields)
        if parts and parts[0].startswith("ports"):
            parts[0] = "open " + parts[0]
        details.append(" · ".join(parts) or "no open ports seen")
    # Strong sources that were not asked are already named by the headline ("VT not asked (…)").
    unchecked = [f"{SOURCE_NAMES[name][0]} ({_web_reason(by_source[name].reason)})" for name in PART_ORDER + ["RDAP"]
                 if name in by_source and by_source[name].status == "not_checked"
                 and by_source[name].reason != "no key" and name not in STRONG_SOURCES]
    if unchecked:
        details.append("not checked: " + ", ".join(unchecked))
    return details


def _web_reason(reason: str) -> str:
    """Page wording for a not-checked reason: no command-line flags on the web page."""
    return "VirusTotal switched off" if reason == "--no-vt" else reason

