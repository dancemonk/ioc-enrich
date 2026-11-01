"""The lookup plan: every lookup a run intends to make, decided before anything is sent.

This module is the ONE place for the rules about which lookups apply:
  - which sources support which IOC type
  - private IPs and allowlisted domains are skipped entirely
  - a shared CDN IP is never sent to VirusTotal
  - RDAP only for TLDs that have an RDAP server
  - --no-vt and missing keys make a lookup "not checked"
  - follow-up lookups (VT domain age, --deep relationships) that depend on an answer
  - whether a row is complete

The engine, the dry run, the web page, Ctrl-C handling and the CSV merge all
read the plan instead of re-deriving these rules. The plan is pure: no
network, no cache, no keys (only which sources have one).
"""

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from ioc_enrich.config import Keys
from ioc_enrich.lists import cdn_provider, registered_domain
from ioc_enrich.models import IOC, SourceResult
from ioc_enrich.sources import KEY_FIELD
from ioc_enrich.sources.vt import relationships_for

# Which sources support which IOC type (see docs/design.md, Appendix A).
SOURCES_BY_TYPE = {
    "domain": ["ThreatFox", "VT", "URLhaus", "OTX", "RDAP"],
    "ip": ["ThreatFox", "VT", "URLhaus", "OTX", "AbuseIPDB", "InternetDB"],
    "url": ["VT", "URLhaus", "OTX"],
    "md5": ["ThreatFox", "VT", "URLhaus", "MalwareBazaar", "OTX"],
    "sha1": ["VT", "MalwareBazaar", "OTX"],          # ThreatFox and URLhaus do not take SHA1
    "sha256": ["ThreatFox", "VT", "URLhaus", "MalwareBazaar", "OTX"],
}

ANSWERED = ("ok", "not_listed")


@dataclass(frozen=True)
class Lookup:
    """One question to one source about one IOC, with its intended outcome.

    source:     name shown to the analyst and used on the answer ("VT", "VT-age",
                "VT-related:resolutions", "RDAP", ...)
    cache_name: name the answer is cached under (today always equal to source)
    cache_ioc:  IOC the answer is cached under (the registered domain for VT-age)
    outcome:    "ask" | "skipped" | "not_checked"
    reason:     why it is skipped / not checked ("shared CDN", "--no-vt", "no key")
    """

    ioc: IOC
    source: str
    cache_name: str
    cache_ioc: IOC
    outcome: str = "ask"
    reason: str = ""
    relationship: str = ""      # only for VT-related lookups


@dataclass
class PlannedIOC:
    ioc: IOC
    skip: str | None = None     # "private" | "allowlisted": no lookups at all
    cdn: str | None = None      # shared CDN provider name
    lookups: list[Lookup] = field(default_factory=list)   # decided up front


def _lookup(ioc: IOC, source: str, outcome: str = "ask", reason: str = "") -> Lookup:
    return Lookup(ioc, source, source, ioc, outcome, reason)


def _tld(ioc: IOC) -> str:
    return ioc.value.rsplit(".", 1)[-1]


class LookupPlan:
    """All lookups for a run. Build it with build_plan()."""

    def __init__(self, items: list[PlannedIOC], rdap_tlds: set[str], deep: bool = False):
        self.items = items
        self.rdap_tlds = rdap_tlds
        self.deep = deep

    def _vt_lookup(self, ioc: IOC) -> Lookup | None:
        """The up-front VT lookup for this IOC, if VT will actually be asked."""
        for item in self.items:
            if item.ioc == ioc:
                return next((lk for lk in item.lookups if lk.source == "VT" and lk.outcome == "ask"), None)
        return None

    def _age_lookup(self, ioc: IOC) -> Lookup | None:
        """VT hostname answers rarely carry a creation date. For a subdomain whose
        TLD has no RDAP, ask VT about the registered domain instead."""
        if ioc.type != "domain" or _tld(ioc) in self.rdap_tlds:
            return None
        registered = registered_domain(ioc.value)
        if ioc.value == registered:
            return None
        return Lookup(ioc, "VT-age", "VT-age", IOC("domain", registered))

    def _related_lookups(self, ioc: IOC) -> list[Lookup]:
        if not self.deep:
            return []
        return [Lookup(ioc, f"VT-related:{rel}", f"VT-related:{rel}", ioc, relationship=rel)
                for rel in relationships_for(ioc)]

    def possible_follow_ups(self, ioc: IOC) -> list[Lookup]:
        """Follow-ups that MAY be needed, whatever VT answers (for 'up to N' in the cost)."""
        if self._vt_lookup(ioc) is None:
            return []
        age = self._age_lookup(ioc)
        return ([age] if age else []) + self._related_lookups(ioc)

    def follow_ups(self, lookup: Lookup, answer: SourceResult) -> list[Lookup]:
        """Follow-ups that are due now, given this answer."""
        if lookup.source != "VT" or lookup.outcome != "ask" or answer.status not in ANSWERED:
            return []
        due = []
        age = self._age_lookup(lookup.ioc)
        if age and not answer.fields.get("creation_date"):
            due.append(age)
        return due + self._related_lookups(lookup.ioc)

    def unanswered(self, results: dict[IOC, list[SourceResult]]) -> list[Lookup]:
        """Lookups that should have an answer but have none (used after Ctrl-C or a crash)."""
        missing = []
        for item in self.items:
            if item.skip:
                continue
            answers = {r.source: r for r in results.get(item.ioc, [])}
            for lookup in item.lookups:
                if lookup.source not in answers:
                    missing.append(lookup)
                elif lookup.source == "VT" and lookup.outcome == "ask":
                    missing.extend(fu for fu in self.follow_ups(lookup, answers["VT"])
                                   if fu.source not in answers)
        return missing

    def progress(self, results: dict[IOC, list[SourceResult]],
                 reused: set[tuple[IOC, str]] = frozenset()) -> dict[str, int]:
        """How far a run is: answered vs expected NEW requests, overall and for VirusTotal.

        Follow-ups count once they are due (e.g. VT-age after a VT answer without a date).
        reused: (ioc, source) pairs whose answer came from the cache. They send nothing,
        so they are counted separately and never inflate "Sending to VirusTotal · x of y".
        """
        counts = {"done": 0, "total": 0, "vt_done": 0, "vt_total": 0, "reused": 0}
        for item in self.items:
            answers = {r.source: r for r in results.get(item.ioc, [])}
            expected = [lk for lk in item.lookups if lk.outcome == "ask"]
            vt = next((lk for lk in expected if lk.source == "VT"), None)
            if vt and "VT" in answers:
                expected += self.follow_ups(vt, answers["VT"])
            for lookup in expected:
                if (item.ioc, lookup.source) in reused:
                    counts["reused"] += 1
                    continue
                answered = int(lookup.source in answers)
                counts["total"] += 1
                counts["done"] += answered
                if lookup.source.startswith("VT"):
                    counts["vt_total"] += 1
                    counts["vt_done"] += answered
        return counts

    def is_complete(self, ioc: IOC, results: dict[IOC, list[SourceResult]]) -> bool:
        """A complete row: every planned lookup answered or deliberately skipped."""
        if any(r.status == "not_checked" for r in results.get(ioc, [])):
            return False
        return not any(lk.ioc == ioc for lk in self.unanswered(results))


def load_allowlist(path: Path) -> set[str]:
    """Known-good domains, one per line. A missing file means an empty list."""
    if not path.exists():
        return set()
    lines = path.read_text(encoding="utf-8").splitlines()
    return {line.strip().lower() for line in lines if line.strip() and not line.startswith("#")}


def keyed_sources(keys: Keys) -> set[str]:
    """Names of the sources whose API key is present."""
    return {source for source, key_field in KEY_FIELD.items() if key_field and getattr(keys, key_field)}


def _is_allowlisted(host: str, allowlist: set[str]) -> bool:
    """True if host is an allowlisted domain or a subdomain of one."""
    return any(host == good or host.endswith("." + good) for good in allowlist)


def _is_non_global_ip(text: str) -> bool:
    """True for private/reserved IPv4 addresses; False for anything else."""
    try:
        return not ipaddress.IPv4Address(text).is_global
    except ValueError:
        return False


def _skip_and_cdn(ioc: IOC, allowlist: set[str], cdn_ranges) -> tuple[str | None, str | None]:
    if ioc.type == "ip":
        # "Not global" covers private, loopback, link-local, CGNAT, reserved...
        if _is_non_global_ip(ioc.value):
            return "private", None
        return None, cdn_provider(ioc.value, cdn_ranges)
    if ioc.type == "domain" and _is_allowlisted(ioc.value, allowlist):
        return "allowlisted", None
    if ioc.type == "url":
        host = urlsplit(ioc.value).hostname or ""
        if _is_non_global_ip(host):
            # Internal URLs (paths, tokens) must never reach VT's public dataset.
            return "private", None
        if _is_allowlisted(host, allowlist):
            return "allowlisted", None
    return None, None


def build_plan(iocs: list[IOC], *, allowlist: set[str], cdn_ranges, rdap_tlds: set[str],
               no_vt: bool = False, deep: bool = False,
               keyed_sources: set[str] | None = None) -> LookupPlan:
    """Decide every lookup for these IOCs.

    keyed_sources: sources that have an API key, or None for a dry run
    (no keys are read, so every key is assumed present).
    """
    items = []
    for ioc in iocs:
        skip, cdn = _skip_and_cdn(ioc, allowlist, cdn_ranges)
        item = PlannedIOC(ioc, skip, cdn)
        if not skip:
            for source in SOURCES_BY_TYPE[ioc.type]:
                if source == "RDAP" and _tld(ioc) not in rdap_tlds:
                    continue                      # no RDAP server for this TLD: not applicable
                if source == "VT" and no_vt:
                    item.lookups.append(_lookup(ioc, source, "not_checked", "--no-vt"))
                elif source == "VT" and cdn:
                    item.lookups.append(_lookup(ioc, source, "skipped", "shared CDN"))
                elif keyed_sources is not None and KEY_FIELD[source] and source not in keyed_sources:
                    item.lookups.append(_lookup(ioc, source, "not_checked", "no key"))
                else:
                    item.lookups.append(_lookup(ioc, source))
        items.append(item)
    return LookupPlan(items, rdap_tlds, deep)
