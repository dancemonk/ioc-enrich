"""ThreatFox (abuse.ch) — IOC search only. Never calls submit_ioc."""

from datetime import date

from ioc_enrich.http import HttpClient
from ioc_enrich.models import IOC, SourceResult
from ioc_enrich.sources.abusech import http_error, unexpected

API = "https://threatfox-api.abuse.ch/api/v1/"


def _is_this_ip(stored, ip: str) -> bool:
    return isinstance(stored, str) and (stored == ip or stored.startswith(ip + ":"))


def lookup(ioc: IOC, key: str, http: HttpClient, today: date) -> SourceResult:
    if ioc.type == "sha1":
        raise ValueError("ThreatFox search_hash supports MD5 and SHA256 only")
    if ioc.type in ("md5", "sha256"):
        payload = {"query": "search_hash", "hash": ioc.value}
    elif ioc.type == "ip":
        # Most IPs are stored as "ip:port", which an exact search misses. Search
        # wildcard and keep only "ip" and "ip:port" entries below.
        payload = {"query": "search_ioc", "search_term": ioc.value}
    else:
        # exact_match: the default is a wildcard search, which would return look-alikes.
        payload = {"query": "search_ioc", "search_term": ioc.value, "exact_match": True}

    response = http.post_json(API, payload, {"Auth-Key": key})
    error = http_error("ThreatFox", response, today)
    if error:
        return error
    data = response.json()
    status = data.get("query_status")
    if status == "no_result":
        return SourceResult("ThreatFox", "not_listed", today)
    if status != "ok":
        return unexpected("ThreatFox", status, today)
    entries = data.get("data") or []
    if ioc.type == "ip":
        entries = [e for e in entries if _is_this_ip(e.get("ioc"), ioc.value)]
        if not entries:
            return SourceResult("ThreatFox", "not_listed", today)
    families = sorted({entry.get("malware_printable") for entry in entries if entry.get("malware_printable")})
    return SourceResult("ThreatFox", "ok", today, fields={"families": families}, flagged=True)
