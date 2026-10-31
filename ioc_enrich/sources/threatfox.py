"""ThreatFox (abuse.ch) — IOC search only. Never calls submit_ioc."""

from datetime import date

from ioc_enrich.http import HttpClient
from ioc_enrich.models import IOC, SourceResult
from ioc_enrich.sources.abusech import http_error, unexpected

API = "https://threatfox-api.abuse.ch/api/v1/"


def lookup(ioc: IOC, key: str, http: HttpClient, today: date) -> SourceResult:
    if ioc.type == "sha1":
        raise ValueError("ThreatFox search_hash supports MD5 and SHA256 only")
    if ioc.type in ("md5", "sha256"):
        payload = {"query": "search_hash", "hash": ioc.value}
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
    families = sorted({entry.get("malware_printable") for entry in data.get("data", []) if entry.get("malware_printable")})
    return SourceResult("ThreatFox", "ok", today, fields={"families": families}, flagged=True)
