"""VirusTotal API v3 — lookups only (GET). Never submits or rescans.

Note: VirusTotal adds every IOC queried through its API to its dataset.
Use --no-vt when that could tip off an attacker (see README).
"""

import base64
from datetime import date, datetime, timezone

from ioc_enrich.http import HttpClient
from ioc_enrich.models import IOC, SourceResult

API = "https://www.virustotal.com/api/v3/"
_COLLECTION = {"domain": "domains", "ip": "ip_addresses", "url": "urls",
               "md5": "files", "sha1": "files", "sha256": "files"}


def url_id(url: str) -> str:
    """VT's id for a URL: URL-safe base64 of the URL, without '=' padding."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _object_path(ioc: IOC) -> str:
    value = url_id(ioc.value) if ioc.type == "url" else ioc.value
    return f"{_COLLECTION[ioc.type]}/{value}"


def _unix_to_date(timestamp) -> str | None:
    if not timestamp:
        return None
    return datetime.fromtimestamp(timestamp, timezone.utc).date().isoformat()


def _verdict_words(ioc: IOC, attributes: dict) -> list[str]:
    """Short words describing what flagging engines said.

    Hashes: VT's suggested threat label (engine results are long signature names).
    Others: the distinct result words of engines that said malicious/suspicious.
    """
    if ioc.type in ("md5", "sha1", "sha256"):
        label = attributes.get("popular_threat_classification", {}).get("suggested_threat_label")
        return [label] if label else []
    words = {
        engine.get("result")
        for engine in attributes.get("last_analysis_results", {}).values()
        if engine.get("category") in ("malicious", "suspicious") and engine.get("result")
    }
    return sorted(words)


def lookup(ioc: IOC, key: str, http: HttpClient, today: date) -> SourceResult:
    response = http.get(API + _object_path(ioc), {"x-apikey": key})
    if response.status == 404:
        return SourceResult("VT", "not_listed", today)
    if response.status != 200:
        return SourceResult("VT", "not_checked", today, reason=f"error: HTTP {response.status}")

    attributes = response.json()["data"]["attributes"]
    stats = attributes.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    fields = {
        "malicious": malicious,
        "suspicious": suspicious,
        "total": sum(stats.values()),
        "words": _verdict_words(ioc, attributes),
        "creation_date": _unix_to_date(attributes.get("creation_date")),
    }
    return SourceResult("VT", "ok", today, fields=fields, flagged=malicious + suspicious >= 1)


def lookup_age(domain: str, key: str, http: HttpClient, today: date) -> SourceResult:
    """Creation date of a registered domain (used when RDAP has no server for the TLD)."""
    response = http.get(API + f"domains/{domain}", {"x-apikey": key})
    if response.status == 404:
        return SourceResult("VT-age", "not_listed", today, fields={"creation_date": None})
    if response.status != 200:
        return SourceResult("VT-age", "not_checked", today, reason=f"error: HTTP {response.status}")
    created = _unix_to_date(response.json()["data"]["attributes"].get("creation_date"))
    return SourceResult("VT-age", "ok", today, fields={"creation_date": created})


def relationships_for(ioc: IOC) -> list[str]:
    """Read-only VT relationships fetched with --deep (one VT request each)."""
    if ioc.type in ("domain", "ip"):
        return ["resolutions"]
    if ioc.type in ("md5", "sha1", "sha256"):
        return ["contacted_domains", "contacted_ips"]
    return []


def lookup_related(ioc: IOC, relationship: str, key: str, http: HttpClient, today: date) -> SourceResult:
    """--deep: ONE relationship (one request), shown on screen only."""
    response = http.get(API + f"{_object_path(ioc)}/{relationship}?limit=10", {"x-apikey": key})
    if response.status != 200:
        return SourceResult(f"VT-related:{relationship}", "not_checked", today, reason=f"error: HTTP {response.status}")
    rows = response.json().get("data", [])
    if relationship == "resolutions":
        other = "ip_address" if ioc.type == "domain" else "host_name"
        values = [f"{_unix_to_date(r['attributes'].get('date'))} {r['attributes'].get(other)}" for r in rows]
    else:
        values = [row["id"] for row in rows]
    return SourceResult(f"VT-related:{relationship}", "ok", today, fields={relationship: values})
