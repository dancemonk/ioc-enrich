"""Shodan InternetDB — open ports, known vulns and tags for an IP. No key needed.

Free for non-commercial use, updated weekly. It only describes the host, so it
never flags an IOC: like RDAP, it is information, not evidence.
"""

from datetime import date

from ioc_enrich.http import HttpClient
from ioc_enrich.models import IOC, SourceResult

API = "https://internetdb.shodan.io/"


def _list_of(value, kind) -> list:
    """Keep only items of the expected type, so an odd answer can never break the text."""
    return [item for item in value if isinstance(item, kind)] if isinstance(value, list) else []


def lookup(ioc: IOC, key: str | None, http: HttpClient, today: date) -> SourceResult:
    response = http.get(API + ioc.value)
    if response.status == 404:
        return SourceResult("InternetDB", "not_listed", today)
    if response.status != 200:
        return SourceResult("InternetDB", "not_checked", today, reason=f"error: HTTP {response.status}")
    data = response.json()
    fields = {
        "ports": _list_of(data.get("ports"), int),
        "vulns": _list_of(data.get("vulns"), str),
        "tags": _list_of(data.get("tags"), str),
        "hostnames": _list_of(data.get("hostnames"), str),
    }
    return SourceResult("InternetDB", "ok", today, fields=fields)
