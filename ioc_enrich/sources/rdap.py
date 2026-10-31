"""RDAP via rdap.org — domain creation date and registrar. No key needed.

The engine only calls this when the TLD has an RDAP server (IANA bootstrap),
because rdap.org answers 404 for TLDs without one (e.g. .ie).
"""

from datetime import date

from ioc_enrich.http import HttpClient
from ioc_enrich.lists import registered_domain
from ioc_enrich.models import IOC, SourceResult

API = "https://rdap.org/domain/"


def _registrar(data: dict) -> str | None:
    """Name ('fn' in the vCard) of the entity whose role is 'registrar'."""
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray", [None, []])[1]
            for item in vcard:
                if item[0] == "fn":
                    return item[3]
    return None


def _iso_date(text) -> str | None:
    """'2026-05-16T03:12:00Z' -> '2026-05-16'. Anything that is not a real date -> None,
    so one registry's odd format can never break the enrichment text."""
    if not isinstance(text, str):
        return None
    try:
        return date.fromisoformat(text[:10]).isoformat()
    except ValueError:
        return None


def lookup(ioc: IOC, key: str | None, http: HttpClient, today: date) -> SourceResult:
    response = http.get(API + registered_domain(ioc.value))
    if response.status == 404:
        return SourceResult("RDAP", "not_listed", today)
    if response.status != 200:
        return SourceResult("RDAP", "not_checked", today, reason=f"error: HTTP {response.status}")
    data = response.json()
    created = next((_iso_date(e.get("eventDate")) for e in data.get("events", [])
                    if e.get("eventAction") == "registration"), None)
    return SourceResult("RDAP", "ok", today, fields={"created": created, "registrar": _registrar(data)})
