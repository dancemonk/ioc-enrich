"""AlienVault OTX — indicator 'general' section only. Never submits."""

from datetime import date
from urllib.parse import quote

from ioc_enrich.http import HttpClient
from ioc_enrich.lists import registered_domain
from ioc_enrich.models import IOC, SourceResult

API = "https://otx.alienvault.com/api/v1/indicators/"


def _section(ioc: IOC) -> str:
    """OTX's name for the indicator type."""
    if ioc.type == "domain":
        # OTX separates registered domains from hostnames (subdomains).
        return "domain" if ioc.value == registered_domain(ioc.value) else "hostname"
    return {"ip": "IPv4", "url": "url"}.get(ioc.type, "file")


def lookup(ioc: IOC, key: str, http: HttpClient, today: date) -> SourceResult:
    url = f"{API}{_section(ioc)}/{quote(ioc.value, safe='')}/general"
    response = http.get(url, {"X-OTX-API-KEY": key})
    if response.status == 404:
        return SourceResult("OTX", "not_listed", today, fields={"pulses": 0})
    if response.status != 200:
        return SourceResult("OTX", "not_checked", today, reason=f"error: HTTP {response.status}")
    pulses = response.json().get("pulse_info", {}).get("count", 0)
    status = "ok" if pulses >= 1 else "not_listed"
    return SourceResult("OTX", status, today, fields={"pulses": pulses}, flagged=pulses >= 1)
