"""URLhaus (abuse.ch) — url / host / payload lookups only.

Never calls /v1/download/ (that returns the malware sample itself).
"""

from datetime import date

from ioc_enrich.http import HttpClient
from ioc_enrich.models import IOC, SourceResult
from ioc_enrich.sources.abusech import http_error, unexpected

API = "https://urlhaus-api.abuse.ch/v1/"


def _request(ioc: IOC) -> tuple[str, str, dict]:
    """(kind, endpoint, form) for this IOC type."""
    if ioc.type == "url":
        return "url", API + "url/", {"url": ioc.value}
    if ioc.type in ("domain", "ip"):
        return "host", API + "host/", {"host": ioc.value}
    if ioc.type in ("md5", "sha256"):
        return "payload", API + "payload/", {f"{ioc.type}_hash": ioc.value}
    raise ValueError(f"URLhaus does not support {ioc.type}")


def lookup(ioc: IOC, key: str, http: HttpClient, today: date) -> SourceResult:
    kind, endpoint, form = _request(ioc)
    response = http.post_form(endpoint, form, {"Auth-Key": key})
    error = http_error("URLhaus", response, today)
    if error:
        return error
    data = response.json()
    status = data.get("query_status")
    if status == "no_results":
        return SourceResult("URLhaus", "not_listed", today)
    if status != "ok":
        return unexpected("URLhaus", status, today)

    if kind == "url":
        fields = {"kind": kind, "threat": data.get("threat"), "url_status": data.get("url_status")}
    elif kind == "host":
        threats = [u.get("threat") for u in data.get("urls", []) if u.get("threat")]
        fields = {"kind": kind, "url_count": int(data.get("url_count") or 0),
                  "threat": threats[0] if threats else None}
    else:
        fields = {"kind": kind, "url_count": int(data.get("url_count") or 0), "signature": data.get("signature")}
    return SourceResult("URLhaus", "ok", today, fields=fields, flagged=True)
