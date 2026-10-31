"""MalwareBazaar (abuse.ch) — get_info only. Never get_file, never uploads."""

from datetime import date

from ioc_enrich.http import HttpClient
from ioc_enrich.models import IOC, SourceResult
from ioc_enrich.sources.abusech import http_error, unexpected

API = "https://mb-api.abuse.ch/api/v1/"


def lookup(ioc: IOC, key: str, http: HttpClient, today: date) -> SourceResult:
    response = http.post_form(API, {"query": "get_info", "hash": ioc.value}, {"Auth-Key": key})
    error = http_error("MalwareBazaar", response, today)
    if error:
        return error
    data = response.json()
    status = data.get("query_status")
    if status == "hash_not_found":
        return SourceResult("MalwareBazaar", "not_listed", today)
    if status != "ok":
        return unexpected("MalwareBazaar", status, today)
    sample = (data.get("data") or [{}])[0]
    fields = {"signature": sample.get("signature"), "tags": sample.get("tags") or []}
    return SourceResult("MalwareBazaar", "ok", today, fields=fields, flagged=True)
