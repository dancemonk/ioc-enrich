"""AbuseIPDB — /check only. Never reports or clears addresses."""

from datetime import date
from urllib.parse import urlencode

from ioc_enrich.http import HttpClient
from ioc_enrich.models import IOC, SourceResult

API = "https://api.abuseipdb.com/api/v2/check?"


def lookup(ioc: IOC, key: str, http: HttpClient, today: date) -> SourceResult:
    url = API + urlencode({"ipAddress": ioc.value, "maxAgeInDays": 90})
    response = http.get(url, {"Key": key, "Accept": "application/json"})
    if response.status != 200:
        return SourceResult("AbuseIPDB", "not_checked", today, reason=f"error: HTTP {response.status}")
    data = response.json().get("data", {})
    fields = {
        "score": data.get("abuseConfidenceScore", 0),
        "reports": data.get("totalReports", 0),
        "isp": data.get("isp"),
        "usage": data.get("usageType"),
    }
    return SourceResult("AbuseIPDB", "ok", today, fields=fields, flagged=fields["reports"] >= 1)
