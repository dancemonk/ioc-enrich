"""Helpers shared by the three abuse.ch APIs (ThreatFox, URLhaus, MalwareBazaar)."""

from datetime import date

from ioc_enrich.http import Response
from ioc_enrich.models import SourceResult


def http_error(source: str, response: Response, today: date) -> SourceResult | None:
    """A 'not checked' result for a non-200 reply, or None if the reply is fine."""
    if response.status != 200:
        return SourceResult(source, "not_checked", today, reason=f"error: HTTP {response.status}")
    return None


def unexpected(source: str, query_status: str, today: date) -> SourceResult:
    """abuse.ch reports problems (bad key, bad input) in 'query_status'."""
    return SourceResult(source, "not_checked", today, reason=f"error: {query_status}")
