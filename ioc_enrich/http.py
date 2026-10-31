"""HTTP layer. Every outbound request goes through here.

Safety: check_allowed() is called before ANY request. It only lets through
the documented lookup endpoints of our sources (plus the public list URLs
used by update-lists). Anything else, including submit, rescan, download
endpoints and any IOC itself, raises BlockedEndpoint before a socket opens.
"""

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from ioc_enrich import __version__


@dataclass
class Response:
    status: int
    headers: dict = field(default_factory=dict)
    body: bytes = b""

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


class RateLimited(Exception):
    """HTTP 429. retry_after is seconds from the Retry-After header, if any."""

    def __init__(self, retry_after: float | None):
        super().__init__(f"rate limited (retry after {retry_after})")
        self.retry_after = retry_after


class BlockedEndpoint(Exception):
    """A request that is not a known lookup. Never sent."""


VT_API = "https://www.virustotal.com/api/v3/"

# GET lookups (URL prefixes).
_ALLOWED_GET = [
    "https://otx.alienvault.com/api/v1/indicators/",
    "https://api.abuseipdb.com/api/v2/check?",
    "https://rdap.org/domain/",
    # Public lists for update-lists:
    "https://data.iana.org/TLD/tlds-alpha-by-domain.txt",
    "https://data.iana.org/rdap/dns.json",
    "https://www.cloudflare.com/ips-v4/",
    "https://api.fastly.com/public-ip-list",
    "https://ip-ranges.amazonaws.com/ip-ranges.json",
]

# VT: /{collection}/{id} with an optional read-only relationship.
_VT_PATH = re.compile(
    r"^(domains|ip_addresses|urls|files)/[^/?]+"
    r"(/(resolutions|contacted_domains|contacted_ips))?(\?limit=\d+)?$"
)

# POST lookups: exact URL -> allowed values of the "query" field (None = no query field).
_ALLOWED_POST = {
    "https://threatfox-api.abuse.ch/api/v1/": {"search_ioc", "search_hash"},
    "https://mb-api.abuse.ch/api/v1/": {"get_info"},
    "https://urlhaus-api.abuse.ch/v1/url/": None,
    "https://urlhaus-api.abuse.ch/v1/host/": None,
    "https://urlhaus-api.abuse.ch/v1/payload/": None,
}

# Belt and braces: never allow a URL path containing one of these segments,
# whatever the prefix rules say. (Exact segments, so an IOC value such as
# "download.example.com" is still a normal lookup.)
_FORBIDDEN_SEGMENTS = {
    "analyse", "download", "download_url", "upload_url", "comments", "votes",
    "submit_file", "submit_url", "submit_urls", "report", "bulk-report", "clear-address",
}


def check_allowed(method: str, url: str, body: dict | None = None) -> None:
    """Raise BlockedEndpoint unless this is a known, read-only lookup."""
    segments = urllib.parse.urlsplit(url).path.lower().split("/")
    if _FORBIDDEN_SEGMENTS.intersection(segments):
        raise BlockedEndpoint(f"forbidden endpoint: {method} {url}")

    if method == "GET":
        if url.startswith(VT_API) and _VT_PATH.match(url[len(VT_API):]):
            return
        if any(url.startswith(prefix) for prefix in _ALLOWED_GET):
            return
    elif method == "POST" and url in _ALLOWED_POST:
        allowed_queries = _ALLOWED_POST[url]
        if allowed_queries is None:
            return
        if body is not None and body.get("query") in allowed_queries:
            return
    raise BlockedEndpoint(f"not a known lookup endpoint: {method} {url}")


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Redirects are only followed for RDAP (rdap.org sends you to the TLD's
    own RDAP server), only to https, and never for requests that carry a key.
    Any other redirect raises BlockedEndpoint, so a key can never be sent to
    a host we did not choose."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not req.full_url.startswith("https://rdap.org/domain/"):
            raise BlockedEndpoint(f"redirect refused: {req.full_url} -> {newurl}")
        if not newurl.startswith("https://"):
            raise BlockedEndpoint(f"redirect to non-https refused: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SafeRedirect)


def _retry_after(headers) -> float | None:
    value = headers.get("Retry-After") if headers else None
    try:
        return float(value) if value is not None else None
    except ValueError:
        return None


class HttpClient:
    """Small urllib wrapper. 429 raises RateLimited; other statuses return a Response."""

    def __init__(self, timeout: float = 20.0):
        self.timeout = timeout

    def _send(self, method: str, url: str, data: bytes | None, headers: dict) -> Response:
        headers = {"User-Agent": f"ioc-enrich/{__version__}", **headers}
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with _OPENER.open(request, timeout=self.timeout) as reply:
                return Response(reply.status, dict(reply.headers), reply.read())
        except urllib.error.HTTPError as error:
            with error:   # close the error's connection when done
                if error.code == 429:
                    raise RateLimited(_retry_after(error.headers)) from None
                return Response(error.code, dict(error.headers or {}), error.read())

    def get(self, url: str, headers: dict | None = None) -> Response:
        check_allowed("GET", url)
        return self._send("GET", url, None, headers or {})

    def post_json(self, url: str, payload: dict, headers: dict | None = None) -> Response:
        check_allowed("POST", url, payload)
        data = json.dumps(payload).encode("utf-8")
        return self._send("POST", url, data, {"Content-Type": "application/json", **(headers or {})})

    def post_form(self, url: str, form: dict, headers: dict | None = None) -> Response:
        check_allowed("POST", url, form)
        data = urllib.parse.urlencode(form).encode("utf-8")
        return self._send("POST", url, data, {"Content-Type": "application/x-www-form-urlencoded", **(headers or {})})
