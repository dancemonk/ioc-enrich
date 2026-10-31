"""Find IOCs in free text (alert text, tshark output, a plain list).

How it works, token by token:
  1. Split the text on whitespace and common separators.
  2. Refang the token and remember whether it was defanged.
  3. Strip wrapping punctuation such as "(", ")", ".", ",".
  4. Try, in order: URL, hash, IPv4, IPv6, domain.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from ioc_enrich.fang import refang
from ioc_enrich.models import IOC

# TLDs that are also common file extensions. A token like "loader.py" is far
# more likely a file than a Paraguayan domain, so these need extra evidence.
FILENAME_LIKE_TLDS = {"zip", "mov", "py", "sh", "md", "pl", "rs", "ps", "so", "cc"}

_SPLIT = re.compile(r"[\s,;|\"'<>`]+")
_LEADING = "([{"
_TRAILING = ".,;:)]}!?"
_URL = re.compile(r"^https?://", re.IGNORECASE)
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}
_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


@dataclass
class ExtractResult:
    iocs: list[IOC] = field(default_factory=list)          # deduped, first-seen order
    ignored: list[tuple[str, str]] = field(default_factory=list)  # (token, reason)


def _strip_wrapping(token: str) -> str:
    return token.lstrip(_LEADING).rstrip(_TRAILING)


def _as_ipv4(text: str) -> str | None:
    """'1.2.3.4' or '1.2.3.4:443' -> '1.2.3.4'; anything else -> None."""
    host = text.rsplit(":", 1)[0] if text.count(":") == 1 else text
    try:
        return str(ipaddress.IPv4Address(host))
    except ValueError:
        return None


def _is_ipv6(text: str) -> bool:
    try:
        ipaddress.IPv6Address(text.strip("[]"))
        return True
    except ValueError:
        return False


def _as_domain(text: str, tlds: set[str]) -> str | None:
    """Lowercase domain if it looks like a hostname ending in a real TLD."""
    candidate = text.lower().rstrip(".")
    if not _DOMAIN.match(candidate):
        return None
    if candidate.rsplit(".", 1)[1] not in tlds:
        return None
    return candidate


def _normalize_url(url: str) -> tuple[str, str]:
    """Lowercase scheme and host; return (url, host)."""
    parts = urlsplit(url)
    host = (parts.hostname or "").rstrip(".")
    netloc = host + (f":{parts.port}" if parts.port else "")
    return urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment)), host


def extract(text: str, tlds: set[str]) -> ExtractResult:
    result = ExtractResult()
    seen: set[IOC] = set()

    def add(ioc: IOC) -> None:
        if ioc not in seen:
            seen.add(ioc)
            result.iocs.append(ioc)

    for raw in _SPLIT.split(text):
        if not raw:
            continue
        refanged = refang(raw)
        was_defanged = refanged != raw
        token = _strip_wrapping(refanged)
        if not token:
            continue

        if _URL.match(token):
            try:
                url, host = _normalize_url(token)
            except ValueError:          # e.g. a broken port number
                continue
            ip = _as_ipv4(host)
            if ip:
                add(IOC("url", url))
                add(IOC("ip", ip))
            elif _as_domain(host, tlds):
                add(IOC("url", url))
                add(IOC("domain", host))
            continue

        if _HEX.match(token) and len(token) in _HASH_TYPES:
            add(IOC(_HASH_TYPES[len(token)], token.lower()))
            continue

        ip = _as_ipv4(token)
        if ip:
            add(IOC("ip", ip))
            continue

        if ":" in token and _is_ipv6(token):
            result.ignored.append((token, "IPv6 not supported yet"))
            continue

        domain = _as_domain(token, tlds)
        if domain:
            tld = domain.rsplit(".", 1)[1]
            if tld in FILENAME_LIKE_TLDS and not (was_defanged or domain.startswith("www.")):
                result.ignored.append((token, "looks like filename"))
                continue
            add(IOC("domain", domain))

    return result
