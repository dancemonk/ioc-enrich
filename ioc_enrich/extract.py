"""Find IOCs in free text (alert text, tshark output, a plain list).

How it works, token by token:
  1. Split the text on whitespace and common separators.
  2. Refang the token and remember whether it was defanged.
  3. Strip wrapping punctuation such as "(", ")", ".", ",".
  4. Try, in order: URL, hash, IPv4, IPv6, domain.
  5. If none fit, look inside: "label=value" or "md5:value", "host/path"
     without a scheme, "host:port", and the domain of an email address.
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

# "](" splits a Markdown link: [evil.com](http://evil.com/x)
_SPLIT = re.compile(r"[\s|\"'<>`]+|\]\(")
_LIST_SEP = re.compile(r"[,;]+")      # "1.2.3.4,5.6.7.8" - but not inside a URL's query string
_LEADING = "([{"
_TRAILING = ".,;:)]}!?"
_URL = re.compile(r"^https?://", re.IGNORECASE)
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}
_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
_LABELLED = re.compile(r"^[a-z][\w.-]{0,30}[=:](.+)$", re.IGNORECASE)   # src_ip=..., md5:...
_HOST_PORT = re.compile(r"^([^:/]+):\d{1,5}$")
_ARPA = "reverse DNS or local name (.arpa)"


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


def _is_arpa(host: str) -> bool:
    """in-addr.arpa and home.arpa names describe internal hosts: never send them out."""
    return host.lower().rstrip(".").endswith(".arpa")


def _tokens(text: str):
    """Split text into candidate tokens.

    "," and ";" separate list items, except inside a URL's query string,
    where "?x=1,2;sid=3" is part of the URL.
    """
    for piece in _SPLIT.split(text):
        head, sep, query = piece.partition("?")
        parts = _LIST_SEP.split(head)
        if sep and _URL.match(refang(parts[-1]).lstrip(_LEADING)):
            parts[-1] += sep + query
            yield from parts
        else:
            yield from _LIST_SEP.split(piece)


def _normalize_url(url: str) -> tuple[str, str]:
    """Lowercase scheme and host; return (url, host). user@ before the host stays."""
    parts = urlsplit(url)
    host = (parts.hostname or "").rstrip(".")
    userinfo = parts.netloc.rpartition("@")[0]
    netloc = (f"{userinfo}@" if userinfo else "") + host + (f":{parts.port}" if parts.port is not None else "")
    return urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment)), host


def extract(text: str, tlds: set[str]) -> ExtractResult:
    result = ExtractResult()
    seen: set[IOC] = set()

    def add(ioc: IOC) -> None:
        if ioc not in seen:
            seen.add(ioc)
            result.iocs.append(ioc)

    def take(token: str, was_defanged: bool) -> bool:
        """Add the IOC(s) in one token. False when the token holds none."""
        if _URL.match(token):
            try:
                url, host = _normalize_url(token)
            except ValueError:          # e.g. a broken port number
                return True
            ip = _as_ipv4(host)
            if ip:
                add(IOC("url", url))
                add(IOC("ip", ip))
            elif _is_arpa(host):
                result.ignored.append((token, _ARPA))
            elif _as_domain(host, tlds):
                add(IOC("url", url))
                add(IOC("domain", host))
            return True

        if _HEX.match(token) and len(token) in _HASH_TYPES:
            add(IOC(_HASH_TYPES[len(token)], token.lower()))
            return True

        ip = _as_ipv4(token)
        if ip:
            add(IOC("ip", ip))
            return True

        if ":" in token and _is_ipv6(token):
            result.ignored.append((token, "IPv6 not supported yet"))
            return True

        if _is_arpa(token) and _DOMAIN.match(token.lower().rstrip(".")):
            result.ignored.append((token, _ARPA))
            return True

        domain = _as_domain(token, tlds)
        if domain:
            tld = domain.rsplit(".", 1)[1]
            if tld in FILENAME_LIKE_TLDS and not (was_defanged or domain.startswith("www.")):
                result.ignored.append((token, "looks like filename"))
                return True
            add(IOC("domain", domain))
            return True
        return False

    def take_inner(token: str, was_defanged: bool) -> None:
        """The token itself is no IOC: look for one inside it."""
        host_port = _HOST_PORT.match(token)
        if host_port and take(host_port.group(1), was_defanged):
            return
        labelled = _LABELLED.match(token)
        if labelled and take(_strip_wrapping(labelled.group(1)), was_defanged):
            return
        if "/" in token:
            host, rest = token.split("/", 1)
            if host and not rest.isdigit():          # "1.2.3.0/24" is a network, not a host
                ip = _as_ipv4(host)
                if ip:
                    add(IOC("ip", ip))
                elif _as_domain(host, tlds) or _is_arpa(host):
                    take(host, was_defanged)
            return
        if token.count("@") == 1:
            take(token.split("@")[1], was_defanged)

    for raw in _tokens(text):
        if not raw:
            continue
        refanged = refang(raw)
        was_defanged = refanged != raw
        token = _strip_wrapping(refanged)
        if token and not take(token, was_defanged):
            take_inner(token, was_defanged)

    return result
