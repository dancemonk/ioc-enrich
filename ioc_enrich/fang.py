"""Refang (make usable) and defang (make safe to share) IOC text.

Analysts "defang" IOCs so nobody clicks them by accident:
    http://evil.com  ->  hxxp://evil[.]com
This module turns those forms back into real values (refang) and
produces the defanged style used in the CSV (defang).
"""

import re
from urllib.parse import urlsplit

from ioc_enrich.models import IOC

# Each pattern is matched case-insensitively and replaced with the real character.
_REFANG_RULES = [
    (re.compile(r"hxxp(s?)", re.IGNORECASE), lambda m: "http" + m.group(1).lower()),
    (re.compile(r"\[\.\]|\(\.\)|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[:\]"), ":"),
]


def refang(text: str) -> str:
    """Turn defanged text back into real IOC text."""
    for pattern, replacement in _REFANG_RULES:
        text = pattern.sub(replacement, text)
    return text


def _defang_host(host: str) -> str:
    return host.replace(".", "[.]")


def defang(ioc: IOC) -> str:
    """Return the IOC value in the CSV's defanged style.

    Domains and IPs: every dot becomes [.].
    URLs: scheme http -> hxxp, dots in the host -> [.], the port colon -> [:].
    The URL path is left as it is.
    Hashes are not clickable, so they stay unchanged.
    """
    if ioc.type in ("domain", "ip"):
        return _defang_host(ioc.value)
    if ioc.type == "url":
        parts = urlsplit(ioc.value)
        scheme = parts.scheme.replace("http", "hxxp")
        host = _defang_host(parts.hostname or "")
        port = f"[:]{parts.port}" if parts.port else ""
        rest = ioc.value.split(parts.netloc, 1)[1]   # path + query + fragment, untouched
        return f"{scheme}://{host}{port}{rest}"
    return ioc.value
