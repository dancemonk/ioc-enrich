"""Bundled reference lists: real TLDs, TLDs with RDAP, shared-CDN IP ranges.

The files live in ioc_enrich/data/ and are refreshed with `ioc-enrich update-lists`.
"""

import ipaddress
import json
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"

# Public suffixes made of two labels. For "a.bbc.co.uk" the registered
# domain is "bbc.co.uk", not "co.uk". Many country TLDs sell names one level
# down (co.il, net.cn, com.ru, ne.jp, gob.mx), so under any two-letter TLD
# these second labels count as part of the suffix. A built-in rule, not the
# full Public Suffix List (stdlib-only rule; see docs/usage.md limitations).
COUNTRY_SECOND_LEVELS = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "mil", "nic"}


def _read_lines(path: Path) -> list[str]:
    """Non-empty, non-comment lines of a text file."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def load_tlds(data_dir: Path = DATA_DIR) -> set[str]:
    """All real top-level domains (IANA list), lowercase."""
    return {line.lower() for line in _read_lines(data_dir / "tlds.txt")}


def load_rdap_tlds(data_dir: Path = DATA_DIR) -> set[str]:
    """TLDs that have an RDAP server listed in IANA's bootstrap file."""
    return {line.lower() for line in _read_lines(data_dir / "rdap_tlds.txt")}


def rdap_tlds_from_bootstrap(data: dict) -> set[str]:
    """Flatten IANA's dns.json: each service is [[tlds...], [server urls...]]."""
    return {tld.lower() for service in data["services"] for tld in service[0]}


def load_cdn_ranges(data_dir: Path = DATA_DIR) -> dict[str, list[ipaddress.IPv4Network]]:
    """{"Cloudflare": [networks], "Fastly": [...], "CloudFront": [...]}"""
    data = json.loads((data_dir / "cdn_ranges.json").read_text(encoding="utf-8"))
    return {
        provider: [ipaddress.IPv4Network(cidr) for cidr in cidrs]
        for provider, cidrs in data["providers"].items()
    }


def cdn_provider(ip: str, ranges: dict[str, list[ipaddress.IPv4Network]]) -> str | None:
    """Name of the shared CDN that owns this IP, or None."""
    address = ipaddress.IPv4Address(ip)
    for provider, networks in ranges.items():
        if any(address in network for network in networks):
            return provider
    return None


def registered_domain(host: str) -> str:
    """Best guess at the registered domain of a hostname.

    "www.taibeinan.cc" -> "taibeinan.cc"; "a.b.bbc.co.uk" -> "bbc.co.uk".
    """
    labels = host.lower().rstrip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in COUNTRY_SECOND_LEVELS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])
