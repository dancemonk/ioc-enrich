"""`ioc-enrich update-lists`: refresh the bundled reference lists.

This talks only to IANA, Cloudflare, Fastly and AWS (who publish these
lists for exactly this use). It never contacts an IOC.
"""

import ipaddress
import json
import re
from datetime import date, datetime, timezone
from pathlib import Path

from ioc_enrich.lists import DATA_DIR, rdap_tlds_from_bootstrap

TLD_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
RDAP_URL = "https://data.iana.org/rdap/dns.json"
CLOUDFLARE_URL = "https://www.cloudflare.com/ips-v4/"
FASTLY_URL = "https://api.fastly.com/public-ip-list"
CLOUDFRONT_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"


def _ipv4_only(cidrs: list[str]) -> list[str]:
    """Keep valid IPv4 networks (v1 is IPv4-only)."""
    kept = []
    for cidr in cidrs:
        try:
            kept.append(str(ipaddress.IPv4Network(cidr.strip())))
        except ValueError:
            continue
    return kept


def _write_text_list(path: Path, url: str, today: date, items: list[str]) -> None:
    header = f"# fetched {today.isoformat()} from {url}\n"
    path.write_text(header + "\n".join(sorted(items)) + "\n", encoding="utf-8")


_TLD_PATTERN = re.compile(r"^[a-z0-9-]+$")


def _fetch(http, url: str):
    """GET a list URL; anything but HTTP 200 is an error."""
    response = http.get(url)
    if response.status != 200:
        raise ValueError(f"{url}: HTTP {response.status}")
    return response


def update_lists(http, data_dir: Path, today: date, min_tlds: int = 1000) -> list[str]:
    """Download the lists, check they look sane, then write them into data_dir.

    Nothing is written unless every download succeeded and passed the checks,
    so a failed update never leaves broken or half-updated lists behind.
    """
    tld_text = _fetch(http, TLD_URL).body.decode("utf-8")
    tlds = [line.strip().lower() for line in tld_text.splitlines()
            if line.strip() and not line.startswith("#")]
    if len(tlds) < min_tlds or not all(_TLD_PATTERN.match(tld) for tld in tlds):
        raise ValueError(f"{TLD_URL}: unexpected content ({len(tlds)} lines)")

    rdap_tlds = rdap_tlds_from_bootstrap(_fetch(http, RDAP_URL).json())
    if not rdap_tlds:
        raise ValueError(f"{RDAP_URL}: no TLDs found")

    cloudflare = _ipv4_only(_fetch(http, CLOUDFLARE_URL).body.decode("utf-8").split())
    fastly = _ipv4_only(_fetch(http, FASTLY_URL).json().get("addresses", []))
    aws = _fetch(http, CLOUDFRONT_URL).json().get("prefixes", [])
    cloudfront = _ipv4_only([p["ip_prefix"] for p in aws if p.get("service") == "CLOUDFRONT"])
    if not cloudflare:
        raise ValueError(f"{CLOUDFLARE_URL}: no IPv4 ranges found")

    # All downloads are good: write the files.
    data_dir.mkdir(parents=True, exist_ok=True)
    _write_text_list(data_dir / "tlds.txt", TLD_URL, today, tlds)
    _write_text_list(data_dir / "rdap_tlds.txt", RDAP_URL, today, list(rdap_tlds))
    cdn = {
        "fetched": today.isoformat(),
        "sources": {"Cloudflare": CLOUDFLARE_URL, "Fastly": FASTLY_URL, "CloudFront": CLOUDFRONT_URL},
        "providers": {"Cloudflare": cloudflare, "Fastly": fastly, "CloudFront": cloudfront},
    }
    (data_dir / "cdn_ranges.json").write_text(json.dumps(cdn, indent=1) + "\n", encoding="utf-8")

    return [
        f"tlds.txt: {len(tlds)} TLDs",
        f"rdap_tlds.txt: {len(rdap_tlds)} TLDs with RDAP",
        f"cdn_ranges.json: Cloudflare {len(cloudflare)}, Fastly {len(fastly)}, CloudFront {len(cloudfront)} ranges",
    ]


def main() -> int:
    from ioc_enrich.http import HttpClient

    today = datetime.now(timezone.utc).date()
    for line in update_lists(HttpClient(), DATA_DIR, today):
        print(line)
    return 0
