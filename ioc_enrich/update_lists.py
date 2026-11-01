"""`ioc-enrich update-lists`: refresh the bundled reference lists.

This talks only to IANA, Cloudflare, Fastly and AWS (who publish these
lists for exactly this use). It never contacts an IOC.
"""

import ipaddress
import json
import os
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


def _text_list(url: str, today: date, items: list[str]) -> str:
    return f"# fetched {today.isoformat()} from {url}\n" + "\n".join(sorted(items)) + "\n"


def _replace_all(files: dict[Path, str]) -> None:
    """Write every file to a temp name first, then swap them in.

    os.replace is atomic, so a crash leaves each list either old or new, never cut short.
    """
    temps = {}
    try:
        for path, text in files.items():
            temp = path.with_name(path.name + ".tmp")
            temp.write_text(text, encoding="utf-8")
            temps[path] = temp
        for path, temp in temps.items():
            os.replace(temp, path)
    finally:
        for temp in temps.values():
            if temp.exists():
                temp.unlink()


_TLD_PATTERN = re.compile(r"^[a-z0-9-]+$")


def _fetch(http, url: str):
    """GET a list URL; anything but HTTP 200 is an error."""
    response = http.get(url)
    if response.status != 200:
        raise ValueError(f"{url}: HTTP {response.status}")
    return response


def update_lists(http, data_dir: Path, today: date, min_tlds: int = 1000,
                 min_rdap_tlds: int = 500) -> list[str]:
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
    if len(rdap_tlds) < min_rdap_tlds:
        raise ValueError(f"{RDAP_URL}: only {len(rdap_tlds)} TLDs found")

    cloudflare = _ipv4_only(_fetch(http, CLOUDFLARE_URL).body.decode("utf-8").split())
    fastly = _ipv4_only(_fetch(http, FASTLY_URL).json().get("addresses", []))
    aws = _fetch(http, CLOUDFRONT_URL).json().get("prefixes", [])
    cloudfront = _ipv4_only([p["ip_prefix"] for p in aws if p.get("service") == "CLOUDFRONT"])
    # An empty list would quietly send that CDN's IPs to VirusTotal.
    for url, ranges in ((CLOUDFLARE_URL, cloudflare), (FASTLY_URL, fastly), (CLOUDFRONT_URL, cloudfront)):
        if not ranges:
            raise ValueError(f"{url}: no IPv4 ranges found")

    # All downloads are good: write the files.
    data_dir.mkdir(parents=True, exist_ok=True)
    cdn = {
        "fetched": today.isoformat(),
        "sources": {"Cloudflare": CLOUDFLARE_URL, "Fastly": FASTLY_URL, "CloudFront": CLOUDFRONT_URL},
        "providers": {"Cloudflare": cloudflare, "Fastly": fastly, "CloudFront": cloudfront},
    }
    _replace_all({
        data_dir / "tlds.txt": _text_list(TLD_URL, today, tlds),
        data_dir / "rdap_tlds.txt": _text_list(RDAP_URL, today, list(rdap_tlds)),
        data_dir / "cdn_ranges.json": json.dumps(cdn, indent=1) + "\n",
    })

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
