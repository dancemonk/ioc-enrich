"""Links for a human to check an IOC in the browser (no API, no scraping).

These are the sites' normal search pages. Use them for anything the tool
could not check, or to dig deeper.
"""

from urllib.parse import quote

from ioc_enrich.lists import registered_domain
from ioc_enrich.models import IOC

HASHES = ("md5", "sha1", "sha256")


def manual_links(ioc: IOC) -> list[tuple[str, str]]:
    v = ioc.value
    q = quote(v, safe="")
    links = []

    if ioc.type == "domain":
        links.append(("VirusTotal", f"https://www.virustotal.com/gui/domain/{v}"))
    elif ioc.type == "ip":
        links.append(("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{v}"))
    elif ioc.type == "url":
        links.append(("VirusTotal", f"https://www.virustotal.com/gui/search/{q}"))
    else:
        links.append(("VirusTotal", f"https://www.virustotal.com/gui/file/{v}"))

    links.append(("tria.ge", f"https://tria.ge/s?q={ioc.type}:{q}"))

    if ioc.type != "sha1":
        links.append(("ThreatFox", f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{q}"))
    if ioc.type in ("domain", "ip", "url"):
        links.append(("URLhaus", f"https://urlhaus.abuse.ch/browse.php?search={q}"))
    if ioc.type in HASHES:
        links.append(("MalwareBazaar", f"https://bazaar.abuse.ch/browse.php?search={ioc.type}%3A{v}"))

    if ioc.type == "domain":
        otx_type = "domain" if v == registered_domain(v) else "hostname"
    else:
        otx_type = {"ip": "ip", "url": "url"}.get(ioc.type, "file")
    links.append(("OTX", f"https://otx.alienvault.com/indicator/{otx_type}/{q if ioc.type == 'url' else v}"))

    if ioc.type == "ip":
        links.append(("AbuseIPDB", f"https://www.abuseipdb.com/check/{v}"))
    return links
