"""One module per threat-intel source.

Every source has the same shape:
    lookup(ioc, key, http, today) -> SourceResult
"""

from ioc_enrich.sources import abuseipdb, bazaar, otx, rdap, threatfox, urlhaus, vt

LOOKUPS = {
    "VT": vt.lookup,
    "ThreatFox": threatfox.lookup,
    "URLhaus": urlhaus.lookup,
    "MalwareBazaar": bazaar.lookup,
    "OTX": otx.lookup,
    "AbuseIPDB": abuseipdb.lookup,
    "RDAP": rdap.lookup,
}

# Which field of config.Keys each source needs (None = no key).
KEY_FIELD = {
    "VT": "vt", "ThreatFox": "abusech", "URLhaus": "abusech", "MalwareBazaar": "abusech",
    "OTX": "otx", "AbuseIPDB": "abuseipdb", "RDAP": None,
}
