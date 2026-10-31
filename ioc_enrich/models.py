"""Small data classes shared by every part of the tool."""

from dataclasses import dataclass, field
from datetime import date


@dataclass(frozen=True)
class IOC:
    """One indicator of compromise.

    type:  "domain" | "ip" | "url" | "md5" | "sha1" | "sha256"
    value: refanged and normalized (domains and hashes lowercase,
           URLs with lowercase scheme and host)
    """

    type: str
    value: str


@dataclass
class SourceResult:
    """What one threat-intel source said about one IOC.

    status:
      "ok"          the source knows this IOC (details in `fields`)
      "not_listed"  the source answered, but has nothing on it
      "skipped"     deliberately not asked (reason, e.g. "shared CDN")
      "not_checked" could not ask (reason: "quota", "no key", "--no-vt",
                    "interrupted", "error: ...")
    """

    source: str
    status: str
    fetched_on: date
    reason: str = ""
    fields: dict = field(default_factory=dict)
    cached: bool = False
    flagged: bool = False
