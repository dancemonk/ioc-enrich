"""API keys: from environment variables, then from a local keys file.

Keys are never printed: the Keys class hides them in repr().
"""

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

DEFAULT_KEYS_FILE = Path.home() / ".config" / "ioc-enrich" / "keys.env"

ENV_NAMES = {
    "vt": "VT_API_KEY",
    "abusech": "ABUSECH_AUTH_KEY",
    "otx": "OTX_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
}


# Names shown to the analyst for each key.
KEY_NAMES = {
    "vt": "VirusTotal",
    "abusech": "abuse.ch (ThreatFox, URLhaus, MalwareBazaar)",
    "otx": "OTX",
    "abuseipdb": "AbuseIPDB",
}


@dataclass
class Keys:
    vt: str | None = None
    abusech: str | None = None
    otx: str | None = None
    abuseipdb: str | None = None

    def __repr__(self) -> str:
        # Show only whether each key is present, never the value.
        state = ", ".join(f"{name}={'set' if getattr(self, name) else 'missing'}" for name in ENV_NAMES)
        return f"Keys({state})"

    __str__ = __repr__


def _read_keys_file(path: Path) -> dict[str, str]:
    """Parse NAME=value lines, the way people write .env files.

    '#' starts a comment (also after a value), quotes are stripped, an
    "export " prefix is allowed, and utf-8-sig drops a leading BOM.
    """
    values = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip().removeprefix("export ").strip()
        value = value.strip()
        if value[:1] in ("'", '"') and value[0] in value[1:]:
            value = value[1:value.index(value[0], 1)]       # quoted: '#' inside is part of the key
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0]
        values[name] = value
    return values


def load_keys(env: Mapping[str, str] = os.environ, path: Path = DEFAULT_KEYS_FILE) -> Keys:
    from_file = _read_keys_file(path)
    found = {}
    for field_name, env_name in ENV_NAMES.items():
        found[field_name] = env.get(env_name) or from_file.get(env_name) or None
    return Keys(**found)


def missing_keys(keys: Keys) -> list[dict[str, str]]:
    """Keys that are not set, e.g. [{"name": "VirusTotal", "env": "VT_API_KEY"}]. Never the values."""
    return [{"name": KEY_NAMES[field], "env": env_name}
            for field, env_name in ENV_NAMES.items() if not getattr(keys, field)]
