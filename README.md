# ioc-enrich

Lookup-only IOC enrichment for SOC triage. Paste the indicators from an alert and see what public threat-intel sources report for each one, then export the results as CSV.

![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776ab)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-2ea44f)
![License: MIT](https://img.shields.io/badge/license-MIT-lightgrey)

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshot-dark.png">
  <img alt="ioc-enrich web page: four IOCs from an alert, each with per-source results" src="docs/screenshot-light.png">
</picture>

It runs from the command line or as a local web page, on Python 3.11+ with no third-party packages. It only queries threat-intel APIs: it never resolves, connects to or fetches an IOC, and never submits anything for scanning.

## Quick start

```bash
uv tool install git+https://github.com/dancemonk/ioc-enrich

ioc-enrich keys     # paste your free API keys; Enter skips one
ioc-enrich serve    # open the printed http://127.0.0.1:8765/?t=... link
```

No [uv](https://docs.astral.sh/uv/)? Use a venv instead:

```bash
git clone https://github.com/dancemonk/ioc-enrich.git && cd ioc-enrich
python3 -m venv .venv && .venv/bin/pip install -e .
source .venv/bin/activate
```

From the command line:

```bash
ioc-enrich alert.txt --dry-run   # show what would be queried; sends nothing
ioc-enrich alert.txt             # run the lookups, write ioc-enrich-<date>.csv
pbpaste | ioc-enrich             # or read from stdin
```

## What it does

- Extracts domains, IPv4 addresses, URLs and MD5/SHA1/SHA256 hashes from free text, defanged or not. IPv6 is not supported yet.
- Drops duplicates, private IPs and allowlisted domains before any query. Shared CDN IPs are marked "do not block" and are not sent to VirusTotal.
- Queries each source only for the IOC types it supports, and caches answers for 7 days.
- Reports which sources flagged each IOC. It never assigns a verdict.
- Writes CSV, or merges into an existing IOC list without changing analyst-maintained columns.

## Sources

| Source | domain | ip | url | hash | Key |
|---|:-:|:-:|:-:|:-:|---|
| VirusTotal | ✓ | ✓ | ✓ | ✓ | free |
| ThreatFox | ✓ | ✓ | | md5, sha256 | free (abuse.ch) |
| URLhaus | ✓ | ✓ | ✓ | md5, sha256 | free (abuse.ch) |
| MalwareBazaar | | | | ✓ | free (abuse.ch) |
| AlienVault OTX | ✓ | ✓ | ✓ | ✓ | free |
| AbuseIPDB | | ✓ | | | free |
| RDAP | age | | | | none |
| Shodan InternetDB | | ports, vulns | | | none |

RDAP and InternetDB add context but never flag anything.

## Keys

All keys are free and optional. Without any, you still get extraction, `--dry-run`, domain age, open ports for IPs and manual-check links for every IOC. One abuse.ch key covers three sources.

| Key | Where |
|---|---|
| `VT_API_KEY` | [virustotal.com](https://www.virustotal.com/) → your profile → API key |
| `ABUSECH_AUTH_KEY` | [auth.abuse.ch](https://auth.abuse.ch/) |
| `OTX_API_KEY` | [otx.alienvault.com](https://otx.alienvault.com/) → Settings → API key |
| `ABUSEIPDB_API_KEY` | [abuseipdb.com](https://www.abuseipdb.com/) → Account → API |

Free keys are for personal, non-commercial use. At work, use your employer's licensed keys.

## Safety and OPSEC

The lookup-only rule is enforced in code. `ioc_enrich/http.py` refuses any request that isn't a known lookup endpoint before a connection opens, and the tests check that, including that no DNS lookup happens during a run. Keys are never printed or logged.

IOC values are sent to the sources in the table above and nowhere else. VirusTotal adds every queried IOC to its dataset, and threat actors monitor it for their own infrastructure. Use `--no-vt` (or the Off switch on the page) when a lookup could alert them.

## More

[docs/usage.md](docs/usage.md) has every command and option, the CSV format, the flagging rules, how VirusTotal quota is handled and the known limitations.

From a clone, run the tests with `python3 -m unittest discover -s tests`. They use recorded API responses and never touch the network.

## License

MIT © Vladislav Guliakin
