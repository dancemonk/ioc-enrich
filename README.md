# ioc-enrich

A small tool for the enrichment step of a SOC investigation. Paste IOCs from anywhere (alert text, tshark output, a list, defanged or not). It looks each one up in public threat-intel APIs and writes the results as rows in an `iocs.csv`-style file.

- **Command line and a local web page.** Both run on the same engine.
- **Python 3.11+, standard library only.** Nothing to install beyond Python itself.
- **Lookup only.** It never contacts an IOC and never submits anything for scanning.

```text
$ echo "www.taibeinan[.]cc 146.59.71[.]167 172.64.155[.]76 172.16.8[.]49" | ioc-enrich --dry-run
domain www[.]taibeinan[.]cc              would ask: ThreatFox, VT, URLhaus, OTX, RDAP
ip     146[.]59[.]71[.]167               would ask: ThreatFox, VT, URLhaus, OTX, AbuseIPDB, InternetDB
ip     172[.]64[.]155[.]76               would ask: ThreatFox, URLhaus, OTX, AbuseIPDB, InternetDB  [shared CDN (Cloudflare) - do not block; VT skipped]
ip     172[.]16[.]8[.]49                 skipped (private)

Cost: 3 IOCs → 2 VirusTotal lookups, about 30 s
```

## What it does

1. **Extracts** domains, IPv4 addresses, URLs and MD5/SHA1/SHA256 hashes from free text. Defanged forms (`hxxp`, `[.]`, `(.)`, `[:]`) are refanged. A URL gives one `url` row plus one row for its host.
2. **Filters before any lookup:**
   - Duplicates are removed.
   - Private and reserved IPs are skipped.
   - IPs in a shared CDN (Cloudflare, Fastly, CloudFront) are marked `shared CDN (…) - do not block` and are not sent to VT.
   - Domains in your allowlist are not checked.
3. **Looks each IOC up** only in the sources that support its type:

   | Source | domain | ip | url | md5 | sha1 | sha256 | Key |
   |---|---|---|---|---|---|---|---|
   | VirusTotal v3 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | free |
   | ThreatFox | ✓ | ✓ |  | ✓ |  | ✓ | abuse.ch |
   | URLhaus | ✓ | ✓ | ✓ | ✓ |  | ✓ | abuse.ch |
   | MalwareBazaar |  |  |  | ✓ | ✓ | ✓ | abuse.ch |
   | AlienVault OTX | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | free |
   | AbuseIPDB |  | ✓ |  |  |  |  | free |
   | RDAP (rdap.org) | creation date + registrar | | | | | | none |
   | Shodan InternetDB | | open ports, known vulns, tags | | | | | none |

   RDAP and Shodan InternetDB are **info-only**: they describe an IOC but never flag it.

4. **Writes:**
   - a CSV (see [Output](#output))
   - one summary line per IOC on screen
   - manual-check links for every IOC (VirusTotal, tria.ge, ThreatFox, URLhaus, MalwareBazaar, OTX, AbuseIPDB, Shodan), so you can verify anything by hand, especially what the tool could not check

## Safety rules

- **Lookup only.** The tool never resolves, fetches or connects to an IOC. It never submits URLs or files, never calls a rescan/reanalyse endpoint and never downloads samples.
- **Enforced in code.** `ioc_enrich/http.py` refuses every request that is not a known lookup endpoint, and it refuses submit/download endpoints by name, before any connection is opened. Tests check this, and they also check that no DNS lookup happens during a run.
- **No scraping.** Where there is no API, the tool gives you a link to open yourself.
- **Keys are never printed or logged.**
- ⚠️ **VirusTotal note:** VirusTotal says that any IOC queried through its API is added to its dataset. Attackers watch VirusTotal for their own infrastructure, so a lookup can tell them someone is looking. Use `--no-vt` (or switch VirusTotal to Off on the web page) when that matters.

## Setup

```bash
git clone <this repo> && cd ioc-enrich
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/ioc-enrich --help
```

### Free API keys

You need a free account for each service. The tool still works with only some keys, or none: sources without a key are reported as `not checked (no key)`. With no keys at all you still get extraction, filtering, `--dry-run`, domain age (RDAP), open ports and known vulns for IPs (Shodan InternetDB) and the manual-check links. One abuse.ch key adds ThreatFox, URLhaus and MalwareBazaar; adding VirusTotal covers the main sources.

| Variable | Where to get it |
|---|---|
| `VT_API_KEY` | Create a VirusTotal community account, then open your profile → API key |
| `ABUSECH_AUTH_KEY` | https://auth.abuse.ch/ (one Auth-Key covers ThreatFox, URLhaus and MalwareBazaar) |
| `OTX_API_KEY` | Create an account at https://otx.alienvault.com/, then go to Settings → API key |
| `ABUSEIPDB_API_KEY` | Create an account at https://www.abuseipdb.com/, then go to Account → API |

The easiest way to save them:

```bash
ioc-enrich keys
```

It asks for each key in turn (paste it and press Enter; the key is not shown, and Enter alone skips it). It saves them to `~/.config/ioc-enrich/keys.env`, a file only you can read, outside the repo so it can never be committed. Run it again to add or replace a key. A running web page picks up new keys when you reload it.

You can also set environment variables (they win over the file), or write the file yourself:

```bash
mkdir -p ~/.config/ioc-enrich
cat > ~/.config/ioc-enrich/keys.env <<'EOF'
VT_API_KEY=your-key-here
ABUSECH_AUTH_KEY=your-key-here
OTX_API_KEY=your-key-here
ABUSEIPDB_API_KEY=your-key-here
EOF
chmod 600 ~/.config/ioc-enrich/keys.env
```

### Terms of use

The free VirusTotal, AbuseIPDB and abuse.ch keys, and Shodan InternetDB, are for **personal, non-commercial use**. At work, use your employer's licensed keys. Don't create multiple accounts to get around limits.

## Usage

```bash
# From a file or from stdin
ioc-enrich alert.txt
pbpaste | ioc-enrich

# See what would be queried and what it costs in VT calls; sends nothing, needs no keys
ioc-enrich alert.txt --dry-run

# Domain age relative to the incident ("created 2026-05-16 via RDAP (85 d before incident)")
ioc-enrich alert.txt --incident-date 2026-08-09

# Merge into an existing iocs.csv (writes a NEW file; your columns are never changed)
ioc-enrich new-iocs.txt --merge iocs.csv -o iocs-enriched.csv
ioc-enrich --merge iocs.csv -o iocs-rechecked.csv     # no input: re-check the file's own rows

# Quiet run without VirusTotal
ioc-enrich alert.txt --no-vt

# A few VT relationships (resolutions, contacted domains/IPs); costs extra VT calls
ioc-enrich alert.txt --deep

# Local web page
ioc-enrich serve            # prints http://127.0.0.1:8765/?t=<token>

# Save your API keys (asks for each one)
ioc-enrich keys

# Refresh the bundled TLD / RDAP / CDN lists
ioc-enrich update-lists
```

Other options: `-o PATH`, `--no-cache`, `--allowlist PATH` (one domain per line; an entry also covers its subdomains), `--keys PATH`, `--vt-per-minute N`, `--vt-daily-limit N` (for a premium key).

### The web page

`ioc-enrich serve` starts a page that only this computer can reach (it listens on 127.0.0.1). Every request needs the random token printed at startup, and requests from other websites are refused (Host/Origin check). Paste IOCs and the plan updates as you type: one chip per source shows what will be asked (or is already cached). The Check button says exactly what it will send, e.g. "Check 5 IOCs · up to 3 VirusTotal lookups", and turns amber whenever VirusTotal is on; the VirusTotal On/Off switch sits right next to it. During a run the button shows progress ("VirusTotal lookup 2 of 3") and a Stop button appears; stopped or unreachable runs keep every answer so far (they are cached). Results show who flagged what per source; "Flagged only" filters them, "links" opens the manual-check links, and "Download CSV" saves the result. Editing the box after a run keeps the results and shows what the next run would do. ⌘/Ctrl+Enter runs. The Auto / Light / Dark switch at the top right sets the theme (Auto follows your system) and is remembered in that browser.

## Output

CSV columns (the same as the analyst's `iocs.csv`):

```
type,value,first_seen_utc,frame,context,role,confidence,enrichment,checked_on
```

- **Filled by the tool:**
  - `type`: one of `domain`, `ip`, `url`, `md5`, `sha1`, `sha256`
  - `value`: defanged
  - `enrichment`
  - `checked_on`: the date of the oldest answer used, so a cached answer keeps its own date
- `role` is filled only on new rows for shared-CDN IPs.
- **Your columns** (`first_seen_utc`, `frame`, `context`, `role`, `confidence`) are never changed.
- **With `--merge`:**
  - Rows of other types (e.g. `user_agent`) pass through untouched.
  - If a run could not check every source (quota, missing key, `--no-vt`), the existing enrichment cell is kept and the screen says `kept old enrichment (incomplete run)`.
- An existing output file is never overwritten.

`enrichment` example (fixed order, and sources that don't apply to the type are left out):

```
ThreatFox: not listed; VT 2/92 (malicious, malware); URLhaus: not listed; OTX: 0 pulses; created 2026-05-15 via RDAP (86 d before incident)
```

When something was not checked, it says so: `VT: skipped (shared CDN)`, `VT: off (--no-vt)`, `VT: not checked (quota)`, `ThreatFox: not checked (no key)`.

### No verdicts

The tool never says "malicious" or "clean". The decision is the analyst's. The screen shows **who flagged** an IOC: `flagged by: VT 2/92, ThreatFox`, or `flagged by: none`, or `not checked`. A source counts as having flagged an IOC when:

- **VirusTotal:** at least 1 engine says malicious or suspicious (the number shown is malicious + suspicious)
- **ThreatFox, URLhaus, MalwareBazaar:** the IOC is listed
- **OTX:** at least 1 pulse
- **AbuseIPDB:** at least 1 report
- **RDAP, Shodan InternetDB:** never (info-only). If only they answered, the line says `not checked`, not `flagged by: none`.

On the web page a hit is also marked by **strength of evidence**: *strong* when VirusTotal, ThreatFox, URLhaus or MalwareBazaar flagged it, *weak signal* when only OTX pulses and/or AbuseIPDB reports did (both are common on shared or popular infrastructure). Finished results sort strongest first. This describes the sources, not the IOC: the decision stays with the analyst.

## VirusTotal quota handling

The free key allows 4 requests/minute and 500/day.

- **Spacing:** calls are 15 s apart (configurable), and the other sources run in parallel without waiting for VT.
- **Fewer calls:** duplicates, private IPs, shared-CDN IPs and allowlisted domains never reach VT.
- **Cache:** results are cached for 7 days in `~/.cache/ioc-enrich/cache.sqlite`. Every answer is stored as soon as it arrives, so after Ctrl-C you just rerun the same command.
- **One lookup per IOC** by default. Relationships are fetched only with `--deep`.
- **On HTTP 429:** the tool waits (honouring `Retry-After`) and retries. It counts its own VT calls per day. When the daily quota is used up, or after 3 429s in a row, it stops asking VT for the rest of the run and lists every IOC that was `not checked (quota)`. Nothing is skipped silently.

## Limitations

- **IPv4 only.** IPv6 addresses are listed as `skipped (IPv6 not supported yet)`.
- **Some TLDs have no RDAP**, e.g. `.ie .io .co .de .me .ru .cn`. For those, the creation date comes from VirusTotal: one extra VT call on the registered domain, shown in the cost line. Otherwise it's `age n/a`.
- **Registered-domain guess:** last two labels, plus a small built-in list of two-part suffixes (`co.uk`, `com.au`, …). It is not the full Public Suffix List.
- **Filenames vs domains:** TLDs that look like file extensions (`zip mov py sh md pl rs ps so cc`) count only if the token was defanged, sits inside a URL, or starts with `www.`. Anything else is listed as `ignored (looks like filename)`. This means a bare Polish domain such as `example.pl` is ignored unless you defang it.
- **ThreatFox** does not search SHA1, and IP lookups may miss entries stored as `ip:port`.
- **Free tiers:** VT allows 4/min and 500/day; AbuseIPDB allows 1,000 checks/day; abuse.ch and OTX are "fair use". Shodan InternetDB publishes no limit (the tool asks at most once per second) and is updated weekly, so its ports can be up to a week old.
- **Manual-check link formats** follow each site's public search pages. If a site changes its URLs, a link may break.

## Development

```bash
.venv/bin/python -m unittest discover -s tests
```

Tests use recorded/fake API responses. They never touch the network and never need keys.

## License

MIT
