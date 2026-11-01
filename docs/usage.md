# ioc-enrich: full reference

Everything the [README](../README.md) leaves out.

## Commands

```bash
ioc-enrich alert.txt                     # from a file
pbpaste | ioc-enrich                     # from stdin
ioc-enrich alert.txt --dry-run           # what would be asked and the VT cost; sends nothing, needs no keys
ioc-enrich alert.txt --incident-date 2026-08-09   # domain age as "85 d before incident"
ioc-enrich alert.txt --no-vt             # skip VirusTotal (see OPSEC below)
ioc-enrich alert.txt --deep              # also fetch a few VT relationships; costs extra VT calls

ioc-enrich new-iocs.txt --merge iocs.csv -o iocs-enriched.csv
ioc-enrich --merge iocs.csv -o iocs-rechecked.csv   # no input: re-check the file's own rows

ioc-enrich serve                         # local web page, prints http://127.0.0.1:8765/?t=<token>
ioc-enrich keys                          # save your API keys
ioc-enrich update-lists                  # refresh the bundled TLD, RDAP and CDN lists
```

Other options: `-o PATH`, `--no-cache`, `--allowlist PATH` (one domain per line, subdomains included; `# comments` and `*.corp.com` are fine), `--keys PATH`, `--vt-per-minute N` and `--vt-daily-limit N` for a premium key.

A dry run looks like this:

```text
$ echo "www.taibeinan[.]cc 146.59.71[.]167 172.64.155[.]76 172.16.8[.]49" | ioc-enrich --dry-run
domain www[.]taibeinan[.]cc              would ask: ThreatFox, VT, URLhaus, OTX, RDAP
ip     146[.]59[.]71[.]167               would ask: ThreatFox, VT, URLhaus, OTX, AbuseIPDB, InternetDB
ip     172[.]64[.]155[.]76               would ask: ThreatFox, URLhaus, OTX, AbuseIPDB, InternetDB  [shared CDN (Cloudflare) - do not block; VT skipped]
ip     172[.]16[.]8[.]49                 skipped (private)

Cost: 3 IOCs → 2 VirusTotal lookups, about 30 s
```

## What happens to your input

Extraction finds domains, IPv4 addresses, URLs and MD5/SHA1/SHA256 hashes in free text, and refangs `hxxp`, `[.]`, `(.)`, `{.}`, `[dot]`, `\.`, `[:]` and `[://]`. A URL gives one `url` row plus one row for its host. It also looks inside `label=value` and `md5:value`, `host/path` written without a scheme, `host:port`, Markdown links and email addresses (the domain only). `.arpa` names (reverse DNS, `home.arpa`) describe internal hosts, so they are listed as ignored and never sent.

Before any lookup, duplicates go, private, reserved and multicast IPs are skipped, and allowlisted domains are left alone. IPs in a shared CDN range (Cloudflare, Fastly, CloudFront) are marked `shared CDN (…) - do not block` and never go to VirusTotal.

Each IOC is then asked only of the sources that support its type (table in the README). Every IOC also gets manual-check links (VirusTotal, tria.ge, ThreatFox, URLhaus, MalwareBazaar, OTX, AbuseIPDB, Shodan) so you can verify by hand, especially whatever the tool couldn't check.

## Keys

`ioc-enrich keys` asks for each key in turn. Paste it and press Enter. The key isn't shown, and Enter on its own skips it or keeps the one you already saved. Keys go to `~/.config/ioc-enrich/keys.env`, which only you can read and which lives outside the repo, so it can't be committed. A running web page picks up new keys on reload.

Environment variables (`VT_API_KEY`, `ABUSECH_AUTH_KEY`, `OTX_API_KEY`, `ABUSEIPDB_API_KEY`) win over the file. You can also write the file yourself (`export NAME=…`, quotes and `# comments` are fine):

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

A source without a key shows up as `not checked (no key)`.

## The web page

`ioc-enrich serve` listens on 127.0.0.1 only. Every request needs the random token printed at startup, and requests from other sites are refused by a Host/Origin check.

The plan updates as you type, with one chip per source showing what will be asked or is already cached. The Check button says what it will send ("Check 5 IOCs · up to 3 VirusTotal lookups") and turns amber while VirusTotal is on, with the On/Off switch right next to it. During a run it shows progress and a Stop button. A stopped or failed run keeps every answer it got, because answers are cached as they arrive.

Results show who flagged what. "Flagged only" filters them, "links" opens the manual-check links and "Download CSV" saves the file. Incident date and Ignore cache sit under Options. ⌘/Ctrl+Enter runs, and the Auto / Light / Dark switch sets the theme.

## CSV output

Columns match the analyst's `iocs.csv`:

```
type,value,first_seen_utc,frame,context,role,confidence,enrichment,checked_on
```

The tool fills `type` (`domain`, `ip`, `url`, `md5`, `sha1`, `sha256`), `value` (defanged), `enrichment` and `checked_on`, which is the date of the oldest answer used, so a cached answer keeps its own date. It fills `role` only on new rows for shared-CDN IPs. Your own columns are never changed, and an existing output file is never overwritten.

With `--merge`, rows of other types (such as `user_agent`) pass through untouched. If a run couldn't check every source (quota, missing key, `--no-vt`), the old enrichment cell stays and the screen says `kept old enrichment (incomplete run)`.

An `enrichment` cell lists sources in a fixed order and leaves out the ones that don't apply:

```
ThreatFox: not listed; VT 2/92 (malicious, malware); URLhaus: not listed; OTX: 0 pulses; created 2026-05-15 via RDAP (86 d before incident)
```

Anything not checked says why: `VT: skipped (shared CDN)`, `VT: off (--no-vt)`, `VT: not checked (quota)`, `ThreatFox: not checked (no key)`.

## Flagged by, never a verdict

The tool doesn't call anything malicious or clean. It reports which sources flagged an IOC, for example `flagged by: VT 2/92, ThreatFox`, `flagged by: none` or `not checked`. The rules:

| Source | Counts as flagged when |
|---|---|
| VirusTotal | at least 1 engine says malicious or suspicious (the number is malicious + suspicious) |
| ThreatFox, URLhaus, MalwareBazaar | the IOC is listed |
| OTX | at least 1 pulse |
| AbuseIPDB | at least 1 report |
| RDAP, Shodan InternetDB | never: they describe, they don't flag |

If only RDAP or InternetDB answered, the line says `not checked`, not `flagged by: none`.

The web page also labels evidence strength. A hit is strong when VirusTotal, ThreatFox, URLhaus or MalwareBazaar flagged it, and a weak signal when only OTX pulses or AbuseIPDB reports did, since both are common on shared infrastructure. "So far" means a strong source wasn't asked. Finished results sort strongest first.

## OPSEC: VirusTotal

VirusTotal adds every IOC queried through its API to its dataset. Attackers watch VirusTotal for their own infrastructure, so a lookup can tell them someone is looking. Use `--no-vt`, or the Off switch on the page, when that matters.

## VirusTotal quota

The free key allows 4 requests a minute and 500 a day. Calls are spaced 15 s apart (configurable) while the other sources run in parallel. Duplicates, private IPs, shared-CDN IPs and allowlisted domains never reach VT, and relationships are fetched only with `--deep`.

Answers are cached for 7 days in `~/.cache/ioc-enrich/cache.sqlite` and stored the moment they arrive, so after Ctrl-C you rerun the same command and it picks up where it stopped.

On HTTP 429 the tool waits (honouring `Retry-After`) and retries. It also counts its own VT calls per day. Once the daily quota is gone, or after three 429s in a row, it stops asking VT for the rest of the run and lists every IOC that ended up `not checked (quota)`. Other sources work the same way: three 429s in a row, or a `Retry-After` longer than two minutes, and that source shows `not checked (rate limited)` for the rest of the run.

## Limitations

- IPv4 only. IPv6 addresses show as `skipped (IPv6 not supported yet)`.
- Some TLDs have no RDAP server (`.ie .io .co .de .me .ru .cn`). For those the creation date comes from one extra VT call on the registered domain, counted in the cost line, or it's `age n/a`.
- The registered domain is a guess: the last two labels, or three under a country TLD whose second label is a common one like `co.uk`, `net.cn` or `com.ru`. It isn't the full Public Suffix List.
- TLDs that look like file extensions (`zip mov py sh md pl rs ps so cc`) only count when the token was defanged, sits in a URL or starts with `www.`. Otherwise it's `ignored (looks like filename)`, so a bare `example.pl` needs defanging.
- ThreatFox can't search SHA1.
- OTX counts at most 50 pulses per IOC, so a busy indicator shows `OTX: 50+ pulses`.
- Free tiers: AbuseIPDB allows 1,000 checks a day, abuse.ch and OTX are "fair use", and Shodan InternetDB publishes no limit (the tool asks at most once a second). InternetDB updates weekly, so its ports can be a week old.
- Manual-check links follow each site's public search URLs and break if a site changes them.

## Terms of use

The free VirusTotal, AbuseIPDB and abuse.ch keys, and Shodan InternetDB, are for personal, non-commercial use. At work, use your employer's licensed keys, and don't create extra accounts to get around limits.
