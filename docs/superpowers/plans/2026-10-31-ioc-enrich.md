# ioc-enrich Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A stdlib-only Python CLI + localhost web page that extracts IOCs from pasted text, looks them up (lookup only) in VT, ThreatFox, URLhaus, MalwareBazaar, OTX, AbuseIPDB and RDAP, and writes rows in the analyst's `iocs.csv` format.

**Architecture:** Pure functions for text → IOCs → plan (fang, extract, filters, lists), a thin guarded HTTP client, one module per source that turns a response into a `SourceResult`, an engine that schedules lookups (VT on one rate-limited worker, others in a thread pool) through a SQLite cache, and two front ends (argparse CLI, `http.server` page) over the same engine and formatter.

**Tech Stack:** Python ≥3.11 standard library only (`urllib`, `json`, `sqlite3`, `csv`, `ipaddress`, `argparse`, `concurrent.futures`, `http.server`, `unittest`). Plain HTML/JS for the page.

**Spec:** `docs/design.md` (read it first; this plan argues from it).

## Global Constraints

- Standard library only. No third-party package, ever, without Vlad's explicit OK. `pyproject.toml` has `dependencies = []`.
- `requires-python = ">=3.11"`. Tests: `unittest` only. Run: `.venv/bin/python -m unittest discover -s tests 2>&1 | tail -5`.
- LOOKUP ONLY: never resolve, fetch or connect to an IOC; never submit, rescan, or download; every outbound request passes `http.check_allowed()`.
- Tests never hit the network and never need keys (all HTTP through `FakeHttp`).
- Never print or log API keys. Key env vars: `VT_API_KEY`, `ABUSECH_AUTH_KEY`, `OTX_API_KEY`, `ABUSEIPDB_API_KEY`; file `~/.config/ioc-enrich/keys.env`.
- Paths: cache `~/.cache/ioc-enrich/cache.sqlite`, allowlist `~/.config/ioc-enrich/allowlist.txt`. Tests use temp dirs.
- CSV columns exactly: `type,value,first_seen_utc,frame,context,role,confidence,enrichment,checked_on`. Types: `domain, ip, url, md5, sha1, sha256`.
- Defang style: `.` → `[.]` (host part), `http` → `hxxp`, port `:` → `[:]`.
- Enrichment part order: ThreatFox; VT; URLhaus; MalwareBazaar; OTX; AbuseIPDB; created/age.
- Code readable for a Tier 1 trainee: short functions, docstrings, comments where non-obvious, no clever tricks.
- Memory: nothing may exceed 2 GB RSS; ask before installing anything; never delete files.
- **Git: commit only when Vlad asks.** Each task ends with a checkpoint (`git status --short`), not a commit. When asked: author `Vlad G. <114040348+dancemonk@users.noreply.github.com>`, short message, no Co-Authored-By, no AI credit anywhere.

## Review Focus

1. Pasted text with wrapping punctuation (`(hxxp://a[.]b/c).`, `www.x[.]com,`, Markdown backticks) → IOC extracted clean, punctuation stripped. *Test in Task 3.*
2. Mixed case / trailing dot (`WWW.Example.COM.` and `www.example.com`) → one IOC, lowercase, deduped. *Test in Task 3.*
3. IP with port (`146.59.71[.]167:443`) and URLs with an IP host → `ip` IOC without port. *Test in Task 3.*
4. Source failure (timeout, HTTP 500, non-JSON body) → that source `not checked (error: …)`, run continues, other sources fine. *Test in Task 9.*
5. Ctrl-C mid-run → results so far written to CSV, unanswered ones `not checked (interrupted)`, message says rerun resumes from cache. *Test in Task 12.*

---

### Task 1: Scaffold + shared models + refang/defang

**Files:**
- Create: `pyproject.toml`, `.gitignore`, `LICENSE` (MIT, "Vlad G.", 2026), `ioc_enrich/__init__.py` (`__version__ = "0.1.0"`), `ioc_enrich/__main__.py`, `ioc_enrich/models.py`, `ioc_enrich/fang.py`
- Test: `tests/test_fang.py`, `tests/__init__.py`

**Interfaces:**
- Produces (`models.py`):
  ```python
  @dataclass(frozen=True)
  class IOC:
      type: str    # "domain" | "ip" | "url" | "md5" | "sha1" | "sha256"
      value: str   # refanged + normalized (domain/hash lowercase; url: lowercase scheme+host)
  @dataclass
  class SourceResult:
      source: str          # "ThreatFox","VT","URLhaus","MalwareBazaar","OTX","AbuseIPDB","RDAP","VT-age","VT-related"
      status: str          # "ok" | "not_listed" | "skipped" | "not_checked"
      fetched_on: date
      reason: str = ""     # skipped: "shared CDN"; not_checked: "quota","no key","--no-vt","interrupted","error: ..."
      fields: dict = field(default_factory=dict)
      cached: bool = False
      flagged: bool = False
  ```
- Produces (`fang.py`): `refang(text: str) -> str`, `defang(ioc: IOC) -> str`

- [ ] **Step 1:** `git init`; write `.gitignore` with `.env`, `*.env`, `.venv/`, `__pycache__/`, `*.sqlite`, `ioc-enrich-*.csv`, `out/`, `.DS_Store`. `pyproject.toml`: name `ioc-enrich`, `dependencies = []`, `[project.scripts] ioc-enrich = "ioc_enrich.cli:main"`, package data `ioc_enrich/data/*`, `ioc_enrich/web/*`. `__main__.py` calls `cli.main()` (cli lands in Task 12; stub `main()` printing version until then).
- [ ] **Step 2: Write failing tests** (`tests/test_fang.py`):
  ```python
  def test_refang_variants(self):
      self.assertEqual(refang("hxxp://www.taibeinan[.]cc/lqjm/"), "http://www.taibeinan.cc/lqjm/")
      self.assertEqual(refang("HXXPS://a(.)b[.]c"), "https://a.b.c")
      self.assertEqual(refang("1.2.3[.]4[:]8080"), "1.2.3.4:8080")
      self.assertEqual(refang("x[dot]com"), "x.com")
  def test_defang_domain_ip(self):
      self.assertEqual(defang(IOC("domain", "www.independent.ie")), "www[.]independent[.]ie")
      self.assertEqual(defang(IOC("ip", "146.59.71.167")), "146[.]59[.]71[.]167")
  def test_defang_url_host_and_port_only(self):
      self.assertEqual(defang(IOC("url", "http://1.2.3.4:8080/a.php")), "hxxp://1[.]2[.]3[.]4[:]8080/a.php")
      self.assertEqual(defang(IOC("url", "https://www.independent.ie/ujvq/")), "hxxps://www[.]independent[.]ie/ujvq/")
  def test_defang_hash_unchanged(self): ...
  def test_roundtrip(self):  # refang(defang(x)) == x.value for domain, ip, url samples
  ```
- [ ] **Step 3:** Run `python3 -m venv .venv && .venv/bin/pip install -e . -q` then the test command → FAIL (import error).
- [ ] **Step 4:** Implement. `refang` is case-insensitive for `hxxp`; handles `[.]`, `(.)`, `[dot]`, `[:]`.
- [ ] **Step 5:** Tests PASS. Checkpoint: `git status --short`.

---

### Task 2: Bundled lists + registered domain + `update-lists`

**Files:**
- Create: `ioc_enrich/lists.py`, `ioc_enrich/update_lists.py`, `ioc_enrich/data/tlds.txt`, `ioc_enrich/data/rdap_tlds.txt`, `ioc_enrich/data/cdn_ranges.json`
- Test: `tests/test_lists.py`

**Interfaces:**
- Consumes: any object with `get(url: str, headers: dict | None = None) -> Response` (the real `HttpClient` arrives in Task 4). Define a minimal `Response` + `FakeHttp` in `tests/fakes.py` here; Task 4 moves `Response` into `ioc_enrich/http.py` and extends `FakeHttp`.
- Produces:
  ```python
  def load_tlds() -> set[str]                       # lowercase, no comments
  def load_rdap_tlds() -> set[str]                  # TLDs with an RDAP server in IANA dns.json
  def load_cdn_ranges() -> dict[str, list[ipaddress.IPv4Network]]   # {"Cloudflare": [...], "Fastly": [...], "CloudFront": [...]}
  def cdn_provider(ip: str, ranges) -> str | None
  def registered_domain(host: str) -> str           # last 2 labels, or 3 if last 2 in TWO_PART_SUFFIXES
  TWO_PART_SUFFIXES = {"co.uk","org.uk","ac.uk","gov.uk","com.au","net.au","org.au","co.nz","co.jp","co.za","co.in","com.br","com.cn","com.mx","com.tr","com.sg","com.hk"}
  def update_lists(http, data_dir: Path, today: date) -> list[str]   # returns one summary line per file written
  ```
- Data file format: text files start with `# fetched YYYY-MM-DD from <url>`; `cdn_ranges.json` = `{"fetched": "YYYY-MM-DD", "sources": {...urls}, "providers": {"Cloudflare": ["173.245.48.0/20", ...], ...}}` (IPv4 only).
- Source URLs: IANA TLDs `https://data.iana.org/TLD/tlds-alpha-by-domain.txt`; RDAP `https://data.iana.org/rdap/dns.json` (flatten each service's TLD list); Cloudflare `https://www.cloudflare.com/ips-v4/`; Fastly `https://api.fastly.com/public-ip-list` (`addresses`); CloudFront `https://ip-ranges.amazonaws.com/ip-ranges.json` (`prefixes[]` where `service == "CLOUDFRONT"`, field `ip_prefix`).

- [ ] **Step 1: Failing tests:** `registered_domain("www.taibeinan.cc") == "taibeinan.cc"`, `("a.b.bbc.co.uk") == "bbc.co.uk"`, `("independent.ie") == "independent.ie"`; `cdn_provider("172.64.155.76", ranges) == "Cloudflare"`, `cdn_provider("146.59.71.167", ranges) is None`; `update_lists` with `FakeHttp` canned bodies writes the three files with the `# fetched` header and filters CloudFront by service; parsing a small fixture `tests/fixtures/rdap_dns.json` (services for `info`, `cc`) gives `{"info","cc"}`. Tests never depend on the live-fetched data files.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement (real data files are generated at the end of Task 4, once `HttpClient` exists).
- [ ] **Step 4:** Tests PASS.
- [ ] **Step 5:** Checkpoint.

---

### Task 3: Extraction + classification

**Files:**
- Create: `ioc_enrich/extract.py`
- Test: `tests/test_extract.py`

**Interfaces:**
- Consumes: `refang`, `IOC`, `load_tlds`.
- Produces:
  ```python
  FILENAME_LIKE_TLDS = {"zip","mov","py","sh","md","pl","rs","ps","so","cc"}
  @dataclass
  class ExtractResult:
      iocs: list[IOC]                      # deduped, first-seen order
      ignored: list[tuple[str, str]]       # (raw token, reason): "IPv6 not supported yet" | "looks like filename"
  def extract(text: str, tlds: set[str]) -> ExtractResult
  ```
- Approach: split the ORIGINAL text on whitespace and `,;|"'<>` and backticks; per token: `was_defanged = refang(token) != token`; strip leading `(`/`[` and trailing `.,;:)]!?` from the refanged token; then try in order: URL (`^(https?)://`) → emits `url` IOC plus its host as `domain` or `ip`; hash by length (32/40/64 hex, whole token); IPv4 (`ipaddress`, strip `:port`); IPv6 (→ ignored); domain (regex on lowercase, trailing dot removed, last label in `tlds`; filename-like TLD needs `was_defanged` or `www.` prefix or came from a URL).

- [ ] **Step 1: Failing tests:**
  ```python
  TLDS = {"com","info","cc","ie","zip","py","uk"}   # small fixed set; tests never read the live data file
  SAMPLE = "www.grinswakebthu[.]info, www.taibeinan[.]cc, www.independent[.]ie, 146.59.71[.]167, 172.64.155[.]76, 172.16.8[.]49"
  def test_sample(self):
      r = extract(SAMPLE, TLDS)
      self.assertEqual([(i.type, i.value) for i in r.iocs], [
          ("domain","www.grinswakebthu.info"),("domain","www.taibeinan.cc"),("domain","www.independent.ie"),
          ("ip","146.59.71.167"),("ip","172.64.155.76"),("ip","172.16.8.49")])
  def test_url_yields_url_and_host(self):  # "hxxp://www.independent[.]ie/ujvq/" -> url + domain
  def test_hashes(self):  # md5/sha1/sha256 classified by length; 63-hex token ignored; uppercase lowered
  def test_punctuation_wrapping(self):  # Review Focus 1: "(hxxp://a[.]com/c)." and "`www.x[.]com`," -> clean values
  def test_case_and_trailing_dot_dedupe(self):  # Review Focus 2: "WWW.Example.COM. www.example.com" -> one domain
  def test_ip_with_port_and_ip_url(self):  # Review Focus 3: "146.59.71[.]167:443", "hxxp://1.2.3[.]4:8080/x" -> ip w/o port
  def test_filenames_ignored(self):  # "report.pdf frame.time" -> nothing; "loader.py" -> ignored "looks like filename"; "evil[.]zip" -> domain
  def test_ipv6_ignored(self):  # "2001:db8::1" -> ignored "IPv6 not supported yet"
  def test_tshark_line(self):  # "11032 2026-08-09 02:13:23 172.16.8.49 172.64.155.76 HTTP POST /ujvq/ HTTP/1.1 www.independent.ie" -> 2 ips + 1 domain, no "HTTP/1.1"
  ```
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** PASS. **Step 5:** Checkpoint.

---

### Task 4: Filters + per-type source plan + keys + guarded HTTP

**Files:**
- Create: `ioc_enrich/filters.py`, `ioc_enrich/config.py`, `ioc_enrich/http.py`
- Modify: `tests/fakes.py`
- Test: `tests/test_filters.py`, `tests/test_config.py`, `tests/test_http.py`

**Interfaces:**
- Produces (`filters.py`):
  ```python
  SOURCES_BY_TYPE = {
      "domain": ["ThreatFox","VT","URLhaus","OTX","RDAP"],
      "ip":     ["ThreatFox","VT","URLhaus","OTX","AbuseIPDB"],
      "url":    ["VT","URLhaus","OTX"],
      "md5":    ["ThreatFox","VT","URLhaus","MalwareBazaar","OTX"],
      "sha1":   ["VT","MalwareBazaar","OTX"],
      "sha256": ["ThreatFox","VT","URLhaus","MalwareBazaar","OTX"],
  }
  @dataclass
  class Planned:
      ioc: IOC
      sources: list[str]          # from SOURCES_BY_TYPE
      skip: str | None = None     # "private" | "allowlisted"
      cdn: str | None = None      # provider name; VT is then answered "skipped (shared CDN)" without a call
  def load_allowlist(path: Path) -> set[str]      # missing file -> empty set; '#' comments
  def plan(iocs: list[IOC], allowlist: set[str], cdn_ranges) -> list[Planned]
  ```
  Private = `not ipaddress.ip_address(v).is_global`. Allowlist entry covers itself and subdomains; also matches URL hosts.
- Produces (`config.py`): `@dataclass Keys(vt, abusech, otx, abuseipdb: str | None)` with `__repr__` returning `Keys(vt=set, abusech=missing, ...)` (never the value); `load_keys(env: Mapping[str,str], path: Path) -> Keys` (env wins over file; file lines `NAME=value`, `#` comments, quotes stripped).
- Produces (`http.py`):
  ```python
  @dataclass
  class Response:
      status: int; headers: dict[str, str]; body: bytes
      def json(self) -> Any
  class RateLimited(Exception):  retry_after: float | None
  class BlockedEndpoint(Exception): ...
  def check_allowed(method: str, url: str, body: dict | None = None) -> None
  class HttpClient:
      def __init__(self, timeout: float = 20.0)
      def get(self, url: str, headers: dict | None = None) -> Response
      def post_json(self, url: str, payload: dict, headers: dict | None = None) -> Response
      def post_form(self, url: str, form: dict, headers: dict | None = None) -> Response
  ```
  Every method calls `check_allowed` first. 429 → `RateLimited(Retry-After as float or None)`. 404 returns a `Response` (not an exception). Other ≥400 → `Response` too; sources decide. `User-Agent: ioc-enrich/0.1`.
  Allowlist (method, URL prefix): GET `https://www.virustotal.com/api/v3/{domains,ip_addresses,urls,files}/`; GET `https://otx.alienvault.com/api/v1/indicators/`; GET `https://api.abuseipdb.com/api/v2/check?`; GET `https://rdap.org/domain/`; POST `https://threatfox-api.abuse.ch/api/v1/` with `query` in {`search_ioc`,`search_hash`}; POST `https://urlhaus-api.abuse.ch/v1/{url,host,payload}/`; POST `https://mb-api.abuse.ch/api/v1/` with `query == "get_info"`; GET the five list URLs from Task 2. Additionally reject any URL containing `/analyse`, `/download`, `/upload_url`, `/comments`, `/votes`, `submit`. VT GET path must have no further segment except `resolutions`, `contacted_domains`, `contacted_ips`.
- `tests/fakes.py`: `FakeHttp(routes: dict[tuple[str,str], Response | Exception])` matching (method, url-prefix), records `calls`, and calls `check_allowed` like the real client.

- [ ] **Step 1: Failing tests:**
  - `plan` on the Task 3 sample: `172.16.8.49` → `skip == "private"`; `172.64.155.76` → `cdn == "Cloudflare"`; domains get the domain source list.
  - allowlist `independent.ie` → `www.independent.ie` `skip == "allowlisted"`; `notindependent.ie` not skipped.
  - `load_keys({"VT_API_KEY":"TESTKEY123"}, file_with_otx)` → both set; `"TESTKEY123" not in repr(keys)`.
  - `check_allowed` raises for: `POST https://www.virustotal.com/api/v3/urls`, `POST .../files`, `GET .../files/{h}/download`, `POST .../domains/x/analyse`, `POST mb-api {"query":"get_file"}`, `POST threatfox {"query":"submit_ioc"}`, `GET https://urlhaus-api.abuse.ch/v1/download/abc`, `GET http://www.grinswakebthu.info/` (an IOC). Passes for each allowed lookup.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5:** Generate the bundled data files once, live: `.venv/bin/python -c "from ioc_enrich.update_lists import main; main()"` (contacts IANA/Cloudflare/Fastly/AWS only, never an IOC). Check: `grep -c . ioc_enrich/data/tlds.txt` > 1000; `grep -x ie ioc_enrich/data/rdap_tlds.txt` prints nothing; `grep -x cc ioc_enrich/data/rdap_tlds.txt` prints `cc`. Checkpoint.

---

### Task 5: Rate limiter + SQLite cache

**Files:**
- Create: `ioc_enrich/ratelimit.py`, `ioc_enrich/cache.py`
- Test: `tests/test_ratelimit.py`, `tests/test_cache.py`

**Interfaces:**
- Produces:
  ```python
  class RateLimiter:
      def __init__(self, per_minute: int, clock=time.monotonic, sleep=time.sleep)
      def wait(self) -> None      # thread-safe; spaces calls 60/per_minute s apart
  class Cache:
      def __init__(self, path: Path, ttl_days: int = 7, now=time.time)   # creates parent dir; one connection, check_same_thread=False, guarded by a Lock
      def get(self, source: str, ioc: IOC) -> SourceResult | None       # None if missing or older than TTL; returned with cached=True
      def put(self, source: str, ioc: IOC, result: SourceResult) -> None # never stores status "not_checked"
      def vt_calls_today(self) -> int                                    # UTC day
      def add_vt_call(self) -> None
  ```
  Tables: `results(source, ioc_type, value, fetched_at REAL, payload TEXT, PRIMARY KEY(source, ioc_type, value))`, `vt_calls(day TEXT PRIMARY KEY, count INTEGER)`. Payload = JSON of the result (dates as ISO strings).

- [ ] **Step 1: Failing tests:** limiter at 4/min with fake clock/sleep: 3 back-to-back `wait()` → sleeps `[15.0, 15.0]` (first is free); at 60/min → 1.0 s. Cache: put then get → equal fields, `cached=True`, `fetched_on` preserved; advance fake `now` by 7 days + 1 s → `None`; 6 days → hit; `not_checked` not stored; `add_vt_call` ×3 → `vt_calls_today() == 3`, next UTC day → 0.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS. **Step 5:** Checkpoint.

---

### Task 6: VirusTotal source

**Files:**
- Create: `ioc_enrich/sources/__init__.py`, `ioc_enrich/sources/vt.py`, `tests/fixtures/vt_domain.json`, `vt_ip.json`, `vt_file.json`, `vt_url.json`, `vt_resolutions.json`
- Test: `tests/test_source_vt.py`

**Interfaces:**
- Produces (uniform for all sources, in `sources/__init__.py`):
  ```python
  Lookup = Callable[[IOC, str, HttpClient, date], SourceResult]   # (ioc, key, http, today)
  LOOKUPS: dict[str, Lookup]   # filled by Tasks 6–8: "VT","ThreatFox","URLhaus","MalwareBazaar","OTX","AbuseIPDB","RDAP"
  KEY_FIELD = {"VT":"vt","ThreatFox":"abusech","URLhaus":"abusech","MalwareBazaar":"abusech","OTX":"otx","AbuseIPDB":"abuseipdb","RDAP":None}
  ```
- Produces (`vt.py`): `lookup(ioc, key, http, today) -> SourceResult`; `lookup_age(domain: str, key, http, today) -> SourceResult` (source `"VT-age"`, fields `{"creation_date": "YYYY-MM-DD" | None}`); `lookup_related(ioc, key, http, today) -> SourceResult` (source `"VT-related"`, fields `{"resolutions": [...]}` or `{"contacted_domains": [...], "contacted_ips": [...]}`; `?limit=10`); `url_id(url: str) -> str` (urlsafe base64, `=` stripped); `calls_for_related(ioc) -> int` (1 for domain/ip, 2 for hashes, 0 for url).
- VT fields (status `ok`): `malicious`, `suspicious`, `total` (sum of all `last_analysis_stats` values), `words` (sorted distinct `result` of engines whose `category` is malicious/suspicious; for hashes instead `[popular_threat_classification.suggested_threat_label]` when present), `creation_date` (UTC date ISO or None). `flagged = malicious + suspicious >= 1`. 404 → `not_listed`. Header `x-apikey`. Raises `RateLimited` through.

- [ ] **Step 1: Failing tests** (fixtures hand-written to the documented schema, `total` 92):
  ```python
  r = vt.lookup(IOC("domain","www.grinswakebthu.info"), "K", fake, TODAY)
  self.assertEqual((r.status, r.fields["malicious"]+r.fields["suspicious"], r.fields["total"]), ("ok", 2, 92))
  self.assertEqual(r.fields["words"], ["malicious", "malware"]); self.assertTrue(r.flagged)
  # url: request path == "/api/v3/urls/" + url_id(url); url_id("http://www.independent.ie/ujvq/") has no "="
  # file: words == ["trojan.xloader/formbook"]
  # 404 -> not_listed, flagged False; header x-apikey sent; only GET used (fake.calls)
  # lookup_related(domain) hits /domains/{d}/resolutions?limit=10
  ```
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS. **Step 5:** Checkpoint.

---

### Task 7: abuse.ch sources (ThreatFox, URLhaus, MalwareBazaar)

**Files:**
- Create: `ioc_enrich/sources/threatfox.py`, `urlhaus.py`, `bazaar.py`, fixtures `tf_hit.json`, `tf_none.json`, `uh_host_hit.json`, `uh_url_hit.json`, `uh_none.json`, `mb_hit.json`, `mb_none.json`
- Test: `tests/test_source_abusech.py`

**Interfaces:** each exports `lookup(ioc, key, http, today) -> SourceResult`, registered in `LOOKUPS`. Header `Auth-Key`.
- ThreatFox: hashes → `{"query":"search_hash","hash":h}` (md5/sha256 only); else `{"query":"search_ioc","search_term":v,"exact_match":true}`. `query_status == "ok"` → `ok`, fields `{"families": sorted distinct malware_printable}`, flagged; `no_result` → `not_listed`.
- URLhaus: url → `/v1/url/` form `url`; domain/ip → `/v1/host/` form `host`; md5/sha256 → `/v1/payload/` form `md5_hash`/`sha256_hash`. `ok` → fields `{"threat": str, "url_status": str, "url_count": int}`, flagged; `no_results` → `not_listed`.
- MalwareBazaar: form `query=get_info&hash=h`. `ok` → fields `{"signature": str|None, "tags": [...]}`, flagged; `hash_not_found` → `not_listed`.
- Any other `query_status` (e.g. `invalid_*`, `unknown_auth_key`) → `not_checked`, reason `error: <query_status>`.

- [ ] **Step 1: Failing tests:** each hit/none fixture → expected status/fields; ThreatFox body contains `"exact_match": true`; ThreatFox on sha1 is never requested (not in `SOURCES_BY_TYPE`, assert raises `ValueError` if called); MalwareBazaar body `query == "get_info"`; `unknown_auth_key` → `not_checked` `error: unknown_auth_key`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS. **Step 5:** Checkpoint.

---

### Task 8: OTX, AbuseIPDB, RDAP sources

**Files:**
- Create: `ioc_enrich/sources/otx.py`, `abuseipdb.py`, `rdap.py`, fixtures `otx_general.json`, `abuseipdb_check.json`, `rdap_domain.json`
- Test: `tests/test_source_misc.py`

**Interfaces:** `lookup(ioc, key, http, today) -> SourceResult` each.
- OTX: section type: domain → `domain` if `ioc.value == registered_domain(ioc.value)` else `hostname`; ip → `IPv4`; url → `url`; hashes → `file`. URL path `/api/v1/indicators/{type}/{quote(value, safe='')}/general`. Fields `{"pulses": pulse_info.count}`; status `ok` if pulses ≥ 1 (flagged) else `not_listed`; 404 → `not_listed`. Header `X-OTX-API-KEY`.
- AbuseIPDB: `?ipAddress=v&maxAgeInDays=90`, headers `Key`, `Accept: application/json`. Fields `{"score": abuseConfidenceScore, "reports": totalReports, "isp": ..., "usage": usageType}`; `ok` always when 200; `flagged = reports >= 1`.
- RDAP: query `registered_domain(ioc.value)`; caller (engine) only calls it when the TLD is in `load_rdap_tlds()`. Fields `{"created": eventDate[:10] of eventAction "registration" | None, "registrar": vcard fn of entity with role registrar | None}`; 404 → `not_listed`. No key. Never flagged.

- [ ] **Step 1: Failing tests:** OTX on `www.taibeinan.cc` requests `/indicators/hostname/www.taibeinan.cc/general`, on `taibeinan.cc` → `/domain/`; pulses 2 → `ok`, flagged; AbuseIPDB `score 35, reports 12` → fields, flagged; reports 0 → not flagged; RDAP fixture → `created == "2026-05-16"`, registrar parsed; RDAP request goes to `https://rdap.org/domain/taibeinan.cc`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS. **Step 5:** Checkpoint.

---

### Task 9: Engine (scheduling, cache, quota, 429, age call, deep, cost estimate)

**Files:**
- Create: `ioc_enrich/engine.py`
- Test: `tests/test_engine.py`

**Interfaces:**
- Consumes: `Planned`, `Keys`, `HttpClient`/`FakeHttp`, `Cache`, `RateLimiter`, `LOOKUPS`, `vt.lookup_age`, `vt.lookup_related`, `load_rdap_tlds`, `registered_domain`.
- Produces:
  ```python
  @dataclass
  class RunOptions:
      no_vt: bool = False; no_cache: bool = False; deep: bool = False
      vt_per_minute: int = 4; vt_daily_limit: int = 500
  @dataclass
  class Cost:
      vt_calls: int; vt_age_calls_max: int; other_calls: int; seconds: int
      def describe(self, n_iocs: int) -> str    # "12 IOCs → 9 VT calls (+ up to 1 for domain age), about 2 min 15 s"
  def estimate(planned: list[Planned], cache: Cache, opts: RunOptions, rdap_tlds: set[str]) -> Cost
  def run(planned, keys: Keys, http, cache: Cache, opts: RunOptions,
          on_result: Callable[[IOC, SourceResult], None] = lambda i, r: None,
          today: Callable[[], date] = lambda: datetime.now(timezone.utc).date(),
          sleep=time.sleep, clock=time.monotonic) -> dict[IOC, list[SourceResult]]
  ```
- Rules (from spec):
  - Skipped `Planned` (private/allowlisted) get no results.
  - Per source: cache hit (unless `no_cache`) → use it. Missing key → `not_checked "no key"`. `no_vt` → VT `not_checked "--no-vt"`. CDN → VT `skipped "shared CDN"` (no call). RDAP only if TLD in `rdap_tlds`, else no RDAP result.
  - Non-VT lookups: `ThreadPoolExecutor(max_workers=4)`; RDAP through its own `RateLimiter(per_minute=60)`.
  - VT: one worker thread, `RateLimiter(opts.vt_per_minute)`, `cache.add_vt_call()` per real request. On `RateLimited`: if `vt_calls_today() >= vt_daily_limit` or 3 consecutive 429s → quota exhausted: this and every remaining VT job → `not_checked "quota"`. Else `sleep(retry_after or 60)` and retry the same job.
  - Age call: domain IOC, TLD not in `rdap_tlds`, `value != registered_domain(value)`, VT result has no `creation_date` → `vt.lookup_age(registered_domain)` (cached under source `"VT-age"`, counts as a VT call).
  - `deep`: after a VT `ok`/`not_listed`, `vt.lookup_related` (counts `calls_for_related` VT calls).
  - Any other exception from a lookup (`URLError`, `TimeoutError`, `ValueError` from bad JSON, HTTP ≥500 handled in sources) → `not_checked "error: <ExceptionName>"` and continue.
  - Fresh results (not `not_checked`) → `cache.put`. Every result → `on_result` (may be called from threads; caller must be thread-safe).
  - `KeyboardInterrupt` → cancel pending futures, stop VT worker, re-raise (caller writes partial output).
  - `estimate`: VT calls = planned non-skipped, non-CDN IOCs with VT in sources and no cache hit (0 if `no_vt`); `vt_age_calls_max` = domains matching the age-call condition by TLD; + related calls if `deep`; `seconds = (vt_calls + vt_age_calls_max) * 60 // vt_per_minute`.

- [ ] **Step 1: Failing tests** (FakeHttp + temp Cache + fake sleep/clock):
  - Task 3 sample, all keys set → VT requested for the 3 domains + `146.59.71.167` only (not CDN, not private); Cloudflare IP has VT `skipped "shared CDN"`; RDAP requested for `grinswakebthu.info` and `taibeinan.cc`, not `independent.ie`; `www.independent.ie` gets a `VT-age` call to `/domains/independent.ie`.
  - `estimate` on same sample → `vt_calls == 4`, `vt_age_calls_max == 1`, `seconds == 75`; `describe(5)` == `"5 IOCs → 4 VT calls (+ up to 1 for domain age), about 1 min 15 s"`.
  - Second run with same cache → zero HTTP calls, results `cached=True`.
  - 429 once then 200 → one `sleep(60)` (or Retry-After value), result `ok`.
  - 429 ×3 → that IOC and all later VT jobs `not_checked "quota"`; non-VT results still present.
  - `vt_calls_today()` already 500 then 429 → `quota` immediately, no sleep.
  - No abuse.ch key → ThreatFox/URLhaus `not_checked "no key"`, others fine.
  - **Review Focus 4:** URLhaus raises `TimeoutError`, ThreatFox returns 500 with HTML body → `not_checked "error: …"`, OTX/VT results still `ok`.
  - `no_vt` → zero VT calls; VT `not_checked "--no-vt"`.
  - DNS guard: patch `socket.getaddrinfo` to fail the test if called; full `extract → plan → run` with FakeHttp passes.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS. **Step 5:** Checkpoint.

---

### Task 10: Enrichment string, flagged-by line, manual links

**Files:**
- Create: `ioc_enrich/format.py`, `ioc_enrich/links.py`
- Test: `tests/test_format.py`, `tests/test_links.py`

**Interfaces:**
- Produces:
  ```python
  def enrichment(ioc: IOC, results: list[SourceResult], ref_date: date | None) -> str
  def flagged_by(results: list[SourceResult]) -> str
  def is_complete(results: list[SourceResult]) -> bool         # False if any status == "not_checked"
  def checked_on(results: list[SourceResult], today: date) -> date   # oldest fetched_on of ok/not_listed/skipped; today if none
  def screen_line(planned: Planned, results: list[SourceResult], ref_date: date | None) -> str
  def manual_links(ioc: IOC) -> list[tuple[str, str]]          # (label, url)
  ```
- Exact part formats (join with `"; "`, order: ThreatFox, VT, URLhaus, MalwareBazaar, OTX, AbuseIPDB, age; parts only for sources that produced a result):
  - ThreatFox: `ThreatFox: not listed` | `ThreatFox: XLoader, Formbook`
  - VT: `VT 2/92 (malicious, malware)` | `VT 0/92` | `VT: not found` (404)
  - URLhaus: `URLhaus: not listed` | `URLhaus: malware_download (online)` (host: `URLhaus: 3 URLs (malware_download)`)
  - MalwareBazaar: `MalwareBazaar: not listed` | `MalwareBazaar: AgentTesla`
  - OTX: `OTX: 0 pulses` | `OTX: 1 pulse` | `OTX: 2 pulses`
  - AbuseIPDB: `AbuseIPDB: 35% (12 reports)` | `AbuseIPDB: 0% (0 reports)`
  - skipped/not checked: `VT: skipped (shared CDN)`, `VT: off (--no-vt)`, otherwise `<Source>: not checked (<reason>)`
  - age (domain only): from RDAP `created`, else `VT-age`/VT `creation_date`: `created 2026-05-15 via RDAP (86 d before incident)`; after → `(3 d after incident)`; no ref_date → `created 2026-05-15 via VT`; nothing → `age n/a`
  - allowlisted row: whole string `allowlisted - not checked`
- `flagged_by`: `flagged by: VT 2/92, ThreatFox, AbuseIPDB 12 reports, OTX 2 pulses` (only flagged ones, same order) | `flagged by: none` | `not checked` (no ok/not_listed results). Results with `cached=True` → the screen line ends with ` (cached)`.
- `screen_line`: `f"{type:<7}{defang(value):<34}{flagged_by}  |  {enrichment}"`; skipped: `ip     172[.]16[.]8[.]49   skipped (private)`; CDN rows add `  [shared CDN (Cloudflare) - do not block]`.
- Links: VT `https://www.virustotal.com/gui/{domain|ip-address|file}/{v}`, url → `https://www.virustotal.com/gui/search/{quote(v, safe='')}`; tria.ge `https://tria.ge/s?q={domain|ip|url|md5|sha1|sha256}:{quote(v)}`; ThreatFox `https://threatfox.abuse.ch/browse.php?search=ioc%3A{v}`; URLhaus `https://urlhaus.abuse.ch/browse.php?search={quote(v)}`; MalwareBazaar (hashes) `https://bazaar.abuse.ch/browse.php?search={md5|sha1|sha256}%3A{v}`; OTX `https://otx.alienvault.com/indicator/{domain|hostname|ip|url|file}/{v}`; AbuseIPDB (ip) `https://www.abuseipdb.com/check/{v}`.

- [ ] **Step 1: Failing tests:** one test per format line above using hand-built `SourceResult`s; full string for a domain: `"ThreatFox: not listed; VT 2/92 (malicious, malware); URLhaus: not listed; OTX: 0 pulses; created 2026-05-15 via RDAP (86 d before incident)"` with ref `2026-08-09`; `.ie` with only VT-age `2001-01-12` → `created 2001-01-12 via VT (…)`; flagged_by cases; `checked_on` picks the oldest cached date; links for each type (exact strings).
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS. **Step 5:** Checkpoint.

---

### Task 11: CSV build, merge, write

**Files:**
- Create: `ioc_enrich/csvio.py`, `tests/fixtures/iocs_sample.csv` (copy rows 1–5 and 18–19 of `~/learning/soc-analyst/writeups/2026-08-09-first-to-last/iocs.csv`, including the `user_agent` row)
- Test: `tests/test_csvio.py`

**Interfaces:**
- Produces:
  ```python
  COLUMNS = ["type","value","first_seen_utc","frame","context","role","confidence","enrichment","checked_on"]
  def read_rows(path: Path) -> list[dict[str, str]]          # utf-8, csv.DictReader; ValueError if header != COLUMNS
  def row_key(row_type: str, value: str) -> tuple[str, str]  # (type, refang(value).lower())
  def build_rows(planned: list[Planned], results: dict[IOC, list[SourceResult]],
                 existing: list[dict] | None, incident_date: date | None, today: date
                 ) -> tuple[list[dict], list[str]]          # (rows, notes)
  def write_rows(path: Path, rows: list[dict]) -> None        # open(path, "x"): FileExistsError if it exists
  def default_output_name(now: datetime) -> str               # "ioc-enrich-2026-10-31-1405.csv"
  ```
- Rules: private-skipped IOCs → no row. Existing rows keep order and every owner column; only `enrichment`/`checked_on` change, and only if `is_complete(results)` and the IOC was not allowlisted — else note `kept old enrichment (incomplete run): <defanged value>`. Rows of other types (`user_agent`) and rows not in this run untouched. New rows appended: `type`, defanged `value`, `enrichment`, `checked_on`, and `role = f"shared CDN ({cdn}) - do not block"` when `cdn`. `ref_date` per row = date part of the row's `first_seen_utc` (`YYYY-MM-DD HH:MM:SS`), else `incident_date`.

- [ ] **Step 1: Failing tests:** merging a complete run for `www.grinswakebthu.info` into the fixture changes only its `enrichment`/`checked_on`, keeps `context`, `role`, `confidence` byte-identical; age uses that row's `first_seen_utc` (`2026-08-09`); `user_agent` row identical; incomplete run (VT `quota`) → old enrichment kept + note; new IOC appended at end with CDN role; private IP absent; `write_rows` on existing path raises `FileExistsError`; output re-read equals rows; header mismatch → `ValueError`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS. **Step 5:** Checkpoint.

---

### Task 12: CLI (enrich, dry-run, merge, update-lists, interrupt)

**Files:**
- Create: `ioc_enrich/cli.py`
- Modify: `ioc_enrich/__main__.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Produces: `main(argv: list[str] | None = None, *, stdin=sys.stdin, stdout=sys.stdout, env=os.environ, deps: Deps | None = None) -> int`, where `@dataclass Deps(http, cache, now: Callable[[], datetime], sleep)` lets tests inject fakes (default: real ones).
- Command shape: `argv[0] == "serve"` → `server.serve(port)`; `argv[0] == "update-lists"` → `update_lists.main()`; otherwise the enrich parser:
  `ioc-enrich [FILE] [-o OUT] [--merge CSV] [--incident-date YYYY-MM-DD] [--no-vt] [--no-cache] [--deep] [--dry-run] [--allowlist PATH] [--keys PATH] [--vt-per-minute N] [--vt-daily-limit N]`. `--help` epilog lists the three commands, an example with the defanged sample, and one line: "Lookup only: never contacts an IOC, never submits anything for scanning."
- Input: FILE, else stdin if not a TTY, else (with `--merge` and no input) the lookup-able rows of the merge file; nothing → stderr `No IOCs found in input.` exit 2.
- Output order on stdout: summary lines (`screen_line`) as results complete per IOC; "Ignored" list; "Not checked" list; "Related" (with `--deep`); "Manual-check links" (every IOC, links indented); final line `Wrote <path> (<n> rows)` plus merge notes. Exit 0.
- `--dry-run`: no keys read, no network (assert `http.calls == []`), prints classification/skip per IOC, `Cost.describe`, per-source query counts, the links; writes no CSV.
- Ctrl-C: catch `KeyboardInterrupt` around `engine.run`, mark unanswered sources `not_checked "interrupted"`, still write CSV, print `Interrupted. Answers so far are cached; rerun the same command to continue.` exit 130.

- [ ] **Step 1: Failing tests:**
  - `--dry-run` on the sample via stdin: output contains `skipped (private)`, `shared CDN (Cloudflare) - do not block`, `4 VT calls`; `http.calls == []`; no file written; works with empty `env`.
  - Full run with FakeHttp + temp dirs: CSV written to `-o` path with 5 rows; stdout contains `flagged by:`; key string `TESTKEY123` (set in env) absent from stdout and stderr.
  - `-o` existing file → exit 1, message `refusing to overwrite`.
  - `--merge` fixture without input → re-checks fixture domain/ip rows only.
  - Empty input → exit 2.
  - **Review Focus 5:** FakeHttp raises `KeyboardInterrupt` on the 2nd call → exit 130, CSV exists, contains `not checked (interrupted)`.
  - `main(["--help"])` exits 0 and mentions `serve` and `update-lists`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS. **Step 5:** Checkpoint.

---

### Task 13: Local web page (`ioc-enrich serve`)

**Files:**
- Create: `ioc_enrich/server.py`, `ioc_enrich/web/index.html` (inline CSS + JS, no external URLs)
- Test: `tests/test_server.py`

**Interfaces:**
- Produces: `make_server(port: int, token: str, deps: Deps) -> ThreadingHTTPServer` (bound to `127.0.0.1` only); `serve(port: int = 8765) -> int` (generates `secrets.token_urlsafe(24)`, prints `Open http://127.0.0.1:<port>/?t=<token>`; Ctrl-C stops).
- Endpoints (JSON in/out; every request needs the token: `?t=` for `GET /`, header `X-Token` for `/api/*`; `Host` must be `127.0.0.1:<port>` or `localhost:<port>`; if `Origin` is present it must be `http://127.0.0.1:<port>` or `http://localhost:<port>`; otherwise 403):
  - `GET /` → `index.html` with the token injected.
  - `POST /api/plan` `{text, incident_date, no_vt, no_cache}` → `{cost: str, rows: [{type, value, status}], ignored: [...]}` (no network).
  - `POST /api/run` same body → `{job: id}`; runs `engine.run` in a background thread, collects results under a lock.
  - `GET /api/job/<id>` → `{done: bool, rows: [{type, value, status, enrichment, links: [[label,url]]}]}`; page polls every 2 s.
  - `GET /api/job/<id>/csv` → `text/csv` attachment (built with `build_rows`, no merge).
  - Body limit 1 MB → 413.
- Page: paste box, incident date, "No VT" + "Ignore cache" checkboxes, Run; cost line (from `/api/plan`, refreshed on input with 500 ms debounce); results table (type, value, status, enrichment) with per-row "links" toggle (links open in a new tab with `rel="noopener noreferrer"`); "Download CSV". All values inserted with `textContent`, never `innerHTML`.

- [ ] **Step 1: Failing tests** (start server on port 0 in a thread, FakeHttp deps, `urllib` client to 127.0.0.1): no token → 403; wrong token → 403; `Host: evil.com` → 403; `Origin: https://evil.com` → 403; valid `/api/plan` on sample → cost contains `4 VT calls`; `/api/run` then poll until `done` → 5 rows; CSV endpoint returns header `type,value,...`; 2 MB body → 413; server socket address is `127.0.0.1`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5:** Manual check in the built-in browser: `ioc-enrich serve`, open printed URL, paste sample, see cost line and dry plan (no keys needed for the plan); screenshot. Stop the server. Checkpoint.

---

### Task 14: README + end-to-end verification

**Files:**
- Create: `README.md`

- [ ] **Step 1:** README sections: Purpose; Safety rules (lookup only, never contacts IOCs, never submits/rescans/downloads, endpoint allowlist in `http.py`; **VT note:** VT adds every queried IOC to its dataset — use `--no-vt` when that would tip off an attacker); Setup (venv, `pip install -e .`, getting each free key: VT community account → API key; abuse.ch `https://auth.abuse.ch/` one Auth-Key for ThreatFox/URLhaus/MalwareBazaar; OTX account → API key; AbuseIPDB account → API key; `keys.env` example with placeholder values); Terms (free VT/AbuseIPDB/abuse.ch keys are personal/non-commercial; at work use the employer's licensed key; no multiple-account tricks); Usage (CLI examples incl. sample, `--dry-run`, `--merge`, `--incident-date`, `--deep`, `serve`, `update-lists`); Output (CSV columns, enrichment format, the exact "flagged by" rules, "the tool gives no verdicts"); Limitations (IPv4 only; RDAP missing for `.ie .io .co .de .me .ru .cn` → VT fallback; ThreatFox no SHA1 and IP lookups may miss `ip:port` entries; registered-domain guess is last-two-labels + small suffix list; free VT 4/min 500/day; filename-like TLD rule, incl. `.pl`); License MIT.
- [ ] **Step 2:** Full suite with memory check: `/usr/bin/time -l .venv/bin/python -m unittest discover -s tests 2>&1 | grep -E "Ran|OK|FAIL|maximum resident"` → `OK`, RSS well under 1 GB.
- [ ] **Step 3:** `ioc-enrich --help` and `printf '%s\n' "www.grinswakebthu[.]info, www.taibeinan[.]cc, www.independent[.]ie, 146.59.71[.]167, 172.64.155[.]76, 172.16.8[.]49" | ioc-enrich --dry-run` with an empty env → private IP skipped, Cloudflare IP flagged, rest planned. Show Vlad the output.
- [ ] **Step 4:** Live run with Vlad's keys (only if Vlad has put them in `~/.config/ioc-enrich/keys.env`; never print them): same sample with `--incident-date 2026-08-09 -o out/sample-live.csv`; compare with his hand enrichment in `iocs.csv` (VT counts, created dates). If no keys yet, say so and stop here.
- [ ] **Step 5:** `pgrep -fl python` — stop any server/process started. Checkpoint; ask Vlad whether to make the first commit.
