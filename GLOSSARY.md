# ioc-enrich

Enrichment of indicators of compromise for a SOC investigation: what public threat-intel sources already know about each indicator, written next to the analyst's own notes.

## Indicators

**IOC**:
One indicator of compromise of type domain, ip, url, md5, sha1 or sha256, in its real (refanged) form.
_Avoid_: indicator, artifact, observable

**Shared CDN IP**:
An IP inside a published content-delivery range (Cloudflare, Fastly, CloudFront) that serves many unrelated sites, so it must not be blocked.
_Avoid_: CDN IOC, benign IP

**Allowlist**:
The analyst's list of known-good domains; an entry also covers its subdomains.
_Avoid_: whitelist, safelist

## Lookups

**Source**:
One public threat-intel service the tool may ask about an IOC (VirusTotal, ThreatFox, URLhaus, MalwareBazaar, OTX, AbuseIPDB, RDAP).
_Avoid_: provider, feed, API

**Lookup**:
One question to one source about one IOC, together with its intended outcome: asked, skipped, or not checked.
_Avoid_: query, request, call

**Lookup plan**:
All the lookups a run intends to make, decided before anything is sent, including the follow-up lookups that depend on an earlier answer.
_Avoid_: query plan, job list

**Follow-up lookup**:
A lookup that is only made because of another lookup's answer, such as asking VirusTotal for the registered domain's creation date when the hostname's answer has none.
_Avoid_: secondary query, chained call

**Skipped**:
A lookup deliberately not made because asking would be wrong (a shared CDN IP is never sent to VirusTotal).
_Avoid_: ignored, excluded

**Not checked**:
A lookup that should have been made but was not (no key, quota, --no-vt, interrupted, error); the row is then incomplete.
_Avoid_: failed, missing

## Results

**Enrichment**:
The short, fixed-order text summarising every source's answer for one IOC, written into the CSV.
_Avoid_: verdict, score, summary

**Flagged by**:
The list of sources that report an IOC as known-bad by their own published rule; a fact, never a verdict.
_Avoid_: hit, malicious, detection

**Complete row**:
A row whose every planned lookup was answered or deliberately skipped; only complete rows may replace an analyst's existing enrichment.
_Avoid_: finished, full

**Domain age**:
How many days before (or after) the incident a domain was registered.
_Avoid_: whois age, registration age
