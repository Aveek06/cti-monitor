# CTI Monitor

An automated Cyber Threat Intelligence pipeline that monitors **187 security research sources**, sends daily email digests with AI-generated article summaries, extracts IOCs and MITRE ATT&CK techniques with AI, surfaces everything on a live dashboard, and exports a **read-only TAXII 2.1 / STIX 2.1 feed** for downstream platforms.

---

## Features

| Feature | Detail |
|---|---|
| **Source monitoring** | 187 configured sources — RSS feeds, JSON APIs, JS-heavy SPAs, WAF-protected blogs |
| **Scraper diversity** | 9 scraper types: feed, api, nextjs, html, html_auto, crawl4ai, scrapling_fetcher, scrapling_stealthy, playwright_api |
| **Parallel scraping** | 15 concurrent HTTP workers; 6 concurrent crawl4ai browser tabs; Playwright sites sequential under one browser |
| **WAF bypass** | Full Chrome 125 browser headers + `requests.Session()`; automatic Playwright upgrade when responses are too short (< 1,500 chars) to be real article content |
| **AI article summaries** | 1–2 sentence CTI summary per article via Claude Haiku 4.5 |
| **AI combined extraction** | Single Claude Haiku call per article returns TTPs + IOCs + APT attribution as structured JSON |
| **IOC extraction** | SHA-256 / SHA-1 / MD5 / domain / IPv4 / IPv6 via iocsearcher (defang, IANA TLD validation, overlap removal) |
| **False positive filtering** | ~120-entry FP list + source-domain filter + Tranco top-100k + RFC1918 private IP filter + version-number IP heuristic |
| **APT attribution** | 80+ threat actor aliases (Chinese, Russian, Iranian, North Korean, financial) with word-boundary matching |
| **STIX 2.1 storage** | Each IOC stored as a deterministic STIX 2.1 Indicator in Supabase PostgreSQL (JSONB column) |
| **TAXII 2.1 export** | Read-only TAXII 2.1 endpoint (`/api/taxii/*`) serving the full STIX feed; optional Bearer token auth; pagination and `added_after` filtering |
| **Decay scoring** | Jakusz (2025) adversary-aware quadratic decay with APT10/29/38 LTV coefficients |
| **Site reliability scoring** | 0–100 score per source (availability + content quality + analyst feedback) |
| **Reliability-weighted LTV** | IOC lifetime extended 1.3× from high-reliability sources; shortened 0.7× from low-reliability sources |
| **VirusTotal verification** | SHA-256 and SHA-1 hashes (≥10 malicious engines), rate-limited to free tier |
| **Shodan enrichment** | IP IOCs tagged (VPN / proxy / scanner / honeypot) with open ports |
| **TTP extraction** | MITRE ATT&CK extraction — regex (free, always-on) + Claude AI (budget-capped, 30 articles/run) |
| **AI Sigma rule drafting** | On-demand analyst-triggered detection: one click in the TTP drawer calls Claude Haiku, injects the correct ATT&CK→logsource category from a code-side lookup table, validates YAML, and stores the rule with a draft/reviewed/promoted/retired lifecycle. **None of the 11 major commercial CTI platforms (MISP, Recorded Future, Anomali ThreatStream, ThreatConnect, ThreatQ, EclecticIQ, IBM X-Force Exchange, Mandiant/Google TI, Silobreaker, Flashpoint, CrowdStrike Falcon Intelligence) close this loop natively.** |
| **URLhaus feed** | Malware URL IOCs from URLhaus online-only filter, merged into export |
| **Live dashboard** | Sources / IOCs / TTPs tabs with reliability badges, source filter, export, ATT&CK heatmap |
| **IOC reliability filter** | Toggle IOC table to show all / ≥40 amber+ / ≥70 trusted sources only |
| **Weekly report** | Friday email: AI-generated threat narrative, stale sites, source activity, degradation alerts, 7-day IOC summary |
| **Degradation alerts** | Weekly email flags sources that dropped from ≥70 to <50 reliability since last snapshot |
| **AI cost tracking** | Per-run cost in every digest; 7-day rollup chip in weekly report |

---

## Architecture

```
GitHub Actions (daily 21:30 IST via cron-job.org + schedule fallback)
  │
  ├── run_check.py
  │     ├── Phase 1: Parallel fetch
  │     │     ├── HTTP sites (feed, api, nextjs, scrapling_fetcher)  — up to 15 threads
  │     │     ├── crawl4ai sites                                      — up to 6 async browser tabs
  │     │     └── Playwright sites (html, html_auto, playwright_api) — sequential, shared browser
  │     ├── Phase 2: State diffing
  │     │     ├── Diff against state.json (seen-URL dedup, flood guard)
  │     │     ├── Resolve publish dates (URL pattern → requests+htmldate → crawl4ai)
  │     │     └── Suppress articles older than 7 days from digest
  │     ├── Summarise fresh articles → Claude Haiku 4.5 (1-2 sentences)
  │     │     └── Fetches article text via fetch_article_text() (WAF-bypass headers + Playwright fallback)
  │     ├── Build site reliability scores (availability + content quality + analyst ratings)
  │     └── ioc_pipeline.py
  │           ├── Parallel fetch article texts (up to 10 workers, full browser headers)
  │           ├── Sort by reliability → high-reliability sites get Claude API budget priority
  │           ├── Per article:
  │           │     ├── ioc_extractor.py   — regex IOC extraction + APT detection
  │           │     ├── ai_extractor.py    — combined TTPs + IOCs + APT (one Haiku call)
  │           │     ├── ioc_scorer.py      — Jakusz decay LTV × reliability multiplier
  │           │     ├── stix_converter.py  — build STIX 2.1 Indicator objects
  │           │     └── ioc_db.py          — upsert to Supabase (psycopg2)
  │           ├── vt_enricher.py     — VirusTotal SHA-256/SHA-1 hash verification
  │           ├── shodan_enricher.py — Shodan IP tagging (VPN / scanner / honeypot)
  │           ├── urlhaus_fetcher.py — URLhaus malware URL feed (merged into export)
  │           └── Save ioc_export.json + ttp_export.json + sigma_export.json (for dashboard)
  │
  ├── Save state.json, last_active.json (with _reliability_snapshot), prev_run_links.json
  ├── Send HTML digest email (articles + summaries + IOC tables + reliability badges + AI cost)
  │
  ├── weekly_report.py  (Fridays 16:00–20:00 UTC, or force_weekly=true)
  │     ├── Claude Haiku: 2-3 paragraph executive threat narrative
  │     ├── Stale sites table (silent ≥ 7 days)
  │     ├── Source activity with reliability badges and degradation alerts
  │     └── IOC 7-day summary (by type, by APT, top-10 decay score table)
  │
  └── GitHub Actions cache + artifact (7-day retention)
        state.json / last_active.json / prev_run_links.json
        ioc_export.json / ttp_export.json / sigma_export.json / .tranco_cache.txt

Dashboard (Vercel)
  ├── /api/data.js           — fetches latest artifact from GitHub, returns merged JSON
  ├── /api/ratings.js        — analyst rating API (GET averages / POST new 1-5 star rating)
  ├── /api/taxii.js          — TAXII 2.1 server discovery (GET /api/taxii)
  ├── /api/taxii/[...].js    — TAXII 2.1 collections + objects (GET /api/taxii/*)
  └── /public/index.html
        ├── Home tab    — KPI cards, daily volume sparkline, IOC donut chart, ATT&CK radar
        ├── Sources tab — active / quiet / failing panels with reliability badges and site drawers
        ├── IOCs tab    — scored table with reliability filter, VT/Shodan enrichment, export
        ├── TTPs tab    — MITRE ATT&CK heatmap with tactic/technique breakdown + Navigator export
        │                 + "Draft Sigma Rule" button per technique (admin only)
        └── Sigma tab   — all drafted rules: expandable YAML, Copy button, status lifecycle dropdown
```

---

## Scraper Types

| Type | Method | Used for |
|---|---|---|
| `feed` | feedparser (+ direct fallback on fetch failure) | Standard RSS / Atom feeds |
| `api` | requests + JSON | Sites with a public JSON API |
| `nextjs` | Playwright + `__NEXT_DATA__` extraction | Next.js-rendered blogs |
| `scrapling_fetcher` | curl_cffi TLS fingerprinting | Fast fetching without a browser |
| `scrapling_stealthy` | Patchright stealth browser (+ Playwright domcontentloaded fallback on timeout) | WAF / Cloudflare-protected sites |
| `crawl4ai` | AsyncWebCrawler with stealth mode | JS-heavy SPAs |
| `html` | Playwright + CSS selectors | Dynamic HTML with known selectors |
| `html_auto` | Playwright + heuristic link diffing | Dynamic HTML without known selectors |
| `playwright_api` | Playwright + response interception | Sites that load content via API calls |
| `skip` | No-op | Disabled sources |

---

## WAF Bypass and Article Fetching

All article text (for summaries and IOC extraction) goes through `fetch_article_text()` in `ioc_extractor.py`, which runs a two-stage fetch:

1. **Stage 1 — requests with full browser headers**: Full Chrome 125 `User-Agent`, `Accept`, `Accept-Language`, `Sec-Fetch-*` headers via a `requests.Session()`. Response is cleaned by stripping nav/header/footer/script tags and checked for block-page signatures (Cloudflare, WP Engine WAF).

2. **Stage 2 — Playwright upgrade**: If the cleaned text is under 1,500 characters (JS shell, blank response, or block page), headless Chromium is launched with `wait_until="domcontentloaded"` to render the full page. The longer result wins.

Sites where even Playwright fails (interactive Cloudflare challenges, H2 rejection) are in `_PLAYWRIGHT_SKIP_HOSTS` and only the requests result is returned.

---

## Site Reliability Score

Each source receives a 0–100 score computed from three components:

| Component | Max | How it's earned |
|---|---|---|
| **Availability** | 40 | Not failing (+20), posted in last 7 days (+15), last_active timestamp known (+5); −2/day past 7 days |
| **Content quality** | 40 | IOC yield ratio (up to 25 pts), VT-verified IOC from this site (+5), APT-attributed IOC (+5) |
| **Analyst feedback** | 20 | 1–5 star ratings via dashboard (1★ = 0 pts, 5★ = 20 pts) |

Score thresholds: **≥70** green (trusted) / **40–69** amber (moderate) / **<40** red (low).

The score directly affects IOC lifetime: LTV for IOCs from green sources is multiplied by **1.3×** (decays slower); red sources get **0.7×** (decays faster). Reliability scores are snapshotted each run to detect degradation over time.

---

## IOC Pipeline

### Extraction

Articles are fetched with up to 10 parallel workers, then processed sequentially (sorted by source reliability). Each article runs two extraction passes:

1. **Regex pass** (`ioc_extractor.py`) — iocsearcher regex after un-defanging (`hxxp→http`, `[.]→.`)
2. **AI pass** (`ai_extractor.py`) — single Claude Haiku call returning TTPs + additional IOCs + APT as structured JSON; budget-capped at 30 articles per run

| IOC type | Notes |
|---|---|
| SHA-256 | 64-char hex |
| SHA-1 | 40-char hex |
| MD5 | 32-char hex (extracted; not sent to VirusTotal) |
| Domain / FQDN | IANA TLD validation, subdomain dedup |
| IPv4 / IPv6 | IANA validated; RFC1918 private ranges excluded; version-number strings filtered (max octet < 60) |

**False positive filtering** runs after both passes:

1. ~120-entry FP list — security vendors, CDNs, major platforms, news sites (exact + subdomain match)
2. Source-domain filter — the article's own domain is never extracted as an IOC
3. Tranco top-100k — popular domains filtered out; list cached locally for 30 days
4. RFC1918 private IP filter — `10.x`, `172.16–31.x`, `192.168.x`, loopback excluded
5. Version-number heuristic — dotted-quad strings where the largest octet is < 60 (e.g. `2.10.3.2`) are dropped

### Enrichment

| Enricher | IOC types | Threshold | Rate |
|---|---|---|---|
| VirusTotal | SHA-256, SHA-1 | ≥10 malicious engines | 15 s between calls (free tier) |
| Shodan | IPv4, IPv6 | — | 1 s between calls |
| URLhaus | URL | Online-only filter | Batch of up to 500 |

Shodan stores open ports and tags (e.g. `vpn`, `scanner`, `honeypot`) in JSONB columns. URLhaus URLs are merged directly into the export (not inserted into Postgres).

### STIX 2.1 Storage

Each IOC becomes a STIX 2.1 `Indicator` with a deterministic UUID (`uuid5(dns_namespace, value:type)`) — safe to re-ingest without duplication. Stored in Supabase `ioc_indicators` with full STIX JSON in a `JSONB` column alongside enrichment data.

### Decay Scoring (Jakusz 2025)

```
score = 100 × max(0, 1 − (t / (τ × LTV))²)

t   = days since last_seen
τ   = VT-observed TTL (if enriched) or default (domain 30d, hash 60d, url/ip 7d)
LTV = APT-specific coefficient (APT10: hash 1.85 / APT29: hash 0.84 / default 1.0)
      × site reliability multiplier (≥70: 1.3× / 40–69: 1.0× / <40: 0.7×)
```

Scores are recomputed live from stored `tau` and `ltv` values — the dashboard always shows current-moment decay. Active threshold: score ≥ 30. Expiring: 1–29. Hard prune: `last_seen` older than 90 days.

---

## TTP Extraction

Each article runs two passes:

1. **Regex** — free, always-on, matches `T1234` / `T1234.001` patterns against a ~320-technique lookup table
2. **Claude AI** (`ai_extractor.py`) — combined call also returns TTPs; falls back to `ttp_extractor` regex-only when AI budget is exhausted or no API key is set

Techniques are stored in Supabase `ttp_observations` with technique ID, name, tactic, APT attribution, source URL, and observation count. The dashboard TTPs tab renders a MITRE ATT&CK heatmap filterable by time window (7 / 14 / 30 / all days) with one-click Navigator JSON export.

---

## AI Sigma Rule Drafting

### The gap no commercial platform closes

Every major CTI platform extracts TTPs and maps them to MITRE ATT&CK. None of them produce detection rules from that extraction. The analyst still reads the report, opens a text editor, and writes Sigma YAML by hand.

Tested against 11 platforms as of mid-2025:

| Platform | TTP extraction | Auto-draft Sigma |
|---|---|---|
| MISP | Yes (via modules) | No |
| Recorded Future | Yes | No |
| Anomali ThreatStream | Yes | No |
| ThreatConnect | Yes | No |
| ThreatQ | Yes | No |
| EclecticIQ | Yes | No |
| IBM X-Force Exchange | Yes | No |
| Mandiant / Google Threat Intelligence | Yes | No |
| Silobreaker | Yes | No |
| Flashpoint | Yes | No |
| CrowdStrike Falcon Intelligence | Yes | No |
| **CTI Monitor** | **Yes** | **Yes** |

This is consistent with findings from [LLMCloudHunter (ACM WWW 2025)](https://arxiv.org/abs/2407.08445) — no benchmarked commercial platform auto-generates detection rules from threat reports — and [MITRE SigmaGen (March 2025)](https://medium.com/mitre-engenuity/sigmagen-using-llms-to-generate-sigma-rules-from-threat-reports-68e1d06f7c34), which identified AI-generated logsource categories as the primary failure mode.

### How it works

```
Analyst opens TTP drawer → clicks "Draft Sigma Rule"
  │
  ├── POST /api/draft-sigma
  │     ├── Fetch TTP row from ttp_observations (technique_id, tactic, APT, source URL)
  │     ├── Fetch up to 15 associated IOCs from ioc_indicators (same article)
  │     ├── Look up ATT&CK → Sigma logsource from a 30-entry code-side map
  │     │     (category and product injected into prompt — never inferred by the model)
  │     │     T1059.001 → process_creation / windows
  │     │     T1003.001 → process_access / windows
  │     │     T1053.005 → scheduled_task_creation / windows
  │     │     T1547.001 → registry_set / windows  ... and so on
  │     ├── Call Claude Haiku 4.5 (~600 input / ~500 output tokens, ~$0.003/rule)
  │     ├── Validate YAML with js-yaml; retry once with correction note on parse failure
  │     ├── INSERT ... ON CONFLICT DO NOTHING  (first draft wins; analyst edits preserved)
  │     └── Return stored rule to dashboard
  │
  └── Dashboard updates inline:
        "Draft Sigma Rule" button → rule display with status badge + Show/Copy YAML
```

The ATT&CK→logsource injection directly addresses MITRE SigmaGen's finding that incorrect `logsource.category` is the most common AI-generation failure. The model is never asked to infer it.

### Rule lifecycle

Analysts manage rules through a status progression:

```
draft → reviewed → promoted → retired
```

Status is stored in `sigma_rules.sigma_status` and surfaced as a live dropdown in the Sigma Rules tab (admin-only write; read-only badge for all authenticated users).

### Cost

| Token budget | Per rule | 5 rules/day |
|---|---|---|
| ~600 input + ~500 output | ~$0.003 | ~$0.016 |

On-demand generation means no tokens are spent on techniques already covered by existing rule libraries. Analysts choose which TTPs are worth detectionizing.

### Research basis

- **LLMCloudHunter** (Nadler et al., ACM WWW 2025): benchmarked 11 commercial platforms; none produce detection rules from threat reports; AI-generated rules explicitly marked as drafts requiring analyst validation.
- **MITRE SigmaGen** (March 2025): evaluated LLM-generated Sigma rules at scale; primary recommendation is to inject logsource category from a structured mapping rather than leaving it to the model.

---

## TAXII 2.1 Export

CTI Monitor exposes a read-only TAXII 2.1 endpoint that serves the full STIX 2.1 feed from Supabase. Any compatible platform (OpenCTI, MISP, Anomali, etc.) can point a TAXII client connector at it.

### Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/taxii` | Server discovery |
| GET | `/api/taxii/collections` | Collections list |
| GET | `/api/taxii/collections/cti-monitor-iocs` | Collection info |
| GET | `/api/taxii/collections/cti-monitor-iocs/objects` | Paginated STIX objects |

### Objects returned

- **`indicator`** — one per IOC, full STIX 2.1 dict from `ioc_indicators.stix_object` (JSONB)
- **`threat-actor`** — one per distinct attributed APT, deterministic UUID keyed on the actor name

### Query parameters (objects endpoint)

| Parameter | Default | Description |
|---|---|---|
| `added_after` | — | ISO 8601 datetime; filters to IOCs updated on or after this timestamp |
| `limit` | 200 | Page size (max 1,000) |
| `page` | 0 | Zero-indexed page number |

### Authentication

Set `TAXII_API_KEY` in the Vercel environment to gate the feed behind a Bearer token:

```
Authorization: Bearer <your-key>
```

If the variable is not set, the endpoint is open (useful during initial testing). The JWT cookie gate used by the main dashboard is bypassed entirely for all `/api/taxii/*` paths — no browser session required.

---

## AI Capabilities

All Claude usage uses **claude-haiku-4-5**. Three distinct uses per run:

| Use | Max tokens | Input limit | Notes |
|---|---|---|---|
| Article summarisation | 150 | 4,000 chars | Skipped if article text < 200 chars |
| Combined extraction (TTPs + IOCs + APT) | 1,000 | 3,500 chars | Budget-capped at 30 articles/run |
| Weekly narrative | 400 | ~300 token prompt | 2–3 paragraph executive threat summary |
| Sigma rule drafting | 600 | ~700 tokens | On-demand via dashboard; admin-only; ~$0.003/rule |

All three degrade gracefully to no-op when no API key is set. Daily spend is tracked in `last_active._ai_cost` and shown in both digest and weekly emails.

---

## Email Digest

Sent after every run (even zero-post runs). Sections:

- **New articles table** — date, source, link, AI summary
- **IOC summary** — new this run / active (≥30) / expiring (<30), up to 20 rows each
- **Site reliability snapshot** — badge + score for sites that posted or failed this run
- **AI footer** — model, articles processed, token counts, run cost

---

## Weekly Report

Sent every **Friday between 16:00–20:00 UTC** (or on demand via `force_weekly=true`). Sections:

- **KPI chips** — active sources, quiet sites, links this week, AI 7-day cost, active IOC count
- **Executive narrative** — Claude Haiku-generated 2–3 paragraph threat landscape summary
- **Stale sites** — sources silent for 7+ days, color-coded amber/red
- **Source activity** — 7-day link counts with reliability badge per source
- **Degradation alerts** — sources that dropped from ≥70 to <50 reliability since the previous run
- **IOC 7-day summary** — totals by type and APT, top-10 IOC decay score table

---

## Key Files

| File | Purpose |
|---|---|
| `run_check.py` | Main orchestrator: scrape → diff → summarise → reliability → IOC pipeline → email |
| `config.json` | All 187 site definitions (type, URL, selectors, filters, per-site timeouts) |
| `state_seeds.json` | Seed URLs for new or force-replaced sites (applied on first run or cache reset) |
| `state.json` | Seen-link history per site (GitHub Actions cache, max 2,000 URLs/site) |
| `last_active.json` | Per-site timestamps, 7-day counts, daily AI cost, reliability snapshot |
| `prev_run_links.json` | Enriched link objects `{url, site, date, summary}` for dashboard |
| `ioc_export.json` | Scored IOC list `{value, type, apt, score, tau, ltv, shodan_tags, …}` |
| `ttp_export.json` | TTP observations `{technique_id, tactic, total_observations, apts, …}` |
| `sigma_export.json` | All drafted Sigma rules `{technique_id, sigma_yaml, sigma_status, …}` — pre-populates dashboard on load |
| `ioc_extractor.py` | Article text fetch (WAF bypass + Playwright upgrade), iocsearcher extraction, FP filtering, APT detection |
| `ai_extractor.py` | Single Haiku call: returns TTPs + IOCs + APT as structured JSON |
| `stix_converter.py` | Build STIX 2.1 Indicator / ThreatActor / Relationship objects |
| `ioc_scorer.py` | Jakusz decay formula + APT LTV coefficients |
| `vt_enricher.py` | VirusTotal SHA-256/SHA-1 verification (free-tier rate-limited) |
| `shodan_enricher.py` | Shodan IP tagging — tags and open ports |
| `ioc_db.py` | Supabase upsert / query / prune via psycopg2 |
| `ioc_pipeline.py` | Orchestrates fetch → extract → STIX → DB → VT → Shodan → URLhaus → export |
| `ttp_extractor.py` | MITRE ATT&CK regex extraction with ~320-technique lookup table |
| `urlhaus_fetcher.py` | URLhaus malware URL feed (online-only filter) |
| `weekly_report.py` | Friday report: narrative generation + stale sites + degradation alerts |
| `dashboard/api/data.js` | Vercel function: fetches latest GitHub artifact, returns merged JSON |
| `dashboard/api/ratings.js` | Vercel function: analyst rating GET/POST backed by Supabase |
| `dashboard/api/draft-sigma.js` | Vercel function: POST — fetches TTP+IOCs, calls Claude Haiku, validates YAML, stores rule (admin only) |
| `dashboard/api/sigma-status.js` | Vercel function: PATCH — updates `sigma_status` for a rule (admin only) |
| `dashboard/api/taxii.js` | Vercel function: TAXII 2.1 server discovery (`GET /api/taxii`) |
| `dashboard/api/taxii/[...segments].js` | Vercel function: TAXII 2.1 collections and objects endpoints |
| `dashboard/middleware.js` | Vercel edge middleware: JWT cookie gate (bypassed for `/api/taxii/*`) |
| `dashboard/public/index.html` | Live dashboard (Home / Sources / IOCs / TTPs tabs) |
| `.github/workflows/cti-monitor.yml` | Daily workflow with guard job (21:30 IST primary + 20:00 UTC fallback) |

---

## Setup

### 1. Fork and clone

```bash
git clone https://github.com/Aveek06/cti-monitor.git
cd cti-monitor
```

### 2. Database (Supabase)

Create a project at [supabase.com](https://supabase.com). The `ioc_indicators`, `ttp_observations`, and `site_ratings` tables are auto-created on first pipeline run — no manual SQL needed.

### 3. Dashboard (Vercel)

1. Import the repo into [Vercel](https://vercel.com), set **Root Directory** to `dashboard`
2. Add the required environment variables:

| Variable | Required | Purpose |
|---|---|---|
| `DATABASE_URL` | Yes | Supabase Postgres connection string |
| `SESSION_SECRET` | Yes | HMAC secret for dashboard JWT signing |
| `GITHUB_TOKEN` | Yes | GitHub PAT (`repo` read scope) for artifact fetching |
| `NVD_API_KEY` | Optional | NVD rate limit: 50 req/30s with key vs 5 without |
| `URLHAUS_API_KEY` | Optional | abuse.ch API key for URLhaus live feed |
| `ANTHROPIC_API_KEY` | Yes (for Sigma) | Claude Haiku for on-demand Sigma rule drafting (Production + Preview + Development) |
| `TAXII_API_KEY` | Optional | If set, gates `/api/taxii/*` behind Bearer token auth |

3. Vercel auto-deploys on every push; the dashboard reads the latest GitHub Actions artifact

### 4. GitHub Actions secrets

Set these in **Settings → Secrets and variables → Actions**:

| Secret | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Claude Haiku for summaries, extraction, weekly narrative |
| `EMAIL_FROM` / `EMAIL_TO` | Digest and weekly report recipients |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | Gmail SMTP credentials |
| `DATABASE_URL` | Same Supabase URL as Vercel |
| `VT_API_KEY` | VirusTotal (free tier) |
| `SHODAN_API_KEY` | Shodan API |
| `URLHAUS_API_KEY` | URLhaus abuse.ch |
| `GITHUB_TOKEN` | Auto-provided by Actions (no setup needed) |

### 5. Trigger a test run

Go to **Actions → CTI Monitor → Run workflow** to run manually and confirm you receive an email.

---

## Local Development

```bash
pip install feedparser requests playwright beautifulsoup4 crawl4ai "scrapling[fetchers]" \
    anthropic psycopg2-binary htmldate iocsearcher openpyxl
playwright install chromium
crawl4ai-setup
scrapling install

python run_check.py config.json state.json last_active.json prev_run_links.json
python weekly_report.py config.json last_active.json ioc_export.json
```

Dashboard (requires Node.js):

```bash
cd dashboard
npm install
vercel dev
```
