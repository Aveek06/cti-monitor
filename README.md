# CTI Monitor

An automated Cyber Threat Intelligence (CTI) pipeline that monitors **173 security research sources**, sends daily email digests with AI-generated article summaries, extracts IOCs and MITRE ATT&CK techniques from new articles, and surfaces everything on a live dashboard.

---

## Features

| Feature | Detail |
|---|---|
| **Source monitoring** | 173 active sources — RSS feeds, JSON APIs, JS-heavy SPAs, WAF-protected blogs |
| **AI summaries** | 1-2 sentence CTI summary per article via Claude Haiku 4.5 |
| **IOC extraction** | SHA256 / SHA1 / MD5 / domain / IPv4 / IPv6 via iocsearcher (IANA TLD validation, defang, overlap removal) |
| **False positive filtering** | Source-domain filter + Tranco top-100k popularity list (cached monthly) |
| **STIX 2.1 storage** | Each IOC stored as a valid STIX 2.1 Indicator in Supabase PostgreSQL |
| **Decay scoring** | Jakusz (2025) adversary-aware formula with APT10/29/38 LTV coefficients |
| **VirusTotal verification** | Hash IOCs (min 10 malicious engines) and IP IOCs (min 3 malicious engines) |
| **Shodan enrichment** | IP IOCs tagged as VPN / proxy / scanner / honeypot with open ports |
| **TTP extraction** | MITRE ATT&CK technique extraction — regex (free, always-on) + Claude AI (cost-guarded) |
| **URLhaus feed** | Malware URL IOCs ingested from URLhaus blocklist |
| **Live dashboard** | Sources / IOCs / TTPs / VMs tabs with real-time data from the latest artifact |
| **ATT&CK Navigator export** | One-click JSON layer export for MITRE ATT&CK Navigator |
| **CISA KEV tracking** | VM tab shows Known Exploited Vulnerabilities with NVD CVSS scores |
| **Weekly report** | Friday email listing stale sites, 7-day activity, and cumulative AI cost |
| **AI cost tracking** | Per-run cost in every digest email; 7-day rollup in weekly report |
| **Zero-post notification** | Digest always sent — even when no new articles are found |

---

## Architecture

```
GitHub Actions (daily 21:30 IST via cron-job.org + schedule fallback)
  │
  ├── run_check.py
  │     ├── Scrape 173 sources (rss / api / nextjs / scrapling / crawl4ai / html / html_auto)
  │     ├── Diff against state.json (dedup, capped per site)
  │     ├── Filter articles older than 30 days from digest
  │     ├── Summarise fresh articles → Claude Haiku 4.5 (1-2 sentences)
  │     ├── ioc_pipeline.py
  │     │     ├── ioc_extractor.py   — fetch + iocsearcher extract + Tranco/source FP filter
  │     │     ├── stix_converter.py  — build STIX 2.1 Indicator objects
  │     │     ├── ioc_db.py          — upsert to Supabase (psycopg2)
  │     │     ├── vt_enricher.py     — VirusTotal hash + IP reputation
  │     │     ├── shodan_enricher.py — Shodan IP tagging (VPN / scanner / honeypot)
  │     │     ├── ttp_extractor.py   — MITRE ATT&CK regex + Claude AI extraction
  │     │     ├── urlhaus_fetcher.py — URLhaus malware URL feed
  │     │     ├── ioc_scorer.py      — Jakusz decay score
  │     │     └── Save ioc_export.json + ttp_export.json (for dashboard)
  │     ├── Save state.json, last_active.json, prev_run_links.json
  │     └── Send HTML digest email (articles + summaries + IOC tables + AI cost)
  │
  ├── weekly_report.py  (Fridays only)
  │     └── Send stale-sites email (sites quiet 7+ days, activity chart, 7-day AI cost)
  │
  └── GitHub Actions cache + artifact
        state.json / last_active.json / prev_run_links.json
        ioc_export.json / ttp_export.json / .tranco_cache.txt

Dashboard (Vercel)
  ├── /api/data.js   — fetches latest artifact from GitHub, returns JSON
  └── /public/index.html
        ├── Sources tab — site cards, 7-day sparkline, active / quiet / failing panels
        ├── IOCs tab    — searchable table, live decay scores, VT + Shodan enrichment
        ├── TTPs tab    — MITRE ATT&CK heatmap with observation counts + Navigator export
        └── VMs tab     — CISA KEV vulnerabilities with NVD CVSS scores
```

---

## Scraper Types

| Type | Method | Used for |
|---|---|---|
| `rss` / `feed` | feedparser | Standard RSS / Atom feeds |
| `api` | requests + JSON | Sites with a public JSON API |
| `nextjs` | Playwright + Next.js routing | Next.js-rendered blogs |
| `scrapling` | Lightweight HTTP + CSS selectors | Plain HTML blogs |
| `scrapling_stealthy` | Patchright stealth browser | WAF / Cloudflare-protected sites |
| `crawl4ai` | AI-assisted crawler | JS-heavy SPAs |
| `html` | Playwright + CSS selectors | Dynamic HTML with explicit selectors |
| `html_auto` | Playwright + heuristic detection | Dynamic HTML without known selectors |
| `skip` | No-op | Disabled sources |

---

## Setup

### 1. Fork and clone

```bash
git clone https://github.com/Aveek06/cti-monitor.git
cd cti-monitor
```

### 2. Supabase (IOC storage)

1. Create a project at [supabase.com](https://supabase.com)
2. Go to **Settings → Database → Connection string** and copy the URI (port 5432)
3. The `ioc_indicators` and `ttp_observations` tables are auto-created on first pipeline run — no manual SQL needed

### 3. API keys

| Service | Where to get it | Free tier |
|---|---|---|
| VirusTotal | [virustotal.com](https://www.virustotal.com) → profile → API key | 4 req/min |
| Shodan | [shodan.io](https://www.shodan.io) → account → API key | Membership plan |
| URLhaus | [urlhaus-api.abuse.ch](https://urlhaus-api.abuse.ch) | Free |

### 4. Dashboard (Vercel)

1. Import the repo into [Vercel](https://vercel.com), set **Root Directory** to `dashboard`
2. Add a `GITHUB_TOKEN` environment variable in Vercel (a GitHub personal access token with `repo` read scope)
3. Vercel auto-deploys on every push; the dashboard reads the latest GitHub Actions artifact

### 5. Trigger a test run

Go to **Actions → CTI Monitor → Run workflow** to run manually and confirm you receive an email.

---

## Email Digest

Each daily digest contains:

- **New articles table** — date, source, link, and a 1-2 sentence AI summary beneath each link
- **IOC tables** — New this run / Active (score ≥ 30) / Expiring (score < 30), capped at 20 rows each
- **AI status footer** — articles summarised, token counts, cost (or reason if skipped)

---

## IOC Pipeline

### Extraction

Articles are fetched, stripped to plain text, and scanned with [iocsearcher](https://github.com/malicialab/iocsearcher) after un-defanging (`hxxp→http`, `[.]→.`):

| IOC type | Method |
|---|---|
| SHA-256 | 64-char hex word |
| SHA-1 | 40-char hex word |
| MD5 | 32-char hex word |
| Domain / FQDN | IANA TLD validation, overlap removal |
| IPv4 | IANA validated, private/reserved ranges excluded |
| IPv6 | IANA validated, private/reserved ranges excluded |

**False positive filtering** runs after extraction:

1. **Allowlist** — known-good domains (security vendors, CDNs, dev platforms, news sites) filtered by exact match or subdomain
2. **Source domain filter** — the article's own blog domain is never extracted as an IOC
3. **Tranco top-100k** — domains ranking in the Tranco popularity list are filtered; list downloaded once and cached for 30 days

APT attribution is detected by keyword scan across 80+ threat actor aliases.

### IP Enrichment

After extraction, IP IOCs are enriched asynchronously (up to 20 per run, rate-limited):

- **VirusTotal** — flags IPs with ≥ 3 malicious engine detections
- **Shodan** — tags IPs with context labels (VPN / tor / scanner / honeypot / cloud) and stores open ports

### STIX 2.1 Storage

Each IOC becomes a STIX 2.1 `Indicator` object with a deterministic UUID (`uuid5(namespace, value:type)`) so the same IOC is safe to re-ingest. Stored in Supabase `ioc_indicators` with full STIX JSON in a `JSONB` column.

### Decay Scoring (Jakusz 2025)

```
score = 100 × (1 − (t / (τ × LTV))²)

t   = days since last_seen
τ   = VirusTotal TTL (observed) or default (domain/IP: 30d, hash: 60d)
LTV = adversary-specific lifetime value:
      APT10: domain 0.97 / hash 1.85
      APT29: domain 0.61 / hash 0.84
      APT38: domain 0.83 / hash 0.77
      Unknown: 1.0
```

Scores are recomputed **live in the browser** on every page load using the exported `tau` and `ltv` values — the dashboard always shows true current-moment decay, not a stale snapshot.

### Pruning

IOCs with `last_seen` older than **90 days** are automatically deleted from Supabase at the end of each pipeline run. If a pruned IOC resurfaces in a new article, the upsert recreates it with today's date.

---

## TTP Extraction

Each new article is scanned for MITRE ATT&CK techniques in two passes:

1. **Regex** — free, always runs, matches explicit `T1234` / `T1234.001` references and common technique keywords
2. **Claude AI** — reads the full article text and returns structured technique IDs; runs cost-guarded (budget cap per run)

Techniques are stored in Supabase `ttp_observations` with article URL, site, APT attribution, date, and observation count. The dashboard TTPs tab renders a heatmap and supports one-click export to MITRE ATT&CK Navigator JSON.

---

## Weekly Report

Sent every **Friday at 21:30 IST**. Contains:

- Stat chips: active sources / quiet sites / links this week / 7-day AI cost
- Stale sites table (color-coded: amber ≥ 7 days, red ≥ 14 days)
- Source activity bar chart (7-day link counts)

Sites currently failing their scraper are excluded from the stale report — they appear in the daily digest instead.

---

## Key Files

| File | Purpose |
|---|---|
| `run_check.py` | Main pipeline: scrape → diff → summarise → IOC extract → email |
| `config.json` | All site definitions (type, URL, selectors, filters) |
| `state_seeds.json` | Seed URLs for new/empty sites (applied on first run or after cache reset) |
| `state.json` | Seen-links history per site (GitHub Actions cache) |
| `last_active.json` | Per-site timestamps, 7-day counts, daily AI cost |
| `prev_run_links.json` | Enriched link objects `{url, site, date, summary}` for dashboard |
| `ioc_export.json` | Scored IOC list `{value, type, apt, score, tau, ltv, shodan_tags, …}` |
| `ttp_export.json` | TTP observations `{technique_id, tactic, score, apt, …}` for dashboard |
| `ioc_extractor.py` | Fetch article text, iocsearcher extraction, Tranco + source FP filtering, APT detection |
| `stix_converter.py` | Build STIX 2.1 Indicator / ThreatActor / Relationship dicts |
| `ioc_scorer.py` | Jakusz decay formula + LTV coefficients |
| `vt_enricher.py` | VirusTotal hash and IP verification (free-tier rate-limited) |
| `shodan_enricher.py` | Shodan IP tagging — VPN, scanner, honeypot labels + open ports |
| `ioc_db.py` | Supabase upsert / query / prune via psycopg2 |
| `ioc_pipeline.py` | Orchestrates extraction → STIX → DB → VT → Shodan → TTP → URLhaus → export |
| `ttp_extractor.py` | MITRE ATT&CK extraction: regex pass + Claude AI pass |
| `urlhaus_fetcher.py` | URLhaus malware URL feed ingestion |
| `weekly_report.py` | Friday stale-sites report |
| `dashboard/api/data.js` | Vercel function: fetches GitHub artifact, returns JSON |
| `dashboard/public/index.html` | Live dashboard (Sources / IOCs / TTPs / VMs tabs) |
| `.github/workflows/cti-monitor.yml` | Daily workflow (21:30 IST via cron-job.org + fallback schedule) |

---

## Local Development

```bash
pip install feedparser requests playwright beautifulsoup4 crawl4ai "scrapling[fetchers]" \
    anthropic psycopg2-binary htmldate iocsearcher openpyxl
playwright install chromium
crawl4ai-setup
scrapling install

# Environment variables
export SMTP_USERNAME=you@gmail.com
export SMTP_PASSWORD=your-app-password
export EMAIL_TO=recipient@example.com
export ANTHROPIC_API_KEY=sk-ant-...
export VT_API_KEY=your-vt-key
export SHODAN_API_KEY=your-shodan-key
export URLHAUS_API_KEY=your-urlhaus-key
export DATABASE_URL=postgresql://...

python run_check.py config.json state.json last_active.json prev_run_links.json
python weekly_report.py config.json last_active.json ioc_export.json  # stale-sites report
```

Dashboard (requires Node.js + Vercel CLI):

```bash
cd dashboard
npm install
GITHUB_TOKEN=ghp_... vercel dev
```
