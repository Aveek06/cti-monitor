# CTI Monitor

An automated Cyber Threat Intelligence (CTI) feed aggregator that monitors **173 security research sources** and sends a digest email every 8 hours with newly published blog posts and advisories.

## What it does

- Monitors RSS/Atom feeds, HTML blog pages, JSON APIs, and bot-protected sites across 173 CTI sources (CrowdStrike, Kaspersky, Microsoft, CISA, Unit 42, Mandiant, Sophos, Trellix, and many more)
- Detects new posts by diffing against a seen-links history (`state.json`)
- Sends an HTML email digest with every new post — link, date, and source
- If nothing new is found, sends a "no new posts" notification so you always know the monitor ran
- Runs automatically every 8 hours via cron-job.org triggering GitHub Actions

## Sources

| Type | Count | Method |
|------|-------|--------|
| `feed` | 128 | RSS/Atom via feedparser |
| `html` | 24 | Playwright headless browser + CSS selector |
| `scrapling_fetcher` | 8 | curl_cffi TLS fingerprinting, no browser (Cloudflare-blocked feeds/pages) |
| `html_auto` | 6 | Playwright headless browser + link extraction |
| `scrapling_feed` | 2 | curl_cffi TLS fingerprinting + feedparser |
| `playwright_api` | 2 | Playwright + XHR interception |
| `crawl4ai` | 1 | crawl4ai with anti-bot fingerprinting |
| `scrapling_stealthy` | 1 | Patchright stealth browser (WAF bypass) |
| `api` | 1 | Direct JSON API |
| **Total active** | **173** | |

18 additional sources are currently set to `skip` (managed Cloudflare Turnstile, geo-blocked, or dead domains).

## Setup

### 1. Fork / clone this repo

```bash
git clone https://github.com/Aveek06/cti-monitor.git
cd cti-monitor
```

### 2. Add GitHub repository secrets

Go to **Settings → Secrets and variables → Actions** and add:

| Secret | Description |
|--------|-------------|
| `SMTP_USERNAME` | Your Gmail address |
| `SMTP_PASSWORD` | Gmail app password (16 chars — not your login password) |
| `EMAIL_TO` | Comma-separated addresses where digests should be delivered |

> To generate a Gmail app password: Google Account → Security → 2-Step Verification → App passwords

### 3. Set up the cron trigger

The workflow is triggered by an external cron service (e.g. [cron-job.org](https://cron-job.org)) that hits the GitHub Actions `workflow_dispatch` endpoint every 8 hours. Alternatively, go to **Actions → CTI Monitor → Run workflow** to trigger it manually.

### 4. Trigger a test run

Go to **Actions → CTI Monitor → Run workflow** to run it manually and verify you receive an email.

## How it works

```
run_check.py
  ├── feed             → feedparser pulls all RSS/Atom entries
  ├── html             → Playwright scrapes post cards via CSS selector
  ├── html_auto        → Playwright extracts all matching links (no selector needed)
  ├── playwright_api   → Playwright intercepts background XHR/JSON responses
  ├── api              → requests fetches JSON API directly
  ├── crawl4ai         → crawl4ai browser with anti-bot evasion
  ├── scrapling_feed   → curl_cffi TLS fingerprinting + feedparser (IP-blocked feeds)
  ├── scrapling_stealthy → patchright stealth browser (WAF-protected sites)
  ├── Diff against state.json (seen-links history)
  ├── New links → fetch publish date if missing → email digest
  └── Save updated state.json to GitHub Actions cache
```

### Key files

| File | Purpose |
|------|---------|
| `run_check.py` | Main pipeline — scrape, diff, email |
| `config.json` | All 191 site definitions (type, URL, selectors, filters) |
| `state.json` | Seen-links history per site (persisted via GitHub Actions cache) |
| `CTI_Source_List.xlsx` | Source-of-truth spreadsheet; sync workflow auto-generates config.json from it |
| `.github/workflows/cti-monitor.yml` | Main monitor workflow (triggered every 8 hours) |
| `.github/workflows/sync.yml` | Auto-syncs config.json when CTI_Source_List.xlsx is updated |

### Per-site config fields

| Field | Applies to | Description |
|-------|-----------|-------------|
| `url` | all | Page or feed URL to fetch |
| `post_container` | `html`, `crawl4ai` | CSS selector for each post card |
| `link_selector` | `html`, `crawl4ai` | CSS selector for the link inside each card (`"self"` if the container is the link) |
| `date_selector` | `html`, `crawl4ai` | CSS selector for the date element (optional) |
| `link_path_prefix` | `html_auto`, `crawl4ai`, `scrapling_*` | Only keep links whose path starts with this prefix |
| `path_exclude` | `html_auto`, `crawl4ai`, `scrapling_*` | Drop links whose path contains any of these strings |
| `min_slug_length` | `html_auto`, `crawl4ai`, `scrapling_*` | Drop links whose last path segment is shorter than N chars |
| `extra_wait_ms` | `html_auto`, `crawl4ai` | Extra wait after page load for JS-heavy SPAs (default 3000–5000ms) |
| `page_timeout_ms` | all Playwright/browser types | Navigation timeout override (default 30000ms) |
| `title_keywords` | `feed`, `scrapling_feed` | Only keep feed entries whose title contains one of these keywords |

## Local development

```bash
pip install feedparser requests playwright beautifulsoup4 crawl4ai "scrapling[fetchers]"
playwright install chromium
crawl4ai-setup
scrapling install

python run_check.py config.json state.json
```

Set `SMTP_USERNAME`, `SMTP_PASSWORD`, and `EMAIL_TO` as environment variables before running locally.
