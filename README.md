# CTI Monitor

An automated Cyber Threat Intelligence (CTI) feed aggregator that monitors **159 security research sources** and sends a digest email every 12 hours with newly published blog posts and advisories.

## What it does

- Monitors RSS/Atom feeds and HTML blog listing pages across 159 CTI sources (CrowdStrike, Kaspersky, Microsoft, CISA, Unit 42, Mandiant, and many more)
- Detects new posts by diffing against a seen-links history (`state.json`)
- Sends an HTML email digest with every new post — link, date, and source
- If nothing new is found, sends a "no new posts" notification so you always know the monitor ran
- Runs automatically every 12 hours via GitHub Actions

## Sources

| Type | Count |
|------|-------|
| RSS/Atom feeds | 132 |
| HTML scraped pages | 27 |
| **Total active** | **159** |

32 additional sources are currently set to `skip` (bot-walled, dead domains, or pending configuration).

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
| `EMAIL_TO` | Address where digests should be delivered |

> To generate a Gmail app password: Google Account → Security → 2-Step Verification → App passwords

### 3. Trigger a test run

Go to **Actions → CTI Monitor → Run workflow** to run it manually and verify you receive an email.

## How it works

```
run_check.py
  ├── For each feed site  → feedparser pulls all RSS/Atom entries
  ├── For each html site  → Playwright headless browser scrapes post cards
  ├── Diff against state.json (seen links history)
  ├── New links → email digest
  └── Save updated state.json to cache
```

### Key files

| File | Purpose |
|------|---------|
| `run_check.py` | Main pipeline — scrape, diff, email |
| `config.json` | All 191 site definitions (type, URL, selectors, filters) |
| `state.json` | Seen-links history per site (persisted via GitHub Actions cache) |
| `.github/workflows/cti-monitor.yml` | Scheduled workflow (runs every 12 hours) |

### Per-site config options (html sites)

| Field | Description |
|-------|-------------|
| `post_container` | CSS selector for each post card |
| `link_selector` | CSS selector for the link inside each card |
| `date_selector` | CSS selector for the date element (optional) |
| `link_path_prefix` | Only keep links whose path starts with this prefix |
| `path_exclude` | Drop links whose path contains any of these strings |

## Local development

```bash
pip install feedparser requests playwright
playwright install chromium

python run_check.py config.json state.json
```

Set `SMTP_USERNAME`, `SMTP_PASSWORD`, and `EMAIL_TO` as environment variables before running locally.
