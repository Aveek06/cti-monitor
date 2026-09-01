"""
Main pipeline. Run this every 24 hours (via Windows Task Scheduler).

For each site in config.json:
  - type "feed": pulls ALL entries from the RSS/Atom feed (not just the
    newest one), so multiple posts published in the same 24h window are
    all caught.
  - type "html_*": loads the listing page, finds every post card matching
    post_container, extracts a link (and date if configured) from each.
  - type "skip": ignored entirely.

State (state.json) stores every link already seen per site. Anything found
this run that ISN'T in state is new -> goes in the email digest -> gets
added to state so it's never reported twice.

Usage:
    python run_check.py config.json state.json
"""

import os
import sys
import re
import json
import smtplib
import asyncio
import feedparser
import requests
import concurrent.futures
from bs4 import BeautifulSoup
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from urllib.parse import urljoin, urlparse
from playwright.sync_api import sync_playwright

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
EMAIL_FROM = SMTP_USERNAME
EMAIL_TO = os.environ.get("EMAIL_TO", SMTP_USERNAME)
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

MAX_SEEN_PER_SITE = 2000  # cap stored history so state.json doesn't grow forever
STALE_ARTICLE_DAYS = 7   # articles older than this are suppressed from the digest email

# Matches dates embedded in URLs: /2024/05/15/ or /2024-05-15- or /blog/2024/06/10/
_URL_DATE_RE = re.compile(r'/(\d{4})[/\-](\d{2})[/\-](\d{2})(?:[/\-_.]|$)')


HAIKU_COST_PER_INPUT  = 1.0 / 1_000_000   # $1.00 per 1M input tokens
HAIKU_COST_PER_OUTPUT = 5.0 / 1_000_000   # $5.00 per 1M output tokens

# Minimum readable characters after stripping boilerplate — shorter = paywall/error page
_MIN_READABLE_CHARS = 200


def _digest_build_ioc_by_site(active_iocs):
    result = {}
    for ioc in (active_iocs or []):
        b = ioc.get("source_blog")
        if not b:
            continue
        if b not in result:
            result[b] = {"count": 0, "vt_verified": False, "has_apt": False}
        result[b]["count"] += 1
        if ioc.get("vt_verified"):
            result[b]["vt_verified"] = True
        if ioc.get("apt"):
            result[b]["has_apt"] = True
    return result


def _digest_fetch_ratings():
    db_url = os.environ.get("DATABASE_URL", "")
    if not db_url:
        return {}
    try:
        import psycopg2
        import psycopg2.extras
        conn = psycopg2.connect(db_url)
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT site_name, ROUND(AVG(rating)::numeric,1) AS avg,
                       COUNT(*)::int AS count
                FROM site_ratings GROUP BY site_name
            """)
            rows = cur.fetchall()
        conn.close()
        return {r["site_name"]: {"avg": float(r["avg"]), "count": r["count"]} for r in rows}
    except Exception as e:
        print(f"digest: could not fetch ratings: {e}")
        return {}


def _digest_compute_reliability(name, week_count, last_ts_str, is_failing, ioc_by_site, ratings):
    avail = 0
    if not is_failing:
        avail += 20
    if week_count > 0:
        avail += 15
    if last_ts_str:
        avail += 5
        try:
            last_ts = datetime.fromisoformat(last_ts_str)
            if last_ts.tzinfo is None:
                last_ts = last_ts.replace(tzinfo=timezone.utc)
            days = (datetime.now(timezone.utc) - last_ts).days
            if days > 7:
                avail = max(0, avail - (days - 7) * 2)
        except Exception:
            pass
    avail = min(40, max(0, avail))
    ioc = ioc_by_site.get(name, {"count": 0, "vt_verified": False, "has_apt": False})
    content = min(25, round((ioc["count"] / max(1, week_count)) * 25))
    if ioc.get("vt_verified"):
        content += 5
    if ioc.get("has_apt"):
        content += 5
    content = min(40, content)
    feedback = 0
    r = ratings.get(name)
    if r and r["count"] > 0:
        feedback = round(((r["avg"] - 1) / 4) * 20)
    return avail + content + feedback


def summarize_article(url, client):
    """Fetch article and return (summary, input_tokens, output_tokens). Summary is '' on skip/failure."""
    try:
        slug = url.rstrip("/").split("/")[-1].replace("-", " ").replace("_", " ")
        resp = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup(["nav", "header", "footer", "script", "style", "aside", "form"]):
            tag.decompose()
        text = soup.get_text(separator=" ", strip=True)[:4000]

        if len(text) < _MIN_READABLE_CHARS:
            print(f"  [summarize] skipped (non-readable, {len(text)} chars): {url[:70]}")
            return "", 0, 0

        msg = client.messages.create(
            model="claude-haiku-4-5",
            max_tokens=150,
            messages=[{"role": "user", "content":
                f"Title hint: {slug}\n\nContent:\n{text}\n\n"
                "Summarize this cybersecurity article in 1-2 sentences. "
                "Focus on the specific threat, technique, or finding. Be concrete and brief."}]
        )
        return msg.content[0].text.strip(), msg.usage.input_tokens, msg.usage.output_tokens
    except Exception as e:
        print(f"  [summarize] {url[:70]}: {e}")
        return "", 0, 0


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def check_feed_site(site):
    """Returns list of (link, date_str) for every entry in the feed."""
    entries = []
    try:
        timeout_s = site.get("page_timeout_ms", 15000) // 1000
        resp = requests.get(
            site["url"],
            timeout=timeout_s,
            headers={"User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")},
        )
        resp.raise_for_status()
        parsed = feedparser.parse(resp.content)
        keywords = [kw.lower() for kw in site.get("title_keywords", [])]
        excludes = site.get("path_exclude", [])
        prefixes = site.get("link_path_prefix", [])
        if isinstance(prefixes, str):
            prefixes = [prefixes]
        max_entries = site.get("max_feed_entries", 25)
        for e in parsed.entries:
            if len(entries) >= max_entries:
                break
            link = e.get("link", "")
            date_str = e.get("published", e.get("updated", ""))
            if not link:
                continue
            if excludes and any(ex in link for ex in excludes):
                continue
            if prefixes and not any(p in link for p in prefixes):
                continue
            if keywords:
                title = e.get("title", "").lower()
                if not any(kw in title for kw in keywords):
                    continue
            entries.append((link, date_str))
    except Exception as ex:
        return entries, f"feed parse error: {ex}"
    return entries, None


def _get_nested(obj, dotpath):
    """Walk a dot-separated path through dicts/lists. Returns '' on miss."""
    for key in dotpath.split("."):
        if isinstance(obj, dict):
            obj = obj.get(key, "")
        elif isinstance(obj, list):
            obj = obj[0] if obj else ""
        else:
            return ""
    return obj if obj is not None else ""


def check_api_site(site):
    """
    Fetches a JSON API endpoint (GET or POST) and extracts blog post links.
    Config fields:
      method         GET | POST (default GET)
      post_body      dict posted as JSON (POST only)
      items_path     dot-path to the list of items in the response, e.g. "result" or "results"
      link_field     dot-path inside each item to the link, e.g. "url.raw"
      link_template  Python format string using item fields, e.g. "https://site.com/{slug}"
      base_url       prepended to relative links
      date_field     dot-path inside each item to the date string
    """
    entries = []
    try:
        headers = {"User-Agent": _C4AI_UA, "Accept": "application/json"}
        method = site.get("method", "GET").upper()
        if method == "POST":
            r = requests.post(site["url"], json=site.get("post_body", {}),
                              headers=headers, timeout=15)
        else:
            r = requests.get(site["url"], headers=headers, timeout=15)
        r.raise_for_status()
        data = r.json()

        items = data
        items_path = site.get("items_path", "")
        if items_path:
            items = _get_nested(data, items_path)
        if not isinstance(items, list):
            return entries, f"{site['type']} error: items_path '{items_path}' did not resolve to a list"

        link_field = site.get("link_field", "")
        link_template = site.get("link_template", "")
        base_url = site.get("base_url", "")
        date_field = site.get("date_field", "")

        for item in items:
            if link_template:
                link = link_template.format(**item)
            elif link_field:
                raw = _get_nested(item, link_field)
                link = raw[0] if isinstance(raw, list) else str(raw)
                if base_url and link.startswith("/"):
                    link = base_url + link
            else:
                link = ""
            date_str = str(_get_nested(item, date_field)) if date_field else ""
            if link:
                entries.append((link, date_str))
    except Exception as ex:
        return entries, f"{site['type']} error: {ex}"
    return entries, None


def check_nextjs_site(site):
    """
    Fetches a Next.js page, extracts the __NEXT_DATA__ JSON blob, and
    pulls blog post links from it.
    Config fields:
      items_path   dot-path from the root of __NEXT_DATA__ to the post list
      link_field   field name inside each post item containing the URL
      base_url     prepended to relative links
      date_field   field name inside each post item for the date
    """
    entries = []
    try:
        r = requests.get(site["url"], headers={"User-Agent": _C4AI_UA}, timeout=15)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        script = soup.find("script", id="__NEXT_DATA__")
        if not script:
            return entries, f"{site['type']} error: __NEXT_DATA__ script tag not found"
        data = json.loads(script.string)

        items = _get_nested(data, site.get("items_path", ""))
        if not isinstance(items, list):
            return entries, f"{site['type']} error: items_path did not resolve to a list"

        link_field = site.get("link_field", "url")
        base_url = site.get("base_url", "")
        date_field = site.get("date_field", "")

        for item in items:
            link = item.get(link_field, "")
            if base_url and link.startswith("/"):
                link = base_url + link
            date_str = str(item.get(date_field, "")) if date_field else ""
            if link:
                entries.append((link, date_str))
    except Exception as ex:
        return entries, f"{site['type']} error: {ex}"
    return entries, None


def check_playwright_api_site(site, browser):
    """
    Loads a page with Playwright, intercepts a JSON API response by URL pattern,
    and extracts blog posts from it. For sites whose API requires browser session
    tokens that can't be replayed externally.
    Config fields:
      url                     page URL to navigate to
      intercept_url_contains  substring to identify the right API response URL
      items_path              dot-path to post list in the response JSON
      link_field              dot-path to URL inside each post item
      base_url                prepended to relative links
      date_field              dot-path to date inside each post item
      intercept_min_results   minimum result count to accept (skips early/empty responses)
      intercept_page_size     if set, rewrites resultsPerPage in outgoing POST bodies matching
                              intercept_url_contains before they are sent
    """
    entries = []
    captured_bodies = []
    try:
        context = browser.new_context(user_agent=_C4AI_UA, ignore_https_errors=True)
        page = context.new_page()
        intercept_pattern = site.get("intercept_url_contains", "")
        intercept_suffix = site.get("intercept_url_suffix", "")
        min_results = site.get("intercept_min_results", 1)
        page_size = site.get("intercept_page_size")

        if page_size and intercept_pattern:
            def rewrite_request(route):
                if route.request.method == "POST" and intercept_pattern in route.request.url:
                    try:
                        body = json.loads(route.request.post_data or "{}")
                        if "requestState" in body:
                            body["requestState"]["resultsPerPage"] = page_size
                        if "queryConfig" in body:
                            body["queryConfig"]["resultsPerPage"] = page_size
                        route.continue_(post_data=json.dumps(body))
                        return
                    except Exception:
                        pass
                route.continue_()
            page.route(f"**{intercept_pattern}**", rewrite_request)

        def on_response(response):
            if intercept_pattern and intercept_pattern not in response.url:
                return
            if intercept_suffix and not response.url.endswith(intercept_suffix):
                return
            ct = response.headers.get("content-type", "")
            if "json" not in ct:
                return
            try:
                body = response.json()
                items = _get_nested(body, site.get("items_path", ""))
                if isinstance(items, list) and len(items) >= min_results:
                    captured_bodies.append(body)
            except Exception:
                pass

        page.on("response", on_response)
        page.goto(site["url"], timeout=site.get("page_timeout_ms", 30000), wait_until="domcontentloaded")
        try:
            page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        page.wait_for_timeout(3000)
        context.close()

        if not captured_bodies:
            return entries, f"{site['type']} error: no matching API response intercepted"

        data = captured_bodies[-1]
        items = _get_nested(data, site.get("items_path", ""))
        if not isinstance(items, list):
            return entries, f"{site['type']} error: items_path did not resolve to a list"

        link_field = site.get("link_field", "")
        base_url = site.get("base_url", "")
        date_field = site.get("date_field", "")

        for item in items:
            raw = _get_nested(item, link_field)
            link = raw[0] if isinstance(raw, list) else str(raw)
            if base_url and link.startswith("/"):
                link = base_url + link
            date_raw = _get_nested(item, date_field) if date_field else ""
            date_str = date_raw[0] if isinstance(date_raw, list) else str(date_raw)
            if link:
                entries.append((link, date_str))
    except Exception as ex:
        return entries, f"{site['type']} error: {ex}"
    return entries, None


def _run_async(coro):
    """Run an async coroutine from synchronous code, always in a fresh event loop.
    Uses a worker thread so it works even when sync_playwright or another library
    has already installed a loop on the main thread."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


_C4AI_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")


def _c4ai_run_cfg(site):
    """Build a per-site CrawlerRunConfig."""
    from crawl4ai import CrawlerRunConfig, CacheMode
    default_wait_ms = 5000 if site.get("post_container") else 4000
    return CrawlerRunConfig(
        cache_mode=CacheMode.BYPASS,
        magic=True,
        simulate_user=True,
        override_navigator=True,
        page_timeout=site.get("page_timeout_ms", 30000),
        wait_until="domcontentloaded",
        delay_before_return_html=site.get("extra_wait_ms", default_wait_ms) / 1000,
        scan_full_page=True,
        scroll_delay=0.5,
    )


_C4AI_CONCURRENCY = 6  # max parallel browser tabs; more causes socket exhaustion


async def _crawl4ai_batch_fetch(sites):
    """
    Fetch all sites with bounded parallelism sharing one crawl4AI browser session.
    Returns a list of (html_string | Exception) in the same order as `sites`.
    Semaphore caps concurrent tabs at _C4AI_CONCURRENCY to avoid socket exhaustion;
    total wall-clock time ≈ ceil(N / concurrency) × avg_site_time.
    """
    from crawl4ai import AsyncWebCrawler, BrowserConfig

    browser_cfg = BrowserConfig(
        headless=True,
        browser_type="chromium",
        user_agent=_C4AI_UA,
        extra_args=["--disable-http2"],
    )
    sem = asyncio.Semaphore(_C4AI_CONCURRENCY)

    async def fetch_one(site):
        async with sem:
            try:
                result = await crawler.arun(url=site["url"], config=_c4ai_run_cfg(site))
                if result.success:
                    return result.html or ""
                return RuntimeError(result.error_message or "crawl4ai returned no content")
            except Exception as ex:
                return ex

    async with AsyncWebCrawler(config=browser_cfg) as crawler:
        results = await asyncio.gather(*[fetch_one(s) for s in sites])

    return list(results)


async def _crawl4ai_fetch(site):
    """Single-site async fetch (used by check_crawl4ai_site for standalone calls)."""
    results = await _crawl4ai_batch_fetch([site])
    result = results[0]
    if isinstance(result, Exception):
        raise result
    return result


def _parse_crawl4ai_html(site, html_or_err):
    """
    Parse pre-fetched crawl4AI HTML for one site.
    html_or_err is either an HTML string or an Exception from the fetch step.

    CSS-selector mode (post_container is set) — mirrors check_html_site:
      post_container    CSS selector for each article card/container
      link_selector     selector within each container, or "self" if container IS the link
      link_path_prefix  keep only links whose path starts with this prefix
      path_exclude      drop links containing any of these substrings
      date_selector     CSS selector for the date element inside each container

    Link-extraction mode (no post_container) — mirrors check_html_auto_site:
      link_path_prefix       string or list of path prefixes to keep
      path_exclude           substrings that disqualify a link
      min_link_depth         minimum path segment count (default 2)
      min_slug_length        last segment must be >= N chars
      require_hyphenated_slug  last segment must contain a hyphen
      min_anchor_words       anchor text must have >= N words
      max_link_occurrences   drop URLs repeated in more than N <a> tags
    """
    entries = []
    if isinstance(html_or_err, Exception):
        return entries, f"crawl4ai error: {html_or_err}"

    html = html_or_err or ""
    try:
        soup = BeautifulSoup(html, "html.parser")

        if site.get("post_container"):
            containers = soup.select(site["post_container"])
            seen_links = set()
            for c in containers:
                if site.get("link_selector") == "self":
                    link_el = c
                else:
                    link_el = c.select_one(site.get("link_selector", "a"))
                if not link_el:
                    continue
                href = link_el.get("href", "")
                if not href or href.startswith(("#", "mailto:", "javascript:")):
                    continue
                full_link = urljoin(site["url"], href)
                if site["url"].startswith("https://") and full_link.startswith("http://"):
                    full_link = "https://" + full_link[7:]
                if full_link in seen_links:
                    continue
                prefix = site.get("link_path_prefix")
                if prefix and not urlparse(full_link).path.startswith(prefix):
                    continue
                if any(excl in urlparse(full_link).path for excl in site.get("path_exclude", [])):
                    continue
                date_str = ""
                if site.get("date_selector"):
                    date_el = c.select_one(site["date_selector"])
                    if date_el:
                        date_str = (date_el.get("datetime") or date_el.get_text(strip=True) or "").strip()
                seen_links.add(full_link)
                entries.append((full_link, date_str))

        else:
            domain = urlparse(site["url"]).netloc
            prefixes = site.get("link_path_prefix", "")
            if isinstance(prefixes, str):
                prefixes = [prefixes] if prefixes else []
            excludes = site.get("path_exclude", [])
            min_depth = site.get("min_link_depth", 2)
            min_slug_len = site.get("min_slug_length")
            require_hyphen = site.get("require_hyphenated_slug", False)
            min_anchor_words = site.get("min_anchor_words")
            max_occurrences = site.get("max_link_occurrences")

            candidates = []
            url_occurrence = {}
            for tag in soup.find_all("a", href=True):
                href = tag["href"]
                if href.startswith(("#", "mailto:", "javascript:")):
                    continue
                full = urljoin(site["url"], href)
                if site["url"].startswith("https://") and full.startswith("http://"):
                    full = "https://" + full[7:]
                p2 = urlparse(full)
                if p2.netloc != domain:
                    continue
                path = p2.path
                if prefixes and not any(path.startswith(pfx) for pfx in prefixes):
                    continue
                if any(excl in path for excl in excludes):
                    continue
                parts = [x for x in path.split("/") if x]
                if len(parts) < min_depth:
                    continue
                clean = p2.scheme + "://" + p2.netloc + path
                text = tag.get_text(strip=True)
                url_occurrence[clean] = url_occurrence.get(clean, 0) + 1
                candidates.append((clean, parts, text))

            seen_links = set()
            for clean, parts, text in candidates:
                if clean in seen_links:
                    continue
                slug = parts[-1] if parts else ""
                if min_slug_len and len(slug) < min_slug_len:
                    continue
                if require_hyphen and "-" not in slug:
                    continue
                if min_anchor_words and len(text.split()) < min_anchor_words:
                    continue
                if max_occurrences and url_occurrence.get(clean, 0) > max_occurrences:
                    continue
                seen_links.add(clean)
                entries.append((clean, ""))

    except Exception as ex:
        return entries, f"crawl4ai parse error: {ex}"

    return entries, None


def check_crawl4ai_site(site):
    """Single-site wrapper for standalone/test use. Prefer the batch path in main()."""
    try:
        html = _run_async(_crawl4ai_fetch(site))
    except Exception as ex:
        return [], f"crawl4ai error: {ex}"
    return _parse_crawl4ai_html(site, html)


def check_scrapling_fetcher_site(site):
    """
    Fetches with curl_cffi TLS fingerprinting (Scrapling Fetcher).
    No browser launch — fast (~1s). Bypasses IP blocks and basic WAFs that key on
    TLS fingerprint. Parses result with _parse_crawl4ai_html (link-extraction mode).
    """
    try:
        from scrapling.fetchers import Fetcher
        timeout_s = site.get("page_timeout_ms", 20000) // 1000
        page = Fetcher.get(
            site["url"],
            stealthy_headers=True,
            timeout=timeout_s,
            impersonate="chrome124",
            follow_redirects=True,
        )
        return _parse_crawl4ai_html(site, page.html_content or "")
    except Exception as ex:
        return [], f"{site['type']} error: {ex}"


def check_scrapling_feed_site(site):
    """
    Fetches an RSS/Atom feed with curl_cffi TLS fingerprinting (Scrapling Fetcher),
    then parses the returned XML with feedparser. For sites whose feeds are
    IP-blocked or filter on TLS fingerprint.
    Supports the same title_keywords filter as check_feed_site.
    """
    try:
        from scrapling.fetchers import Fetcher
        timeout_s = site.get("page_timeout_ms", 20000) // 1000
        page = Fetcher.get(
            site["url"],
            stealthy_headers=True,
            timeout=timeout_s,
            impersonate="chrome124",
            follow_redirects=True,
        )
        parsed = feedparser.parse(page.body or b"")
        keywords = [kw.lower() for kw in site.get("title_keywords", [])]
        excludes = site.get("path_exclude", [])
        prefixes = site.get("link_path_prefix", [])
        if isinstance(prefixes, str):
            prefixes = [prefixes]
        max_entries = site.get("max_feed_entries", 25)
        entries = []
        for e in parsed.entries:
            if len(entries) >= max_entries:
                break
            link = e.get("link", "")
            date_str = e.get("published", e.get("updated", ""))
            if not link:
                continue
            if excludes and any(ex in link for ex in excludes):
                continue
            if prefixes and not any(p in link for p in prefixes):
                continue
            if keywords:
                title = e.get("title", "").lower()
                if not any(kw in title for kw in keywords):
                    continue
            entries.append((link, date_str))
        return entries, None
    except Exception as ex:
        return [], f"{site['type']} error: {ex}"


def check_scrapling_stealthy_site(site):
    """
    Fetches with patchright stealth browser (Scrapling StealthyFetcher).
    Full browser, ~30-45s. Bypasses WAF JS challenges that block standard Playwright.
    Runs in a worker thread so patchright's sync API doesn't conflict with any
    asyncio event loop installed by crawl4ai earlier in the same run.
    """
    def _fetch():
        from scrapling.fetchers import StealthyFetcher
        timeout_ms = site.get("page_timeout_ms", 40000)
        extra = {}
        if site.get("wait_selector"):
            extra["wait_selector"] = site["wait_selector"]
        if site.get("network_idle"):
            extra["network_idle"] = True
        page = StealthyFetcher.fetch(
            site["url"],
            headless=True,
            block_webrtc=True,
            hide_canvas=True,
            timeout=timeout_ms,
            **extra,
        )
        return _parse_crawl4ai_html(site, page.html_content or "")
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(_fetch).result()
    except Exception as ex:
        return [], f"{site['type']} error: {ex}"


def check_html_auto_site(site, browser):
    """
    Generic link extractor (no CSS selector needed). Loads the page, collects all
    same-domain <a> links, filters by link_path_prefix and path_exclude, then
    returns the deduplicated set. Works by link-set diffing: first run seeds all
    found links silently; only genuinely new URLs surface in later digests.

    Config fields (all optional):
      link_path_prefix       string or list — only keep links whose path starts with one
      path_exclude           list of strings — drop links whose path contains any of these
      min_link_depth         minimum path-segment count (default 2)
      extra_wait_ms          extra wait after networkidle for JS-heavy SPAs (default 3000)
      min_slug_length        last path segment must be >= N chars (drops index/archive pages)
      require_hyphenated_slug  last segment must contain a hyphen (drops short nav slugs)
      min_anchor_words       visible link text must have >= N words (drops icon/button links)
      max_link_occurrences   drop URLs that appear in more than N <a> tags (nav/footer links
                             are repeated across header+footer+mobile-menu; article links
                             typically appear once)
    """
    entries = []
    try:
        context = browser.new_context(user_agent=_C4AI_UA, ignore_https_errors=True)
        page = context.new_page()
        page.goto(site["url"], timeout=site.get("page_timeout_ms", 30000), wait_until="domcontentloaded")
        try:
            page.wait_for_load_state("networkidle", timeout=10000)
        except Exception:
            pass
        page.wait_for_timeout(site.get("extra_wait_ms", 3000))

        domain = urlparse(site["url"]).netloc
        prefixes = site.get("link_path_prefix", "")
        if isinstance(prefixes, str):
            prefixes = [prefixes] if prefixes else []
        excludes = site.get("path_exclude", [])
        min_depth = site.get("min_link_depth", 2)
        min_slug_len = site.get("min_slug_length")
        require_hyphen = site.get("require_hyphenated_slug", False)
        min_anchor_words = site.get("min_anchor_words")
        max_occurrences = site.get("max_link_occurrences")

        # First pass: collect candidates and count occurrences per URL
        candidates = []
        url_occurrence = {}
        for a in page.query_selector_all("a"):
            href = a.get_attribute("href") or ""
            if not href or href.startswith(("#", "mailto:", "javascript:")):
                continue
            full = urljoin(site["url"], href)
            p2 = urlparse(full)
            if p2.netloc != domain:
                continue
            path = p2.path
            if prefixes and not any(path.startswith(pfx) for pfx in prefixes):
                continue
            if any(excl in path for excl in excludes):
                continue
            parts = [x for x in path.split("/") if x]
            if len(parts) < min_depth:
                continue
            clean = p2.scheme + "://" + p2.netloc + path
            text = (a.inner_text() or "").strip()
            url_occurrence[clean] = url_occurrence.get(clean, 0) + 1
            candidates.append((clean, parts, text))

        page_date = _extract_date_from_soup(BeautifulSoup(page.content(), "html.parser"))

        # Second pass: apply per-link filters and deduplicate
        seen_links = set()
        for clean, parts, text in candidates:
            if clean in seen_links:
                continue
            slug = parts[-1] if parts else ""
            if min_slug_len and len(slug) < min_slug_len:
                continue
            if require_hyphen and "-" not in slug:
                continue
            if min_anchor_words and len(text.split()) < min_anchor_words:
                continue
            if max_occurrences and url_occurrence.get(clean, 0) > max_occurrences:
                continue
            seen_links.add(clean)
            entries.append((clean, page_date))

        context.close()
    except Exception as ex:
        return entries, f"{site['type']} error: {ex}"
    return entries, None


def wait_for_stable_post_count(page, selector, max_wait_ms=15000, poll_interval_ms=500):
    """Poll selector count every poll_interval_ms; return once count is stable
    on two consecutive polls or max_wait_ms has elapsed."""
    deadline = page.evaluate("Date.now()") + max_wait_ms
    prev_count = -1
    while True:
        count = len(page.query_selector_all(selector))
        if count == prev_count:
            return
        prev_count = count
        remaining = deadline - page.evaluate("Date.now()")
        if remaining <= 0:
            return
        page.wait_for_timeout(min(poll_interval_ms, remaining))


def check_html_site(site, browser):
    """Returns list of (link, date_str) for every post card found on the page."""
    entries = []
    try:
        context = browser.new_context(user_agent=_C4AI_UA, ignore_https_errors=True)
        page = context.new_page()
        page.goto(site["url"], timeout=site.get("page_timeout_ms", 30000), wait_until="domcontentloaded")
        try:
            page.wait_for_selector(site["post_container"], timeout=site.get("page_timeout_ms", 30000))
        except Exception:
            context.close()
            return entries, None
        wait_for_stable_post_count(page, site["post_container"])

        page_soup = BeautifulSoup(page.content(), "html.parser")
        page_date = _extract_date_from_soup(page_soup)

        containers = page.query_selector_all(site["post_container"])
        for c in containers:
            link_el = c if site.get("link_selector") == "self" else c.query_selector(site.get("link_selector", "a"))
            if not link_el:
                continue
            href = link_el.get_attribute("href")
            if not href:
                continue
            full_link = urljoin(site["url"], href)

            prefix = site.get("link_path_prefix")
            if prefix and not urlparse(full_link).path.startswith(prefix):
                continue

            if any(excl in urlparse(full_link).path for excl in site.get("path_exclude", [])):
                continue

            date_str = ""
            if site.get("date_selector"):
                date_el = c.query_selector(site["date_selector"])
                if date_el:
                    date_str = (date_el.get_attribute("datetime") or date_el.inner_text() or "").strip()
            if not date_str:
                date_str = _extract_date_from_soup(BeautifulSoup(c.inner_html(), "html.parser")) or page_date

            entries.append((full_link, date_str))

        context.close()
    except Exception as ex:
        return entries, f"{site['type']} error: {ex}"
    return entries, None


_POST_DATE_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                 "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# Regex patterns for dates visible as rendered text in markdown
_DATE_REGEXES = [
    re.compile(r'\b(\d{4}-\d{2}-\d{2})\b'),
    re.compile(r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4}\b', re.I),
    re.compile(r'\b\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4}\b', re.I),
    re.compile(r'\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b', re.I),
]


def _extract_date_from_soup(soup):
    """Check JSON-LD, OG meta, and <time> in a BeautifulSoup tree."""
    for script in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(script.string or "{}")
            if isinstance(data, list):
                data = data[0] if data else {}
            for key in ("datePublished", "dateCreated"):
                if data.get(key):
                    return str(data[key])
        except Exception:
            pass
    for prop in ("article:published_time", "og:published_time",
                 "article:modified_time", "date", "pubdate"):
        meta = (soup.find("meta", property=prop)
                or soup.find("meta", attrs={"name": prop}))
        if meta and meta.get("content"):
            return meta["content"]
    t = soup.find("time", attrs={"datetime": True})
    if t and t.get("datetime"):
        return t["datetime"]
    return ""


def _extract_date_from_markdown(markdown):
    """Regex-scan crawl4AI markdown for the first date-like string."""
    for pattern in _DATE_REGEXES:
        m = pattern.search(markdown)
        if m:
            return m.group(0)
    return ""


async def _fetch_date_crawl4ai_async(link):
    """Fetch a post page with crawl4AI (JS-rendered) and extract its date."""
    from crawl4ai import AsyncWebCrawler, BrowserConfig, CrawlerRunConfig, CacheMode
    browser_cfg = BrowserConfig(
        headless=True, browser_type="chromium",
        user_agent=_POST_DATE_UA, extra_args=["--disable-http2"],
    )
    run_cfg = CrawlerRunConfig(
        cache_mode=CacheMode.BYPASS, magic=True, simulate_user=True,
        override_navigator=True, page_timeout=25000,
        wait_until="domcontentloaded", delay_before_return_html=4.0,
    )
    try:
        async with AsyncWebCrawler(config=browser_cfg) as crawler:
            result = await crawler.arun(url=link, config=run_cfg)
        if not result.success:
            return ""
        # htmldate with extensive_search on JS-rendered HTML (slower path, worth it here)
        try:
            from htmldate import find_date as _hd_find
            date = _hd_find(result.html or "", original_date=True, extensive_search=True,
                            outputformat="%Y-%m-%d")
        except Exception:
            date = _extract_date_from_soup(BeautifulSoup(result.html or "", "html.parser"))
        if date:
            return date
        # Last resort: regex scan of the crawl4ai markdown text
        return _extract_date_from_markdown(result.markdown or "")
    except Exception:
        return ""


def fetch_post_date(link):
    """
    Extract the publish date of an individual post page. Called only for new
    links where the scraper returned no date (typically 0-5 per run).

    Three-tier strategy:
      0. URL pattern (instant): many security blog URLs embed the date
         (e.g. /2024/05/15/). Free, no network call.
      1. requests (fast, ~1s): checks JSON-LD, OG meta, <time datetime>
         in static HTML — works when date metadata is server-rendered.
      2. crawl4AI fallback (~15s): fetches the fully JS-rendered page and
         checks the same structured sources plus regex-scans the markdown
         text — catches dates injected by JavaScript (Intezer, Forescout,
         Akamai, StrongestLayer).
    """
    # Tier 0: URL-embedded date — instant, no network
    m = _URL_DATE_RE.search(link)
    if m:
        y, mo, d = m.group(1), m.group(2), m.group(3)
        try:
            datetime(int(y), int(mo), int(d))
            return f"{y}-{mo}-{d}"
        except ValueError:
            pass

    # Tier 1: fast static fetch + htmldate full-page scan
    try:
        r = requests.get(link, headers={"User-Agent": _POST_DATE_UA},
                         timeout=10, allow_redirects=True)
        try:
            from htmldate import find_date as _hd_find
            date = _hd_find(r.text, original_date=True, extensive_search=False,
                            outputformat="%Y-%m-%d")
        except Exception:
            date = _extract_date_from_soup(BeautifulSoup(r.text, "html.parser"))
        if date:
            return date
    except Exception:
        pass

    # Tier 2: crawl4AI JS-rendered fallback
    try:
        return _run_async(_fetch_date_crawl4ai_async(link))
    except Exception:
        pass
    return ""


def normalize_date(date_str):
    """Best-effort parse; falls back to 'detected today' if it can't be parsed."""
    if not date_str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d"), "detected"
    if isinstance(date_str, (int, float)):
        try:
            return datetime.fromtimestamp(date_str, tz=timezone.utc).strftime("%Y-%m-%d"), "parsed"
        except Exception:
            return datetime.now(timezone.utc).strftime("%Y-%m-%d"), "detected"
    s = date_str.strip()
    # Normalise ISO 8601 Z suffix so fromisoformat() handles it on all Python versions
    iso = s.replace("Z", "+00:00")
    # Strip milliseconds if present (e.g. .000 or .380) before trying strptime patterns
    iso_no_ms = re.sub(r"\.\d+(\+)", r"\1", iso)
    for candidate in (iso, iso_no_ms, s):
        try:
            dt = datetime.fromisoformat(candidate)
            return dt.strftime("%Y-%m-%d"), "published"
        except ValueError:
            pass
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                "%B %d, %Y", "%b %d, %Y", "%d %B %Y", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.strftime("%Y-%m-%d"), "published"
        except ValueError:
            continue
    return datetime.now(timezone.utc).strftime("%Y-%m-%d"), "detected"


def send_digest_email(new_items, failures, duplicate_links=None, ai_run_cost=0.0, ioc_results=None, ai_status="",
                      last_active=None, config_sites=None):
    rows_html = ""
    for item in new_items:
        summary_html = (f"<br><span style='color:#888;font-size:11px;font-style:italic'>"
                        f"{item['summary']}</span>" if item.get("summary") else "")
        rows_html += (f"<tr><td>{item['date']}</td><td>{item['date_source']}</td>"
                       f"<td><a href='{item['link']}'>{item['link']}</a>{summary_html}</td>"
                       f"<td>{item['site']}</td></tr>")

    failures_html = ""
    if failures:
        failure_rows = "".join(f"<li>{f}</li>" for f in failures)
        failures_html = f"<h3>Sites that failed this run</h3><ul>{failure_rows}</ul>"

    duplicates_html = ""
    if duplicate_links:
        dup_rows = "".join(
            f"<li><a href='{d['link']}'>{d['link']}</a> — {d['site']}</li>"
            for d in duplicate_links
        )
        duplicates_html = (
            f"<h3 style='color:red'>⚠ Links repeated from previous run ({len(duplicate_links)})</h3>"
            f"<p>These links appeared as new in both this run and the previous run, "
            f"which may indicate a state-persistence bug.</p><ul>{dup_rows}</ul>"
        )

    if not new_items:
        body_html = "<p>No new blog posts were observed in this run.</p>"
    else:
        body_html = f"""
        <table border="1" cellpadding="6" cellspacing="0">
          <tr><th>Date</th><th>Date Source</th><th>Link</th><th>Parent Website</th></tr>
          {rows_html}
        </table>
        """

    ioc_html = ""
    if ioc_results:
        def _ioc_table(rows, cap=20):
            if not rows:
                return "<p style='color:#888;font-size:12px'>None.</p>"
            shown = rows[:cap]
            trs = "".join(
                f"<tr><td style='font-family:monospace;font-size:11px'>{r['value'][:60]}</td>"
                f"<td>{r['type']}</td>"
                f"<td>{r.get('attributed_apt') or '—'}</td>"
                f"<td>{r.get('score', '—')}</td></tr>"
                for r in shown
            )
            more = f"<p style='color:#888;font-size:11px'>… and {len(rows)-cap} more</p>" if len(rows) > cap else ""
            return (
                "<table border='1' cellpadding='4' cellspacing='0' style='font-size:12px'>"
                "<tr><th>Indicator</th><th>Type</th><th>APT</th><th>Score</th></tr>"
                f"{trs}</table>{more}"
            )
        ioc_html = (
            f"<hr><h3>IOC Extraction — This Run</h3>"
            f"<h4>New ({len(ioc_results['new'])})</h4>{_ioc_table(ioc_results['new'])}"
            f"<h4>Active — Score &ge; 30 ({len(ioc_results['active'])})</h4>{_ioc_table(ioc_results['active'])}"
            f"<h4>Expiring — Score &lt; 30 ({len(ioc_results['expiring'])})</h4>{_ioc_table(ioc_results['expiring'])}"
        )

    ai_cost_html = (
        f"<p style='color:#888;font-size:11px;margin-top:24px;"
        f"border-top:1px solid #eee;padding-top:8px'>"
        f"AI (Claude Haiku 4.5): {ai_status or 'no status'}</p>"
    )

    # Site reliability snapshot
    rel_html = ""
    if last_active and config_sites:
        try:
            la = last_active if isinstance(last_active, dict) else {}
            failing_set = set(la.get("_currently_failing", []))
            seven_day   = la.get("_seven_day_counts", {})
            cutoff      = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
            ioc_by_site = _digest_build_ioc_by_site((ioc_results or {}).get("active", []))
            ratings     = _digest_fetch_ratings()

            # show sites that posted this run + failing sites
            relevant = {item["site"] for item in new_items}
            for f in failures:
                name = f.split(":")[0].strip()
                relevant.add(name)

            rows_rel = ""
            for site in config_sites:
                name = site.get("name", "")
                if name not in relevant:
                    continue
                counts     = seven_day.get(name, {})
                week_count = sum(v for k, v in counts.items() if k >= cutoff)
                is_failing = name in failing_set
                score      = _digest_compute_reliability(name, week_count, la.get(name), is_failing, ioc_by_site, ratings)
                if score >= 70:
                    col, bg, bd = "#1a7f37", "#d4f7dc", "#82e09a"
                elif score >= 40:
                    col, bg, bd = "#9a5c00", "#fff3cd", "#ffc107"
                else:
                    col, bg, bd = "#b91c1c", "#fee2e2", "#f87171"
                status_str = "Failing" if is_failing else f"{week_count} links/7d"
                rows_rel += (
                    f"<tr>"
                    f"<td style='padding:6px 12px;border-bottom:1px solid #eee;font-size:12px'>{name}</td>"
                    f"<td style='padding:6px 12px;border-bottom:1px solid #eee;font-size:11px;color:#888'>{status_str}</td>"
                    f"<td style='padding:6px 12px;border-bottom:1px solid #eee;text-align:center'>"
                    f"<span style='font-family:monospace;font-size:12px;font-weight:700;"
                    f"color:{col};background:{bg};border:1px solid {bd};"
                    f"border-radius:3px;padding:2px 8px'>{score}</span>"
                    f"<span style='font-size:10px;color:#aaa;margin-left:3px'>/100</span></td>"
                    f"</tr>"
                )
            if rows_rel:
                rel_html = (
                    f"<hr><h3 style='font-size:13px;margin-bottom:8px'>Source Reliability — This Run</h3>"
                    f"<table border='0' cellpadding='0' cellspacing='0' style='font-size:12px;border-collapse:collapse;border:1px solid #eee'>"
                    f"<tr style='background:#f5f5f5'>"
                    f"<th style='padding:6px 12px;text-align:left;font-size:11px;border-bottom:1px solid #ddd'>Site</th>"
                    f"<th style='padding:6px 12px;text-align:left;font-size:11px;border-bottom:1px solid #ddd'>Activity</th>"
                    f"<th style='padding:6px 12px;text-align:center;font-size:11px;border-bottom:1px solid #ddd'>Score</th>"
                    f"</tr>{rows_rel}</table>"
                    f"<p style='color:#aaa;font-size:10px;margin-top:4px'>Availability (0-40) + Content Quality (0-40) + Analyst Feedback (0-20)</p>"
                )
        except Exception as e:
            print(f"digest: reliability section failed: {e}")

    html = f"""
    <html><body>
    <h2>CTI Source Monitor - New Posts ({len(new_items)})</h2>
    {body_html}
    {failures_html}
    {duplicates_html}
    {ioc_html}
    {rel_html}
    {ai_cost_html}
    </body></html>
    """

    recipients = [r for r in re.split(r'[,\s]+', EMAIL_TO.strip()) if r]

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"CTI Monitor: {len(new_items)} new post(s) - {datetime.now().strftime('%Y-%m-%d')}"
    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, recipients, msg.as_string())
        print(f"Email sent: {len(new_items)} new post(s), {len(failures)} failure(s).")
    except Exception as e:
        print(f"Email failed to send (state.json already saved): {e}")
        raise


def main(config_path, state_path, last_active_path="last_active.json", prev_links_path="prev_run_links.json"):
    config = load_json(config_path, {"sites": []})

    seen_names = set()
    dupes = [s["name"] for s in config["sites"] if s["name"] in seen_names or seen_names.add(s["name"])]
    if dupes:
        raise ValueError(f"Duplicate site names in config (fix before running): {dupes}")

    state = load_json(state_path, {})
    raw_prev = load_json(prev_links_path, [])
    if raw_prev and isinstance(raw_prev[0], dict):
        prev_run_links = set(item["url"] for item in raw_prev)
    else:
        prev_run_links = set(raw_prev)

    last_active = load_json(last_active_path, {})
    now_iso = datetime.now(timezone.utc).isoformat()
    for site_name in state:
        if site_name not in last_active:
            last_active[site_name] = now_iso

    new_items = []
    failures = []
    failing_names = []

    # ── Phase 1: Parallel / batch fetch ──────────────────────────────────────
    # Sites are grouped by execution model so we can maximise concurrency
    # without hitting thread-safety limits.
    _PARALLEL_HTTP = {
        "feed", "api", "nextjs",
        "scrapling_fetcher", "scrapling_feed", "scrapling_stealthy",
    }
    _BROWSER_TYPES = {"playwright_api", "html_auto", "html"}

    active_sites  = [s for s in config["sites"] if s["type"] not in ("skip", "html_TODO")]
    http_batch    = [s for s in active_sites if s["type"] in _PARALLEL_HTTP]
    c4ai_batch    = [s for s in active_sites if s["type"] == "crawl4ai"]
    browser_batch = [s for s in active_sites if s["type"] in _BROWSER_TYPES]

    site_results: dict[str, tuple] = {}  # name -> (entries, err)

    def _call_http(site):
        t = site["type"]
        try:
            if t == "feed":               return check_feed_site(site)
            if t == "api":                return check_api_site(site)
            if t == "nextjs":             return check_nextjs_site(site)
            if t == "scrapling_fetcher":  return check_scrapling_fetcher_site(site)
            if t == "scrapling_feed":     return check_scrapling_feed_site(site)
            if t == "scrapling_stealthy": return check_scrapling_stealthy_site(site)
        except Exception as ex:
            return [], str(ex)

    # HTTP-only sites: up to 15 run in parallel (thread-safe, no shared state)
    print(f"Fetching {len(http_batch)} HTTP sites in parallel, "
          f"{len(c4ai_batch)} crawl4ai in batch, "
          f"{len(browser_batch)} browser sites sequentially…")
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as pool:
        futs = {pool.submit(_call_http, s): s for s in http_batch}
        for fut in concurrent.futures.as_completed(futs):
            s = futs[fut]
            try:
                site_results[s["name"]] = fut.result() or ([], "no result")
            except Exception as ex:
                site_results[s["name"]] = ([], str(ex))

    # crawl4ai sites: one async batch (6 concurrent tabs, single browser session)
    if c4ai_batch:
        htmls = _run_async(_crawl4ai_batch_fetch(c4ai_batch))
        for s, h in zip(c4ai_batch, htmls):
            site_results[s["name"]] = _parse_crawl4ai_html(s, h)

    # Browser-rendered sites: sequential (Playwright browser is not thread-safe)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--disable-http2"])
        for s in browser_batch:
            t = s["type"]
            try:
                if t == "playwright_api": site_results[s["name"]] = check_playwright_api_site(s, browser)
                elif t == "html_auto":    site_results[s["name"]] = check_html_auto_site(s, browser)
                else:                     site_results[s["name"]] = check_html_site(s, browser)
            except Exception as ex:
                site_results[s["name"]] = ([], str(ex))
        browser.close()

    # ── Phase 2: Sequential state processing (logic unchanged) ───────────────
    for site in config["sites"]:
        name = site["name"]
        if site["type"] == "skip":
            continue
        if site["type"] == "html_TODO":
            failures.append(f"{name}: config not filled in yet, skipping")
            continue

        entries, err = site_results.get(name, ([], "not processed"))

        if err:
            failures.append(f"{name}: {err}")
            failing_names.append(name)
            print(f"  [{site['type'].upper()}] {name} ... FAIL")
            continue

        is_first_run_for_site = name not in state
        old_order = state.get(name, [])
        seen = set(old_order)
        new_links = [(link, date_str) for link, date_str in entries if link not in seen]

        if is_first_run_for_site:
            # First time we've ever checked this site: just seed state with
            # everything found. Reporting all of it as "new" would flood the
            # digest (some feeds return hundreds of historical entries).
            # Only genuinely new posts on later runs get emailed.
            last_active[name] = now_iso
            print(f"  [{site['type'].upper()}] {name} ... seeding {len(new_links)} (not emailed)")
        else:
            # Flood guard: if apparent-new links >= current state size (and state
            # isn't trivially small), it almost certainly means a cache reset or
            # full-page re-scrape, not real activity. Re-seed silently.
            if len(new_links) >= len(old_order) >= 5:
                last_active[name] = now_iso
                state[name] = [link for link, _ in entries][:MAX_SEEN_PER_SITE]
                print(f"  [{site['type'].upper()}] {name} ... flood guard: {len(new_links)} apparent-new >= {len(old_order)} in state, re-seeding silently")
                continue
            if new_links:
                last_active[name] = now_iso
            for link, date_str in new_links:
                if not date_str:
                    date_str = fetch_post_date(link)
                date_norm, date_source = normalize_date(date_str)
                new_items.append({
                    "site": name, "link": link,
                    "date": date_norm, "date_source": date_source,
                })

        # newest entries go to the front, old order is preserved untouched behind them,
        # only the tail (oldest) gets trimmed if the list grows past the cap
        updated_order = [link for link, _ in new_links] + old_order
        state[name] = updated_order[:MAX_SEEN_PER_SITE]
        if not is_first_run_for_site:
            print(f"{name}: {len(new_links)} new / {len(updated_order)} total")

    save_json(state_path, state)

    # Update rolling 7-day link counts per site (stored in last_active for weekly report)
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    cutoff_str = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
    seven_day = last_active.setdefault("_seven_day_counts", {})
    for item in new_items:
        site_day = seven_day.setdefault(item["site"], {})
        site_day[today_str] = site_day.get(today_str, 0) + 1
    for site_day in seven_day.values():
        for old_date in [d for d in list(site_day) if d < cutoff_str]:
            del site_day[old_date]

    last_active["_currently_failing"] = failing_names
    save_json(last_active_path, last_active)

    # Compare with previous run — any link appearing as new in both runs is a state bug
    duplicate_links = [item for item in new_items if item["link"] in prev_run_links]
    if duplicate_links:
        print(f"WARNING: {len(duplicate_links)} link(s) also appeared as new in the previous run:")
        for d in duplicate_links:
            print(f"  [{d['site']}] {d['link']}")

    # Filter articles older than STALE_ARTICLE_DAYS from the digest.
    # State is already saved above, so stale articles are still deduped going forward.
    # For "detected" items (page gave no date): do one last URL-pattern check so that
    # articles from URLs like /2024/05/15/ are still suppressed even when the page
    # itself has no parseable date metadata.
    stale_threshold = (datetime.now(timezone.utc) - timedelta(days=STALE_ARTICLE_DAYS)).strftime("%Y-%m-%d")
    fresh_items, stale_items = [], []
    for item in new_items:
        if item["date_source"] == "detected":
            m = _URL_DATE_RE.search(item["link"])
            if m:
                y, mo, d = m.group(1), m.group(2), m.group(3)
                try:
                    datetime(int(y), int(mo), int(d))
                    item["date"] = f"{y}-{mo}-{d}"
                    item["date_source"] = "url_parsed"
                except ValueError:
                    pass
        if item["date_source"] != "detected" and item["date"] < stale_threshold:
            stale_items.append(item)
        else:
            fresh_items.append(item)
    if stale_items:
        print(f"Suppressed {len(stale_items)} stale article(s) older than {STALE_ARTICLE_DAYS} days (still added to state):")
        for item in stale_items:
            print(f"  [{item['site']}] {item['date']} {item['link']}")

    # Summarise fresh articles via Claude Haiku, tracking token usage for cost reporting
    ai_run_cost = 0.0
    ai_status   = ""
    if not ANTHROPIC_API_KEY:
        ai_status = "disabled — ANTHROPIC_API_KEY not configured"
        print("AI summarisation: ANTHROPIC_API_KEY not set, skipping.")
    elif not fresh_items:
        ai_status = "no new articles this run"
    else:
        try:
            import anthropic as _anthropic
            _ai = _anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            print(f"Summarising {len(fresh_items)} article(s)...")
            total_input_tokens = 0
            total_output_tokens = 0
            for item in fresh_items:
                summary, inp, out = summarize_article(item["link"], _ai)
                item["summary"] = summary
                total_input_tokens += inp
                total_output_tokens += out
            ai_run_cost = (total_input_tokens * HAIKU_COST_PER_INPUT +
                           total_output_tokens * HAIKU_COST_PER_OUTPUT)
            ai_status = (f"{len(fresh_items)} article(s) summarised — "
                         f"{total_input_tokens} in + {total_output_tokens} out tokens = "
                         f"${ai_run_cost:.4f}")
            print(f"AI cost this run: {total_input_tokens} input + {total_output_tokens} output tokens = ${ai_run_cost:.6f}")
            # Accumulate daily AI cost in last_active for the weekly report
            ai_cost_by_day = last_active.setdefault("_ai_cost", {})
            ai_cost_by_day[today_str] = round(ai_cost_by_day.get(today_str, 0.0) + ai_run_cost, 8)
            for old_date in [d for d in list(ai_cost_by_day) if d < cutoff_str]:
                del ai_cost_by_day[old_date]
            save_json(last_active_path, last_active)
        except Exception as e:
            ai_status = f"error — {e}"
            print(f"Summarisation skipped: {e}")

    # Save enriched prev_run_links (URL + summary + metadata) for dashboard
    save_json(prev_links_path, [
        {"url": item["link"], "site": item["site"], "date": item["date"],
         "summary": item.get("summary", "")}
        for item in new_items
    ])

    # Run IOC extraction pipeline: always run so DB export is written even on quiet runs
    ioc_results = {"new": [], "active": [], "expiring": []}
    try:
        from ioc_pipeline import run as run_ioc_pipeline
        # Build per-site reliability lookup so pipeline can weight LTV
        _rel_lookup = {}
        try:
            _rel_ratings   = _digest_fetch_ratings()
            _rel_ioc_by    = _digest_build_ioc_by_site([])
            _rel_failing   = set(last_active.get("_currently_failing", []))
            _rel_seven_day = last_active.get("_seven_day_counts", {})
            _rel_cutoff    = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
            for _site_cfg in config.get("sites", []):
                _sn = _site_cfg["name"]
                _wk = sum(v for k, v in _rel_seven_day.get(_sn, {}).items() if k >= _rel_cutoff)
                _rel_lookup[_sn] = _digest_compute_reliability(_sn, _wk, last_active.get(_sn), _sn in _rel_failing, _rel_ioc_by, _rel_ratings)
        except Exception as _re:
            print(f"Reliability lookup build failed: {_re}")
        ioc_results = run_ioc_pipeline(fresh_items, rel_lookup=_rel_lookup)
        # Persist snapshot for degradation detection in weekly digest
        snap = ioc_results.get("rel_snapshot") or _rel_lookup
        if snap:
            last_active["_reliability_snapshot"] = snap
            save_json(last_active_path, last_active)
    except Exception as e:
        print(f"IOC pipeline skipped: {e}")

    print(f"Run complete: {len(fresh_items)} new post(s) in digest ({len(stale_items)} stale suppressed), {len(failures)} site(s) failed.")
    send_digest_email(fresh_items, failures, duplicate_links or None, ai_run_cost, ioc_results, ai_status,
                      last_active=last_active, config_sites=config["sites"])


if __name__ == "__main__":
    cfg = sys.argv[1] if len(sys.argv) > 1 else "config.json"
    st  = sys.argv[2] if len(sys.argv) > 2 else "state.json"
    la  = sys.argv[3] if len(sys.argv) > 3 else "last_active.json"
    pl  = sys.argv[4] if len(sys.argv) > 4 else "prev_run_links.json"
    main(cfg, st, la, pl)
