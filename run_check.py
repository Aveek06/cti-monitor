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
from bs4 import BeautifulSoup
from datetime import datetime, timezone
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

MAX_SEEN_PER_SITE = 2000  # cap stored history so state.json doesn't grow forever


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def check_feed_site(site):
    """Returns list of (link, date_str) for every entry in the feed."""
    entries = []
    try:
        parsed = feedparser.parse(site["url"], request_headers={
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
        })
        keywords = [kw.lower() for kw in site.get("title_keywords", [])]
        for e in parsed.entries:
            link = e.get("link", "")
            date_str = e.get("published", e.get("updated", ""))
            if not link:
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
        ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
        headers = {"User-Agent": ua, "Accept": "application/json"}
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
            return entries, f"api error: items_path '{items_path}' did not resolve to a list"

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
        return entries, f"api error: {ex}"
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
        ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
        r = requests.get(site["url"], headers={"User-Agent": ua}, timeout=15)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        script = soup.find("script", id="__NEXT_DATA__")
        if not script:
            return entries, "nextjs error: __NEXT_DATA__ script tag not found"
        data = json.loads(script.string)

        items = _get_nested(data, site.get("items_path", ""))
        if not isinstance(items, list):
            return entries, f"nextjs error: items_path did not resolve to a list"

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
        return entries, f"nextjs error: {ex}"
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
        context = browser.new_context(
            user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
            ignore_https_errors=True,
        )
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
        page.goto(site["url"], timeout=30000, wait_until="domcontentloaded")
        try:
            page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        page.wait_for_timeout(3000)
        context.close()

        if not captured_bodies:
            return entries, "playwright_api error: no matching API response intercepted"

        data = captured_bodies[-1]
        items = _get_nested(data, site.get("items_path", ""))
        if not isinstance(items, list):
            return entries, "playwright_api error: items_path did not resolve to a list"

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
        return entries, f"playwright_api error: {ex}"
    return entries, None


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
        html = asyncio.run(_crawl4ai_fetch(site))
    except Exception as ex:
        return [], f"crawl4ai error: {ex}"
    return _parse_crawl4ai_html(site, html)


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
        context = browser.new_context(
            user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
            ignore_https_errors=True,
        )
        page = context.new_page()
        page.goto(site["url"], timeout=30000, wait_until="domcontentloaded")
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
            entries.append((clean, ""))

        context.close()
    except Exception as ex:
        return entries, f"html_auto error: {ex}"
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
        context = browser.new_context(
            user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
            ignore_https_errors=True,
        )
        page = context.new_page()
        page.goto(site["url"], timeout=30000, wait_until="domcontentloaded")
        wait_for_stable_post_count(page, site["post_container"])

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

            entries.append((full_link, date_str))

        context.close()
    except Exception as ex:
        return entries, f"scrape error: {ex}"
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
        # Try structured metadata in JS-rendered HTML first
        date = _extract_date_from_soup(BeautifulSoup(result.html or "", "html.parser"))
        if date:
            return date
        # Fall back to regex scan of the markdown text
        return _extract_date_from_markdown(result.markdown or "")
    except Exception:
        return ""


def fetch_post_date(link):
    """
    Extract the publish date of an individual post page. Called only for new
    links where the scraper returned no date (typically 0-5 per run).

    Two-tier strategy:
      1. requests (fast, ~1s): checks JSON-LD, OG meta, <time datetime>
         in static HTML — works when date metadata is server-rendered.
      2. crawl4AI fallback (~15s): fetches the fully JS-rendered page and
         checks the same structured sources plus regex-scans the markdown
         text — catches dates injected by JavaScript (Intezer, Forescout,
         Akamai, StrongestLayer).
    """
    # Tier 1: fast static fetch
    try:
        r = requests.get(link, headers={"User-Agent": _POST_DATE_UA},
                         timeout=10, allow_redirects=True)
        date = _extract_date_from_soup(BeautifulSoup(r.text, "html.parser"))
        if date:
            return date
    except Exception:
        pass

    # Tier 2: crawl4AI JS-rendered fallback
    try:
        return asyncio.run(_fetch_date_crawl4ai_async(link))
    except Exception:
        pass
    return ""


def normalize_date(date_str):
    """Best-effort parse; falls back to 'detected today' if it can't be parsed."""
    if not date_str:
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


def send_digest_email(new_items, failures):
    rows_html = ""
    for item in new_items:
        rows_html += (f"<tr><td>{item['date']}</td><td>{item['date_source']}</td>"
                       f"<td><a href='{item['link']}'>{item['link']}</a></td>"
                       f"<td>{item['site']}</td></tr>")

    failures_html = ""
    if failures:
        failure_rows = "".join(f"<li>{f}</li>" for f in failures)
        failures_html = f"<h3>Sites that failed this run</h3><ul>{failure_rows}</ul>"

    if not new_items:
        body_html = "<p>No new blog posts were observed in this run.</p>"
    else:
        body_html = f"""
        <table border="1" cellpadding="6" cellspacing="0">
          <tr><th>Date</th><th>Date Source</th><th>Link</th><th>Parent Website</th></tr>
          {rows_html}
        </table>
        """

    html = f"""
    <html><body>
    <h2>CTI Source Monitor - New Posts ({len(new_items)})</h2>
    {body_html}
    {failures_html}
    </body></html>
    """

    recipients = [r.strip() for r in EMAIL_TO.split(",") if r.strip()]

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


def main(config_path, state_path):
    config = load_json(config_path, {"sites": []})

    seen_names = set()
    dupes = [s["name"] for s in config["sites"] if s["name"] in seen_names or seen_names.add(s["name"])]
    if dupes:
        raise ValueError(f"Duplicate site names in config (fix before running): {dupes}")

    state = load_json(state_path, {})

    new_items = []
    failures = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--disable-http2"])

        for site in config["sites"]:
            name = site["name"]
            if site["type"] == "skip":
                continue
            if site["type"] == "html_TODO":
                failures.append(f"{name}: config not filled in yet, skipping")
                continue

            if site["type"] == "feed":
                entries, err = check_feed_site(site)
            elif site["type"] == "api":
                entries, err = check_api_site(site)
            elif site["type"] == "nextjs":
                entries, err = check_nextjs_site(site)
            elif site["type"] == "playwright_api":
                entries, err = check_playwright_api_site(site, browser)
            elif site["type"] == "html_auto":
                entries, err = check_html_auto_site(site, browser)
            elif site["type"] == "crawl4ai":
                entries, err = check_crawl4ai_site(site)
            else:
                entries, err = check_html_site(site, browser)

            if err:
                failures.append(f"{name}: {err}")
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
                print(f"  [{site['type'].upper()}] {name} ... seeding {len(new_links)} (not emailed)")
            else:
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

        browser.close()

    save_json(state_path, state)

    print(f"Run complete: {len(new_items)} new post(s) found, {len(failures)} site(s) failed.")
    send_digest_email(new_items, failures)


if __name__ == "__main__":
    cfg = sys.argv[1] if len(sys.argv) > 1 else "config.json"
    st = sys.argv[2] if len(sys.argv) > 2 else "state.json"
    main(cfg, st)
