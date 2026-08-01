"""
Test crawl4AI against sites that are currently blocked or failing.
Tries stealth mode and reports how many candidate blog links each site yields.

Usage:
    python test_crawl4ai.py
"""

import asyncio
import sys
import io
from urllib.parse import urlparse, urljoin

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from crawl4ai import AsyncWebCrawler, BrowserConfig, CrawlerRunConfig, CacheMode

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# Sites to test: (name, url, link_path_prefix_or_None)
TARGETS = [
    # Timeout sites
    ("Secureworks",   "https://www.secureworks.com/blog/",           "/blog/"),
    ("Sophos",        "https://news.sophos.com/en-us/",              "/en-us/"),
    ("Trellix",       "https://www.trellix.com/blogs/research/",     "/blogs/research/"),
    # 403 sites
    ("SOCradar",      "https://socradar.io/blog/",                   "/blog/"),
    ("Blackpoint",    "https://blackpointcyber.com/blog/",           "/blog/"),
    ("McAfee",        "https://www.mcafee.com/blogs/",               "/blogs/"),
    ("Forescout",     "https://www.forescout.com/blog/",             "/blog/"),
    ("Human Security","https://www.humansecurity.com/learn/blog/",   "/learn/blog/"),
    ("iZoologic",     "https://izoologic.com/blogs/",                "/blogs/"),
    ("Akamai",        "https://www.akamai.com/blog/security-research","/blog/security-research/"),
    ("F6 Russia",     "https://www.f6.ru/blog/",                     "/blog/"),
    # JS-heavy failures with current html_auto
    ("Oligo Security","https://www.oligo.security/resources/blog",   "/resources/blog/"),
    ("eSentire",      "https://www.esentire.com/resources/blog",     "/resources/blog/"),
    ("Packetstorm",   "https://packetstorm.news/",                   "/news/main/"),
]


def extract_links(html: str, base_url: str, prefix: str | None, min_depth: int = 2) -> list[str]:
    """Pull same-domain links from raw HTML string that match the prefix."""
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "html.parser")
    domain = urlparse(base_url).netloc
    seen = set()
    results = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"]
        if href.startswith(("#", "mailto:", "javascript:")):
            continue
        full = urljoin(base_url, href)
        p = urlparse(full)
        if p.netloc != domain:
            continue
        path = p.path
        if prefix and not path.startswith(prefix):
            continue
        parts = [x for x in path.split("/") if x]
        if len(parts) < min_depth:
            continue
        slug = parts[-1] if parts else ""
        if len(slug) < 8:
            continue
        clean = p.scheme + "://" + p.netloc + path
        if clean not in seen:
            seen.add(clean)
            results.append(clean)
    return results


async def test_site(crawler: AsyncWebCrawler, name: str, url: str, prefix: str | None):
    run_cfg = CrawlerRunConfig(
        cache_mode=CacheMode.BYPASS,
        magic=True,
        simulate_user=True,
        override_navigator=True,
        page_timeout=30000,
        wait_until="domcontentloaded",
        delay_before_return_html=4.0,
        scan_full_page=True,
        scroll_delay=0.5,
    )
    try:
        result = await crawler.arun(url=url, config=run_cfg)
        if not result.success:
            print(f"FAIL  {name}: {result.error_message or 'unknown error'}")
            return

        status = result.status_code or "?"
        html = result.html or ""
        links = extract_links(html, url, prefix)
        print(f"{status}   {name}: {len(links)} candidate links  (html_len={len(html):,})")
        for lnk in links[:4]:
            print(f"       {lnk}")
        if len(links) > 4:
            print(f"       ... ({len(links) - 4} more)")
    except Exception as ex:
        print(f"ERR   {name}: {ex}")


async def main():
    browser_cfg = BrowserConfig(
        headless=True,
        browser_type="chromium",
        user_agent=UA,
        extra_args=["--disable-http2"],
    )

    print("Testing blocked/failing sites with crawl4AI (magic=True, stealth, full-page scan)\n")

    async with AsyncWebCrawler(config=browser_cfg) as crawler:
        # Run sequentially so output stays readable
        for name, url, prefix in TARGETS:
            await test_site(crawler, name, url, prefix)

    print("\nDone.")


if __name__ == "__main__":
    asyncio.run(main())
