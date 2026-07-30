"""
Syncs config.json with CTI_Source_List.xlsx.

- Sites in Excel but not in config  → auto-detect (RSS first, then HTML) and add
- Sites in config but not in Excel  → remove from config (state.json history is kept)

Auto-detection order:
  1. Try common RSS/Atom feed paths on the site's base domain
  2. If a valid feed is found  → type: feed
  3. If not               → Playwright heuristic to find post_container selector
  4. If selector found    → type: html
  5. If not               → type: html_TODO  (flagged in email digest on next run)
"""

import json
import requests
import feedparser
import openpyxl
from urllib.parse import urljoin, urlparse
from playwright.sync_api import sync_playwright

RSS_PATHS = [
    "/feed", "/feed/", "/rss", "/rss/", "/feed.xml", "/rss.xml", "/atom.xml",
    "/feed/rss", "/feed/atom", "/blog/feed", "/blog/rss", "/blog/feed.xml",
    "/blog/rss.xml", "/index.xml", "/posts/feed", "/news/feed", "/en/rss",
    "/en/feed", "/api/rss", "/api/feed",
]

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
HEADERS = {"User-Agent": UA}


def try_rss(site_url):
    """Try the site URL itself and common feed paths. Return the first valid feed URL."""
    parsed = urlparse(site_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    candidates = [site_url] + [urljoin(base, p) for p in RSS_PATHS]
    seen = set()
    for url in candidates:
        if url in seen:
            continue
        seen.add(url)
        try:
            r = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True)
            ct = r.headers.get("Content-Type", "")
            if r.status_code == 200 and any(x in ct for x in ("xml", "rss", "atom")):
                feed = feedparser.parse(r.text)
                if feed.entries:
                    return url
        except Exception:
            continue
    return None


def find_html_selector(url, page):
    """
    Playwright heuristic: find a repeating element class (3–60 occurrences)
    where most instances contain a child <a> pointing to a real article path.
    Returns (post_container_selector, link_selector) or (None, None).
    """
    try:
        page.goto(url, timeout=30000, wait_until="domcontentloaded")
        try:
            page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        page.wait_for_timeout(3000)
    except Exception:
        return None, None

    class_counts = page.evaluate("""() => {
        const counts = {};
        document.querySelectorAll('*').forEach(el => {
            el.classList.forEach(cls => { counts[cls] = (counts[cls] || 0) + 1; });
        });
        return counts;
    }""")

    candidates = {cls: cnt for cls, cnt in class_counts.items()
                  if 3 <= cnt <= 60 and len(cls) > 2}

    best_selector = None
    best_score = 0

    for cls, cnt in sorted(candidates.items(), key=lambda x: -x[1]):
        selector = f"div.{cls}"
        try:
            elements = page.query_selector_all(selector)
            if not elements:
                continue
            valid = 0
            for el in elements[:10]:
                a = el.query_selector("a")
                if a:
                    href = a.get_attribute("href") or ""
                    full = urljoin(url, href)
                    parts = [p for p in urlparse(full).path.split("/") if p]
                    if len(parts) >= 2:
                        valid += 1
            score = valid * cnt
            if valid >= 3 and score > best_score:
                best_score = score
                best_selector = selector
        except Exception:
            continue

    if best_selector:
        return best_selector, "a"
    return None, None


def load_excel(path):
    wb = openpyxl.load_workbook(path)
    ws = wb.active
    sites = {}
    for row in ws.iter_rows(min_row=2, values_only=True):
        if not row[0] or not row[1]:
            continue
        name = str(row[0]).strip()
        url = str(row[1]).strip()
        if name and url:
            sites[name] = url
    return sites


def main():
    excel_sites = load_excel("CTI_Source_List.xlsx")
    with open("config.json", encoding="utf-8") as f:
        config = json.load(f)

    existing = {s["name"]: s for s in config["sites"]}
    to_add = {n: u for n, u in excel_sites.items() if n not in existing}
    to_remove = {n for n in existing if n not in excel_sites}

    print(f"Sites to add:    {len(to_add)}")
    print(f"Sites to remove: {len(to_remove)}")

    # Remove sites no longer in Excel
    if to_remove:
        print("\nRemoving:")
        for name in sorted(to_remove):
            print(f"  - {name}")
        config["sites"] = [s for s in config["sites"] if s["name"] not in to_remove]

    # Add new sites
    if to_add:
        print("\nAdding:")
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--disable-http2"])
            context = browser.new_context(user_agent=UA, ignore_https_errors=True)
            page = context.new_page()

            for name in sorted(to_add):
                url = to_add[name]
                print(f"\n  {name}  ({url})")

                rss_url = try_rss(url)
                if rss_url:
                    print(f"    RSS found: {rss_url}")
                    config["sites"].append({
                        "name": name,
                        "type": "feed",
                        "url": rss_url,
                    })
                    continue

                print(f"    No RSS — trying HTML selector...")
                selector, link_sel = find_html_selector(url, page)
                if selector:
                    print(f"    Selector found: {selector}")
                    config["sites"].append({
                        "name": name,
                        "type": "html",
                        "url": url,
                        "post_container": selector,
                        "link_selector": link_sel,
                        "date_selector": None,
                        "date_format": "auto",
                        "needs_js": True,
                        "notes": "auto-detected by sync_sources.py",
                    })
                else:
                    print(f"    Selector not found — added as html_TODO for manual review")
                    config["sites"].append({
                        "name": name,
                        "type": "html_TODO",
                        "url": url,
                        "notes": "auto-detection failed — manual selector inspection needed",
                    })

            context.close()
            browser.close()

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    added_feed = sum(1 for n in to_add if any(
        s["name"] == n and s["type"] == "feed" for s in config["sites"]))
    added_html = sum(1 for n in to_add if any(
        s["name"] == n and s["type"] == "html" for s in config["sites"]))
    added_todo = sum(1 for n in to_add if any(
        s["name"] == n and s["type"] == "html_TODO" for s in config["sites"]))

    print(f"\nDone.")
    print(f"  Added as feed:     {added_feed}")
    print(f"  Added as html:     {added_html}")
    print(f"  Added as html_TODO:{added_todo}")
    print(f"  Removed:           {len(to_remove)}")
    print(f"config.json updated.")


if __name__ == "__main__":
    main()
