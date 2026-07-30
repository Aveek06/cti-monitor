"""
Run this against each 'html_TODO' site in config.json to get candidate
selectors, instead of reading raw HTML by hand. It loads the page in a real
browser, finds groups of repeated similar elements (the classic "list of
post cards" pattern), and prints the best few guesses with sample text/links
so you can pick the right one and fill in config.json.

Usage:
    python inspect_site.py "https://www.fortinet.com/blog/threat-research"

This does NOT edit config.json for you - it prints suggestions, you paste
the selector you choose into config.json yourself. That manual judgment call
is unavoidable and is the actual bottleneck of this whole phase, not the
tooling.
"""

import sys
from collections import Counter
from playwright.sync_api import sync_playwright


def guess_post_containers(page):
    """
    Heuristic: find the CSS class combination that appears on the most
    elements that (a) contain a link and (b) are siblings of each other.
    That pattern usually IS the repeating post-card element.
    """
    candidates = page.evaluate("""
    () => {
        const all = Array.from(document.querySelectorAll('body *'));
        const groups = {};
        for (const el of all) {
            if (!el.className || typeof el.className !== 'string') continue;
            const cls = el.className.trim().split(/\\s+/).slice(0, 3).join('.');
            if (!cls) continue;
            const key = el.tagName.toLowerCase() + '.' + cls;
            if (!groups[key]) groups[key] = [];
            if (el.querySelector('a')) groups[key].push(el);
        }
        const results = [];
        for (const [key, els] of Object.entries(groups)) {
            if (els.length >= 3 && els.length <= 60) {
                const sample = els[0];
                const link = sample.querySelector('a');
                results.push({
                    selector: key,
                    count: els.length,
                    sampleText: sample.innerText.slice(0, 120).replace(/\\n/g, ' | '),
                    sampleHref: link ? link.href : null,
                });
            }
        }
        return results.sort((a, b) => b.count - a.count).slice(0, 8);
    }
    """)
    return candidates


def main(url):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--disable-http2"])
        context = browser.new_context(
            user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
            ignore_https_errors=True,
        )
        page = context.new_page()
        print(f"Loading {url} ...")
        page.goto(url, timeout=30000, wait_until="domcontentloaded")
        try:
            page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        page.wait_for_timeout(3000)

        candidates = guess_post_containers(page)
        browser.close()

    if not candidates:
        print("No repeating post-card pattern found automatically.")
        print("This site likely needs manual inspection - open dev tools (F12),")
        print("right-click a post title, 'Inspect', and find the repeating parent element.")
        return

    print(f"\nFound {len(candidates)} candidate patterns (best guesses first):\n")
    for i, c in enumerate(candidates, 1):
        print(f"--- Candidate {i}: appears {c['count']} times ---")
        print(f"  post_container selector: {c['selector']}")
        print(f"  sample text: {c['sampleText']}")
        print(f"  sample link: {c['sampleHref']}")
        print()

    print("Pick the candidate whose count roughly matches the number of posts")
    print("visible on the page, and whose sample link looks like a real blog post URL.")
    print("Paste its selector into config.json as 'post_container'.")
    print("The link is usually just the first <a> inside that container, so")
    print("link_selector can usually stay as 'a' unless there are multiple links per card.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python inspect_site.py <url>")
        sys.exit(1)
    main(sys.argv[1])
