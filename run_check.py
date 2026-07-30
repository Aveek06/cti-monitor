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
import json
import smtplib
import feedparser
import requests
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
        for e in parsed.entries:
            link = e.get("link", "")
            date_str = e.get("published", e.get("updated", ""))
            if link:
                entries.append((link, date_str))
    except Exception as ex:
        return entries, f"feed parse error: {ex}"
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


def normalize_date(date_str):
    """Best-effort parse; falls back to 'detected today' if it can't be parsed."""
    if not date_str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d"), "detected"
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z", "%B %d, %Y",
                "%b %d, %Y", "%d %B %Y", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(date_str.strip(), fmt)
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

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"CTI Monitor: {len(new_items)} new post(s) - {datetime.now().strftime('%Y-%m-%d')}"
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
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
