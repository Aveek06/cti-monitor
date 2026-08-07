"""
Reads last_active.json and config.json, then emails a list of active
security blog sites that have produced no new posts in the past 7 days.

Run only on Fridays (the cti-monitor.yml workflow handles the day check).

Usage:
    python weekly_report.py config.json last_active.json
"""

import os
import sys
import json
import smtplib
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_SERVER   = "smtp.gmail.com"
SMTP_PORT     = 587
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
EMAIL_FROM    = SMTP_USERNAME
EMAIL_TO      = os.environ.get("EMAIL_TO", SMTP_USERNAME)

STALE_DAYS     = 7
EXCLUDED_TYPES = {"skip", "html_TODO"}


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def send_stale_email(stale_sites, total_active, report_date):
    rows_html = "".join(
        f"<tr><td>{s['name']}</td><td>{s['last_active']}</td>"
        f"<td style='text-align:center'>{s['days_since']}</td></tr>"
        for s in stale_sites
    )

    html = f"""<html><body>
<h2>CTI Source Monitor — Weekly Stale Sites Report ({report_date})</h2>
<p>{len(stale_sites)} of {total_active} active sites have not published any new
content in the past {STALE_DAYS} days.</p>
<p><em>Note: sites currently returning scraper errors are excluded from this
list — those failures appear in the regular 8-hourly digest.</em></p>
<table border="1" cellpadding="6" cellspacing="0">
  <tr><th>Site</th><th>Last Active</th><th>Days Since Last Post</th></tr>
  {rows_html}
</table>
</body></html>"""

    recipients = [r.strip() for r in EMAIL_TO.split(",") if r.strip()]
    msg = MIMEMultipart("alternative")
    msg["Subject"] = (
        f"CTI Monitor: Weekly Stale Sites — {len(stale_sites)} site(s) quiet "
        f"({report_date})"
    )
    msg["From"] = EMAIL_FROM
    msg["To"]   = ", ".join(recipients)
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, recipients, msg.as_string())
        print(f"Stale sites email sent: {len(stale_sites)} site(s) listed.")
    except Exception as e:
        print(f"Stale sites email failed: {e}")


def main(config_path, last_active_path):
    config      = load_json(config_path,      {"sites": []})
    last_active = load_json(last_active_path, {})

    now       = datetime.now(timezone.utc)
    threshold = now - timedelta(days=STALE_DAYS)

    currently_failing = set(last_active.get("_currently_failing", []))

    stale_sites  = []
    total_active = 0

    for site in config["sites"]:
        name = site["name"]

        if site["type"] in EXCLUDED_TYPES:
            continue

        total_active += 1

        if name in currently_failing:
            continue

        last_ts_str = last_active.get(name)
        if last_ts_str is None:
            continue

        try:
            last_ts = datetime.fromisoformat(last_ts_str)
        except ValueError:
            print(f"Warning: bad timestamp for {name!r}: {last_ts_str!r}")
            continue

        if last_ts <= threshold:
            stale_sites.append({
                "name":        name,
                "last_active": last_ts.strftime("%Y-%m-%d"),
                "days_since":  (now - last_ts).days,
            })

    stale_sites.sort(key=lambda x: x["days_since"], reverse=True)

    report_date = now.strftime("%Y-%m-%d")

    if not stale_sites:
        print(
            f"Weekly stale-sites check ({report_date}): "
            f"all {total_active} active sites are current. No email sent."
        )
        return

    print(
        f"Weekly stale-sites check ({report_date}): "
        f"{len(stale_sites)} of {total_active} site(s) stale."
    )
    send_stale_email(stale_sites, total_active, report_date)


if __name__ == "__main__":
    cfg = sys.argv[1] if len(sys.argv) > 1 else "config.json"
    la  = sys.argv[2] if len(sys.argv) > 2 else "last_active.json"
    main(cfg, la)
