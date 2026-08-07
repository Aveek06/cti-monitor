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


def send_stale_email(stale_sites, active_sites, total_active, report_date):
    # ── palette (dark theme, inline styles for email compatibility) ───────────
    BG       = "#0d1117"
    SURFACE  = "#161b22"
    SURFACE2 = "#1c2128"
    BORDER   = "#30363d"
    TEXT     = "#cdd9e5"
    DIM      = "#768390"
    HEAD     = "#adbac7"
    AMBER    = "#e3925a"
    CRIT     = "#e5534b"
    CYAN     = "#7dd3f0"
    BAR_PX   = 120  # total bar-track width in pixels

    total_links_week = sum(s["count"] for s in active_sites)
    max_count = active_sites[0]["count"] if active_sites else 1

    # ── stale rows ────────────────────────────────────────────────────────────
    stale_rows = ""
    for s in stale_sites:
        day_col = CRIT if s["days_since"] >= 14 else AMBER
        stale_rows += (
            f'<tr>'
            f'<td style="padding:10px 16px 10px 20px;border-bottom:1px solid {BORDER};'
            f'font-size:13px;color:{TEXT};">{s["name"]}</td>'
            f'<td style="padding:10px 16px;border-bottom:1px solid {BORDER};'
            f'font-family:monospace;font-size:12px;color:{DIM};">{s["last_active"]}</td>'
            f'<td style="padding:10px 20px 10px 16px;border-bottom:1px solid {BORDER};'
            f'font-family:monospace;font-size:13px;font-weight:600;'
            f'color:{day_col};text-align:right;">{s["days_since"]}</td>'
            f'</tr>'
        )

    # ── activity rows with proportional bar charts ────────────────────────────
    activity_rows = ""
    if active_sites:
        for s in active_sites:
            fill  = max(2, int(BAR_PX * s["count"] / max_count))
            empty = BAR_PX - fill
            activity_rows += (
                f'<tr>'
                f'<td style="padding:10px 16px 10px 20px;border-bottom:1px solid {BORDER};'
                f'font-size:13px;color:{TEXT};">{s["name"]}</td>'
                f'<td style="padding:10px 20px 10px 8px;border-bottom:1px solid {BORDER};">'
                f'<table cellpadding="0" cellspacing="0" style="display:inline-table;'
                f'vertical-align:middle;margin-right:10px;">'
                f'<tr>'
                f'<td width="{fill}" height="6" bgcolor="{CYAN}" style="font-size:0;line-height:0;">&nbsp;</td>'
                f'<td width="{empty}" height="6" bgcolor="{SURFACE2}" style="font-size:0;line-height:0;">&nbsp;</td>'
                f'</tr></table>'
                f'<span style="font-family:monospace;font-size:12px;font-weight:600;'
                f'color:{CYAN};vertical-align:middle;">{s["count"]}</span>'
                f'</td>'
                f'</tr>'
            )
    else:
        activity_rows = (
            f'<tr><td colspan="2" style="padding:16px 20px;color:{DIM};'
            f'font-style:italic;font-size:13px;">'
            f'No 7-day activity data yet (accumulates after first week of tracking).'
            f'</td></tr>'
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CTI Monitor Weekly Report</title>
</head>
<body style="margin:0;padding:0;background:{BG};">
<table width="100%" cellpadding="0" cellspacing="0" style="background:{BG};">
<tr><td align="center" style="padding:32px 16px 64px;">
<table width="640" cellpadding="0" cellspacing="0" style="max-width:640px;width:100%;">

  <!-- Header -->
  <tr><td style="background:{SURFACE};border:1px solid {BORDER};border-bottom:none;
    border-radius:8px 8px 0 0;padding:24px 28px 20px;">
    <table width="100%" cellpadding="0" cellspacing="0"><tr>
      <td valign="top">
        <div style="font-family:monospace;font-size:10px;letter-spacing:.12em;
          text-transform:uppercase;color:{CYAN};margin-bottom:4px;">Weekly Digest</div>
        <div style="font-size:18px;font-weight:700;color:{HEAD};letter-spacing:-.01em;">
          CTI Source Monitor</div>
      </td>
      <td align="right" valign="top">
        <div style="font-family:monospace;font-size:12px;color:{DIM};">{report_date}</div>
        <div style="font-size:11px;color:{DIM};margin-top:3px;">Friday &middot; 21:30 IST</div>
      </td>
    </tr></table>
    <!-- Stat chips -->
    <table cellpadding="0" cellspacing="0" style="margin-top:18px;">
    <tr>
      <td style="background:{SURFACE2};border:1px solid {BORDER};border-radius:6px;
        padding:6px 12px;white-space:nowrap;">
        <span style="font-family:monospace;font-size:20px;font-weight:600;
          color:{DIM};line-height:1;">{total_active}</span>
        <span style="font-size:11px;color:{DIM};text-transform:uppercase;
          letter-spacing:.06em;margin-left:6px;">Active Sources</span>
      </td>
      <td width="8" style="font-size:0;">&nbsp;</td>
      <td style="background:{SURFACE2};border:1px solid {BORDER};border-radius:6px;
        padding:6px 12px;white-space:nowrap;">
        <span style="font-family:monospace;font-size:20px;font-weight:600;
          color:{AMBER};line-height:1;">{len(stale_sites)}</span>
        <span style="font-size:11px;color:{DIM};text-transform:uppercase;
          letter-spacing:.06em;margin-left:6px;">Quiet Sites</span>
      </td>
      <td width="8" style="font-size:0;">&nbsp;</td>
      <td style="background:{SURFACE2};border:1px solid {BORDER};border-radius:6px;
        padding:6px 12px;white-space:nowrap;">
        <span style="font-family:monospace;font-size:20px;font-weight:600;
          color:{CYAN};line-height:1;">{total_links_week}</span>
        <span style="font-size:11px;color:{DIM};text-transform:uppercase;
          letter-spacing:.06em;margin-left:6px;">Links This Week</span>
      </td>
    </tr>
    </table>
  </td></tr>

  <!-- Stale Sites section -->
  <tr><td style="background:{SURFACE};border:1px solid {BORDER};border-top:none;border-bottom:none;">
    <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td style="padding:14px 20px 12px;border-bottom:1px solid {BORDER};">
      <table width="100%" cellpadding="0" cellspacing="0"><tr>
        <td>
          <span style="color:{AMBER};margin-right:8px;font-size:14px;vertical-align:middle;">&#11044;</span>
          <span style="font-size:13px;font-weight:600;color:{HEAD};vertical-align:middle;">
            Stale Sites &#8212; No Posts in {STALE_DAYS}+ Days</span>
        </td>
        <td align="right">
          <span style="font-family:monospace;font-size:11px;color:{DIM};
            background:{SURFACE2};border:1px solid {BORDER};border-radius:10px;
            padding:2px 8px;">{len(stale_sites)} of {total_active}</span>
        </td>
      </tr></table>
    </td></tr>
    <tr><td style="padding:10px 20px;font-size:12px;color:{DIM};
      border-bottom:1px solid {BORDER};line-height:1.5;">
      Sites currently returning scraper errors are excluded &#8212;
      those failures appear in the regular digest.
    </td></tr>
    <tr style="background:{SURFACE2};">
      <th style="padding:9px 16px 9px 20px;font-size:11px;font-weight:600;
        text-transform:uppercase;letter-spacing:.07em;color:{DIM};
        text-align:left;border-bottom:1px solid {BORDER};">Site</th>
      <th style="padding:9px 16px;font-size:11px;font-weight:600;
        text-transform:uppercase;letter-spacing:.07em;color:{DIM};
        text-align:left;border-bottom:1px solid {BORDER};">Last Active</th>
      <th style="padding:9px 20px 9px 16px;font-size:11px;font-weight:600;
        text-transform:uppercase;letter-spacing:.07em;color:{DIM};
        text-align:right;border-bottom:1px solid {BORDER};">Days Since Last Post</th>
    </tr>
    {stale_rows}
    </table>
  </td></tr>

  <!-- Source Activity section -->
  <tr><td style="background:{SURFACE};border:1px solid {BORDER};border-top:none;
    border-radius:0 0 8px 8px;">
    <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td style="padding:14px 20px 12px;border-bottom:1px solid {BORDER};">
      <table width="100%" cellpadding="0" cellspacing="0"><tr>
        <td>
          <span style="color:{CYAN};margin-right:8px;font-size:14px;vertical-align:middle;">&#11044;</span>
          <span style="font-size:13px;font-weight:600;color:{HEAD};vertical-align:middle;">
            Source Activity &#8212; Past 7 Days</span>
        </td>
        <td align="right">
          <span style="font-family:monospace;font-size:11px;color:{DIM};
            background:{SURFACE2};border:1px solid {BORDER};border-radius:10px;
            padding:2px 8px;">{len(active_sites)} sources reporting</span>
        </td>
      </tr></table>
    </td></tr>
    <tr style="background:{SURFACE2};">
      <th style="padding:9px 16px 9px 20px;font-size:11px;font-weight:600;
        text-transform:uppercase;letter-spacing:.07em;color:{DIM};
        text-align:left;border-bottom:1px solid {BORDER};">Site</th>
      <th style="padding:9px 20px 9px 8px;font-size:11px;font-weight:600;
        text-transform:uppercase;letter-spacing:.07em;color:{DIM};
        text-align:left;border-bottom:1px solid {BORDER};">Unique Links (7 days)</th>
    </tr>
    {activity_rows}
    </table>
  </td></tr>

  <!-- Footer -->
  <tr><td style="padding:20px 0 0;text-align:center;font-size:11px;color:{DIM};line-height:1.8;">
    CTI Source Monitor &middot; Automated weekly digest<br>
    avnandy@deloitte.com &middot; Sent Friday 21:30 IST
  </td></tr>

</table>
</td></tr>
</table>
</body>
</html>"""

    recipients = [r.strip() for r in EMAIL_TO.split(",") if r.strip()]
    msg = MIMEMultipart("alternative")
    msg["Subject"] = (
        f"CTI Monitor: Weekly Report — {len(stale_sites)} site(s) quiet, "
        f"{len(active_sites)} active ({report_date})"
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

    # Compute 7-day link counts per site from _seven_day_counts in last_active
    cutoff_str = threshold.strftime("%Y-%m-%d")
    seven_day = last_active.get("_seven_day_counts", {})
    active_sites = []
    for site in config["sites"]:
        name = site["name"]
        if site["type"] in EXCLUDED_TYPES:
            continue
        counts = seven_day.get(name, {})
        total_links = sum(v for k, v in counts.items() if k >= cutoff_str)
        if total_links > 0:
            active_sites.append({"name": name, "count": total_links})
    active_sites.sort(key=lambda x: x["count"], reverse=True)

    report_date = now.strftime("%Y-%m-%d")

    if not stale_sites:
        print(
            f"Weekly stale-sites check ({report_date}): "
            f"all {total_active} active sites are current. No email sent."
        )
        return

    print(
        f"Weekly stale-sites check ({report_date}): "
        f"{len(stale_sites)} of {total_active} site(s) stale. "
        f"{len(active_sites)} site(s) with 7-day activity data."
    )
    send_stale_email(stale_sites, active_sites, total_active, report_date)


if __name__ == "__main__":
    cfg = sys.argv[1] if len(sys.argv) > 1 else "config.json"
    la  = sys.argv[2] if len(sys.argv) > 2 else "last_active.json"
    main(cfg, la)
