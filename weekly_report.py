"""
Reads last_active.json and config.json, then emails a weekly report.
Always sends on Fridays — shows stale sites if any, otherwise an all-clear.
Optionally reads ioc_export.json for an IOC summary section.

Usage:
    python weekly_report.py config.json last_active.json [ioc_export.json]
"""

import os
import re
import sys
import json
import smtplib
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

try:
    import anthropic as _anthropic
except ImportError:
    _anthropic = None

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


def _live_score(last_seen_str, tau, ltv):
    """Recompute Jakusz decay score as of now."""
    try:
        last_seen = datetime.strptime(last_seen_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        t = (datetime.now(timezone.utc) - last_seen).days
        denom = float(tau or 30) * float(ltv or 1.0)
        return max(0.0, round(100.0 * (1.0 - (t / denom) ** 2), 1))
    except Exception:
        return 0.0


def _compute_ioc_stats(ioc_export, cutoff_str):
    """Return summary dict from ioc_export list."""
    if not ioc_export:
        return None

    by_type = {}
    by_apt  = {}
    new_this_week = 0
    scored = []

    for row in ioc_export:
        ioc_type = row.get("type", "unknown")
        apt      = row.get("apt") or "Unknown"
        score    = _live_score(row.get("last_seen", ""), row.get("tau"), row.get("ltv"))

        if score < 1:
            continue

        by_type[ioc_type] = by_type.get(ioc_type, 0) + 1
        by_apt[apt]       = by_apt.get(apt, 0) + 1

        first_seen = row.get("first_seen", "")
        if first_seen >= cutoff_str:
            new_this_week += 1

        scored.append({
            "value":   row.get("value", ""),
            "type":    ioc_type,
            "apt":     apt,
            "score":   score,
            "source":  row.get("source_blog", ""),
        })

    scored.sort(key=lambda x: x["score"], reverse=True)

    return {
        "total":         len(scored),
        "new_this_week": new_this_week,
        "by_type":       by_type,
        "by_apt":        by_apt,
        "top":           scored[:10],
    }


def _build_ioc_by_site(ioc_export):
    result = {}
    for ioc in (ioc_export or []):
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


def _fetch_ratings():
    db_url = os.environ.get("DATABASE_URL", "")
    if not db_url:
        return {}
    try:
        import psycopg2
        import psycopg2.extras
        conn = psycopg2.connect(db_url)
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT site_name,
                       ROUND(AVG(rating)::numeric, 1) AS avg,
                       COUNT(*)::int AS count
                FROM site_ratings GROUP BY site_name
            """)
            rows = cur.fetchall()
        conn.close()
        return {r["site_name"]: {"avg": float(r["avg"]), "count": r["count"]} for r in rows}
    except Exception as e:
        print(f"weekly_report: could not fetch ratings: {e}")
        return {}


def _compute_reliability(name, week_count, last_ts_str, is_failing, ioc_by_site, ratings):
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


def generate_narrative(active_sites, stale_sites, ioc_stats, top_ttps,
                       degraded_sources, report_date, api_key):
    """Generate a 2-3 paragraph executive threat intelligence narrative using Claude."""
    if not _anthropic or not api_key:
        return ""
    try:
        active_names = ", ".join(s["name"] for s in active_sites[:10]) or "none"
        stale_names  = ", ".join(s["name"] for s in stale_sites[:8])   or "none"
        ioc_summary  = ""
        if ioc_stats and ioc_stats.get("total"):
            breakdown = ", ".join(f"{t} ({c})" for t, c in (ioc_stats.get("by_type") or {}).items())
            ioc_summary = f"{ioc_stats['total']} active IOCs ({breakdown})"
        else:
            ioc_summary = "no active IOCs"
        ttp_names = ", ".join(
            f"{t.get('technique_id','?')} {t.get('technique_name','')}" for t in (top_ttps or [])[:6]
        ) or "none observed"
        degraded = ", ".join(
            f"{d['name']} ({d['prev']}→{d['curr']})" for d in (degraded_sources or [])
        ) or "none"

        prompt = (
            f"You are writing the weekly threat intelligence digest for a security team. "
            f"Write 2-3 concise paragraphs (plain prose, no bullet points, no headers) that give an "
            f"executive summary of this week's CTI monitoring results. Be specific and analytical.\n\n"
            f"Report date: {report_date}\n"
            f"Active sources (posted this week): {active_names}\n"
            f"Silent/stale sources: {stale_names}\n"
            f"IOC posture: {ioc_summary}\n"
            f"Top TTPs observed: {ttp_names}\n"
            f"Reliability degradations: {degraded}\n\n"
            f"Cover: what the threat landscape looks like this week, any notable shifts or concerns, "
            f"and what the team should prioritize reviewing."
        )
        client = _anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model="claude-haiku-4-5",
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text.strip()
    except Exception as e:
        print(f"Weekly narrative generation failed: {e}")
        return ""


def send_stale_email(stale_sites, active_sites, total_active, report_date,
                     ai_weekly_cost=0.0, ioc_stats=None,
                     ioc_by_site=None, ratings=None, last_active_raw=None, failing_set=None,
                     degraded_sources=None, narrative=""):
    # palette (dark theme, inline styles for email compatibility)
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
    GREEN    = "#57ab5a"
    BAR_PX   = 120

    total_links_week = sum(s["count"] for s in active_sites)
    max_count = active_sites[0]["count"] if active_sites else 1

    # stale rows (or all-clear message)
    if stale_sites:
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
        stale_section_header = (
            f'<span style="color:{AMBER};margin-right:8px;font-size:14px;vertical-align:middle;">&#11044;</span>'
            f'<span style="font-size:13px;font-weight:600;color:{HEAD};vertical-align:middle;">'
            f'Stale Sites &#8212; No Posts in {STALE_DAYS}+ Days</span>'
        )
        stale_table_cols = f"""
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
    {stale_rows}"""
    else:
        stale_section_header = (
            f'<span style="color:{GREEN};margin-right:8px;font-size:14px;vertical-align:middle;">&#11044;</span>'
            f'<span style="font-size:13px;font-weight:600;color:{HEAD};vertical-align:middle;">'
            f'All Sites Active &#8212; No Stale Sources This Week</span>'
        )
        stale_table_cols = (
            f'<tr><td style="padding:20px;text-align:center;font-size:13px;color:{GREEN};">'
            f'&#10003; All {total_active} monitored sources published within the past {STALE_DAYS} days.</td></tr>'
        )

    # activity rows
    _ioc_by_site = ioc_by_site or {}
    _ratings     = ratings or {}
    _la_raw      = last_active_raw or {}
    _failing     = failing_set or set()

    narrative_section = ""
    if narrative:
        narrative_section = (
            f'<tr><td style="padding:0 0 16px 0;">'
            f'<table width="100%" cellpadding="0" cellspacing="0"'
            f' style="border-collapse:collapse;background:{SURFACE};'
            f'border:1px solid {BORDER};border-radius:8px;">'
            f'<tr><td style="padding:10px 20px 6px;font-size:9px;font-weight:700;'
            f'letter-spacing:.12em;text-transform:uppercase;color:{DIM};'
            f'border-bottom:1px solid {BORDER};">Threat Intelligence Narrative</td></tr>'
            f'<tr><td style="padding:16px 20px;font-size:13px;color:{TEXT};'
            f'line-height:1.65;font-style:italic;">{narrative}</td></tr>'
            f'</table></td></tr>'
        )

    activity_rows = ""
    if active_sites:
        for s in active_sites:
            fill  = max(2, int(BAR_PX * s["count"] / max_count))
            empty = BAR_PX - fill
            rel   = _compute_reliability(
                s["name"], s["count"], _la_raw.get(s["name"]),
                s["name"] in _failing, _ioc_by_site, _ratings,
            )
            if rel >= 70:
                rel_col, rel_bg, rel_bd = GREEN, "#0d1f0e", "#2d5e30"
            elif rel >= 40:
                rel_col, rel_bg, rel_bd = AMBER, "#1f150a", "#5e3a1a"
            else:
                rel_col, rel_bg, rel_bd = CRIT, "#1f0a0a", "#5e1a1a"
            activity_rows += (
                f'<tr>'
                f'<td style="padding:10px 16px 10px 20px;border-bottom:1px solid {BORDER};'
                f'font-size:13px;color:{TEXT};">{s["name"]}</td>'
                f'<td style="padding:10px 16px 10px 8px;border-bottom:1px solid {BORDER};">'
                f'<table cellpadding="0" cellspacing="0" style="display:inline-table;'
                f'vertical-align:middle;margin-right:10px;">'
                f'<tr>'
                f'<td width="{fill}" height="6" bgcolor="{CYAN}" style="font-size:0;line-height:0;">&nbsp;</td>'
                f'<td width="{empty}" height="6" bgcolor="{SURFACE2}" style="font-size:0;line-height:0;">&nbsp;</td>'
                f'</tr></table>'
                f'<span style="font-family:monospace;font-size:12px;font-weight:600;'
                f'color:{CYAN};vertical-align:middle;">{s["count"]}</span>'
                f'</td>'
                f'<td style="padding:10px 20px 10px 8px;border-bottom:1px solid {BORDER};white-space:nowrap;">'
                f'<span style="font-family:monospace;font-size:12px;font-weight:700;'
                f'color:{rel_col};background:{rel_bg};border:1px solid {rel_bd};'
                f'border-radius:3px;padding:2px 7px;">{rel}</span>'
                f'<span style="font-size:10px;color:{DIM};margin-left:4px;">/100</span>'
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

    # Degradation alert section
    degradation_section_html = ""
    if degraded_sources:
        deg_rows = ""
        for d in degraded_sources:
            deg_rows += (
                f'<tr>'
                f'<td style="padding:10px 16px 10px 20px;border-bottom:1px solid {BORDER};'
                f'font-size:13px;color:{TEXT};">{d["name"]}</td>'
                f'<td style="padding:10px 8px;border-bottom:1px solid {BORDER};'
                f'font-family:monospace;font-size:12px;">'
                f'<span style="color:{GREEN};">{d["prev"]}</span>'
                f'<span style="color:{DIM};margin:0 6px;">&#x2192;</span>'
                f'<span style="color:{CRIT};">{d["curr"]}</span></td>'
                f'<td style="padding:10px 20px 10px 8px;border-bottom:1px solid {BORDER};'
                f'font-family:monospace;font-size:12px;color:{AMBER};">-{d["drop"]} pts</td>'
                f'</tr>'
            )
        degradation_section_html = f"""
  <tr><td style="padding:0 0 16px 0;">
    <table width="100%" cellpadding="0" cellspacing="0"
           style="border-collapse:collapse;background:{SURFACE};border:1px solid #5e3a1a;border-radius:8px;">
    <tr>
      <th colspan="3" style="padding:14px 20px 10px;font-size:10px;font-weight:700;
          letter-spacing:.12em;text-transform:uppercase;color:{AMBER};
          text-align:left;border-bottom:1px solid {BORDER};">
        Reliability Degradation Alert
      </th>
    </tr>
    <tr>
      <th style="padding:6px 16px 6px 20px;font-size:9px;font-weight:700;letter-spacing:.1em;
          text-transform:uppercase;color:{DIM};text-align:left;border-bottom:1px solid {BORDER};">Source</th>
      <th style="padding:6px 8px;font-size:9px;font-weight:700;letter-spacing:.1em;
          text-transform:uppercase;color:{DIM};text-align:left;border-bottom:1px solid {BORDER};">Score</th>
      <th style="padding:6px 20px 6px 8px;font-size:9px;font-weight:700;letter-spacing:.1em;
          text-transform:uppercase;color:{DIM};text-align:left;border-bottom:1px solid {BORDER};">Drop</th>
    </tr>
    {deg_rows}
    </table>
  </td></tr>
"""

    # IOC section
    ioc_section_html = ""
    if ioc_stats and ioc_stats["total"] > 0:
        st = ioc_stats

        # type breakdown chips
        type_chips = ""
        type_order = ["sha256", "sha1", "md5", "domain"]
        for t in type_order:
            if t in st["by_type"]:
                type_chips += (
                    f'<span style="display:inline-block;background:{SURFACE2};border:1px solid {BORDER};'
                    f'border-radius:4px;padding:2px 8px;margin-right:6px;margin-bottom:4px;'
                    f'font-family:monospace;font-size:11px;color:{CYAN};">'
                    f'{t} ({st["by_type"][t]})</span>'
                )

        # APT breakdown chips
        apt_chips = ""
        for apt, cnt in sorted(st["by_apt"].items(), key=lambda x: -x[1]):
            apt_color = AMBER if apt != "Unknown" else DIM
            apt_chips += (
                f'<span style="display:inline-block;background:{SURFACE2};border:1px solid {BORDER};'
                f'border-radius:4px;padding:2px 8px;margin-right:6px;margin-bottom:4px;'
                f'font-family:monospace;font-size:11px;color:{apt_color};">'
                f'{apt} ({cnt})</span>'
            )

        # top IOC rows
        top_rows = ""
        for r in st["top"]:
            val = r["value"]
            display_val = val[:48] + "..." if len(val) > 51 else val
            pct = int(r["score"])
            bar_fill  = max(2, int(80 * pct / 100))
            bar_empty = 80 - bar_fill
            score_col = GREEN if pct >= 70 else (CYAN if pct >= 40 else AMBER)
            apt_color  = AMBER if r["apt"] != "Unknown" else DIM
            top_rows += (
                f'<tr>'
                f'<td style="padding:8px 12px 8px 20px;border-bottom:1px solid {BORDER};'
                f'font-family:monospace;font-size:11px;color:{TEXT};word-break:break-all;">'
                f'{display_val}</td>'
                f'<td style="padding:8px 12px;border-bottom:1px solid {BORDER};'
                f'font-family:monospace;font-size:11px;color:{DIM};white-space:nowrap;">{r["type"]}</td>'
                f'<td style="padding:8px 12px;border-bottom:1px solid {BORDER};'
                f'font-size:11px;color:{apt_color};white-space:nowrap;">{r["apt"]}</td>'
                f'<td style="padding:8px 20px 8px 12px;border-bottom:1px solid {BORDER};white-space:nowrap;">'
                f'<table cellpadding="0" cellspacing="0" style="display:inline-table;vertical-align:middle;margin-right:6px;">'
                f'<tr>'
                f'<td width="{bar_fill}" height="5" bgcolor="{score_col}" style="font-size:0;line-height:0;">&nbsp;</td>'
                f'<td width="{bar_empty}" height="5" bgcolor="{SURFACE2}" style="font-size:0;line-height:0;">&nbsp;</td>'
                f'</tr></table>'
                f'<span style="font-family:monospace;font-size:11px;font-weight:600;'
                f'color:{score_col};vertical-align:middle;">{r["score"]:.0f}</span>'
                f'</td>'
                f'</tr>'
            )

        ioc_section_html = f"""
  <!-- IOC Summary section -->
  <tr><td style="background:{SURFACE};border:1px solid {BORDER};border-top:none;border-radius:0 0 8px 8px;">
    <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td style="padding:14px 20px 12px;border-bottom:1px solid {BORDER};">
      <table width="100%" cellpadding="0" cellspacing="0"><tr>
        <td>
          <span style="color:{AMBER};margin-right:8px;font-size:14px;vertical-align:middle;">&#9650;</span>
          <span style="font-size:13px;font-weight:600;color:{HEAD};vertical-align:middle;">
            IOC Indicators &#8212; 7-Day Summary</span>
        </td>
        <td align="right">
          <span style="font-family:monospace;font-size:11px;color:{DIM};
            background:{SURFACE2};border:1px solid {BORDER};border-radius:10px;
            padding:2px 8px;">{st["total"]} active</span>
        </td>
      </tr></table>
    </td></tr>
    <tr><td style="padding:14px 20px;">
      <table cellpadding="0" cellspacing="0" style="margin-bottom:10px;">
        <tr>
          <td style="background:{SURFACE2};border:1px solid {BORDER};border-radius:6px;
            padding:6px 12px;white-space:nowrap;margin-right:8px;">
            <span style="font-family:monospace;font-size:18px;font-weight:600;color:{CYAN};">{st["total"]}</span>
            <span style="font-size:11px;color:{DIM};text-transform:uppercase;letter-spacing:.06em;margin-left:6px;">Active IOCs</span>
          </td>
          <td width="8">&nbsp;</td>
          <td style="background:{SURFACE2};border:1px solid {BORDER};border-radius:6px;
            padding:6px 12px;white-space:nowrap;">
            <span style="font-family:monospace;font-size:18px;font-weight:600;color:{GREEN};">{st["new_this_week"]}</span>
            <span style="font-size:11px;color:{DIM};text-transform:uppercase;letter-spacing:.06em;margin-left:6px;">New This Week</span>
          </td>
        </tr>
      </table>
      <div style="margin-bottom:6px;">
        <span style="font-size:11px;color:{DIM};text-transform:uppercase;
          letter-spacing:.07em;margin-right:8px;">By Type:</span>{type_chips}
      </div>
      <div>
        <span style="font-size:11px;color:{DIM};text-transform:uppercase;
          letter-spacing:.07em;margin-right:8px;">By APT:</span>{apt_chips}
      </div>
    </td></tr>
    <tr style="background:{SURFACE2};">
      <th colspan="4" style="padding:9px 20px;font-size:11px;font-weight:600;
        text-transform:uppercase;letter-spacing:.07em;color:{DIM};
        text-align:left;border-bottom:1px solid {BORDER};">Top IOCs by Decay Score</th>
    </tr>
    <tr style="background:{SURFACE2};">
      <th style="padding:9px 12px 9px 20px;font-size:10px;font-weight:600;
        text-transform:uppercase;letter-spacing:.07em;color:{DIM};
        text-align:left;border-bottom:1px solid {BORDER};">Indicator</th>
      <th style="padding:9px 12px;font-size:10px;font-weight:600;
        text-transform:uppercase;letter-spacing:.07em;color:{DIM};
        text-align:left;border-bottom:1px solid {BORDER};">Type</th>
      <th style="padding:9px 12px;font-size:10px;font-weight:600;
        text-transform:uppercase;letter-spacing:.07em;color:{DIM};
        text-align:left;border-bottom:1px solid {BORDER};">APT</th>
      <th style="padding:9px 20px 9px 12px;font-size:10px;font-weight:600;
        text-transform:uppercase;letter-spacing:.07em;color:{DIM};
        text-align:left;border-bottom:1px solid {BORDER};">Score</th>
    </tr>
    {top_rows}
    </table>
  </td></tr>"""

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
      {'<td width="8" style="font-size:0;">&nbsp;</td>'
       f'<td style="background:{SURFACE2};border:1px solid {BORDER};border-radius:6px;'
       f'padding:6px 12px;white-space:nowrap;">'
       f'<span style="font-family:monospace;font-size:20px;font-weight:600;'
       f'color:{DIM};line-height:1;">${ai_weekly_cost:.4f}</span>'
       f'<span style="font-size:11px;color:{DIM};text-transform:uppercase;'
       f'letter-spacing:.06em;margin-left:6px;">AI Cost (7d)</span></td>'
       if ai_weekly_cost > 0 else ''}
      {'<td width="8" style="font-size:0;">&nbsp;</td>'
       f'<td style="background:{SURFACE2};border:1px solid {BORDER};border-radius:6px;'
       f'padding:6px 12px;white-space:nowrap;">'
       f'<span style="font-family:monospace;font-size:20px;font-weight:600;'
       f'color:{AMBER};line-height:1;">{ioc_stats["total"]}</span>'
       f'<span style="font-size:11px;color:{DIM};text-transform:uppercase;'
       f'letter-spacing:.06em;margin-left:6px;">Active IOCs</span></td>'
       if ioc_stats and ioc_stats["total"] > 0 else ''}
    </tr>
    </table>
  </td></tr>

  {narrative_section}

  <!-- Stale Sites section -->
  <tr><td style="background:{SURFACE};border:1px solid {BORDER};border-top:none;border-bottom:none;">
    <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td style="padding:14px 20px 12px;border-bottom:1px solid {BORDER};">
      <table width="100%" cellpadding="0" cellspacing="0"><tr>
        <td>{stale_section_header}</td>
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
    {stale_table_cols}
    </table>
  </td></tr>

  <!-- Source Activity section -->
  <tr><td style="background:{SURFACE};border:1px solid {BORDER};border-top:none;border-radius:0;">
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
      <th style="padding:9px 16px 9px 8px;font-size:11px;font-weight:600;
        text-transform:uppercase;letter-spacing:.07em;color:{DIM};
        text-align:left;border-bottom:1px solid {BORDER};">Unique Links (7 days)</th>
      <th style="padding:9px 20px 9px 8px;font-size:11px;font-weight:600;
        text-transform:uppercase;letter-spacing:.07em;color:{DIM};
        text-align:left;border-bottom:1px solid {BORDER};">Reliability</th>
    </tr>
    {activity_rows}
    </table>
  </td></tr>

  {degradation_section_html}

  {ioc_section_html}

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

    all_clear = len(stale_sites) == 0
    subject = (
        f"CTI Monitor: Weekly Report &#8212; All Clear ({report_date})"
        if all_clear else
        f"CTI Monitor: Weekly Report &#8212; {len(stale_sites)} site(s) quiet ({report_date})"
    )
    # email subject must be plain text
    subject_plain = (
        f"CTI Monitor: Weekly Report - All Clear ({report_date})"
        if all_clear else
        f"CTI Monitor: Weekly Report - {len(stale_sites)} site(s) quiet ({report_date})"
    )
    if ioc_stats and ioc_stats["total"] > 0:
        subject_plain += f", {ioc_stats['total']} active IOCs"

    recipients = [r for r in re.split(r'[,\s]+', EMAIL_TO.strip()) if r]
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject_plain
    msg["From"]    = EMAIL_FROM
    msg["To"]      = ", ".join(recipients)
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, recipients, msg.as_string())
        status = "all-clear" if all_clear else f"{len(stale_sites)} stale"
        print(f"Weekly email sent: {status}, {total_active} active, {ioc_stats['total'] if ioc_stats else 0} IOCs.")
    except Exception as e:
        print(f"Weekly email failed: {e}")


def main(config_path, last_active_path, ioc_export_path=None):
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

    cutoff_str = threshold.strftime("%Y-%m-%d")
    seven_day  = last_active.get("_seven_day_counts", {})
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

    ai_cost_by_day = last_active.get("_ai_cost", {})
    ai_weekly_cost = sum(v for k, v in ai_cost_by_day.items() if k >= cutoff_str)

    ioc_export  = load_json(ioc_export_path or "ioc_export.json", [])
    ttp_export  = load_json("ttp_export.json", [])
    ioc_stats   = _compute_ioc_stats(ioc_export, cutoff_str)
    ioc_by_site = _build_ioc_by_site(ioc_export)
    ratings     = _fetch_ratings()

    top_ttps = sorted(ttp_export, key=lambda t: t.get("total_observations", 0), reverse=True)[:6]

    # Detect sources that degraded by >20 pts since the last pipeline snapshot
    prev_snapshot = last_active.get("_reliability_snapshot", {})
    degraded_sources = []
    if prev_snapshot:
        for site in config["sites"]:
            name = site["name"]
            if site.get("type") in ("skip", "html_TODO"):
                continue
            prev_score = prev_snapshot.get(name)
            if prev_score is None or prev_score < 70:
                continue
            counts = seven_day.get(name, {})
            week_count = sum(v for k, v in counts.items() if k >= cutoff_str)
            curr_score = _compute_reliability(
                name, week_count, last_active.get(name),
                name in currently_failing, ioc_by_site, ratings,
            )
            if curr_score < 50:
                degraded_sources.append({
                    "name": name,
                    "prev": prev_score,
                    "curr": curr_score,
                    "drop": prev_score - curr_score,
                })
        degraded_sources.sort(key=lambda x: x["drop"], reverse=True)

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    narrative = generate_narrative(
        active_sites, stale_sites, ioc_stats, top_ttps,
        degraded_sources, report_date, anthropic_key,
    )

    stale_label = f"{len(stale_sites)} stale" if stale_sites else "all clear"
    ioc_label   = f", {ioc_stats['total']} active IOCs" if ioc_stats else ""
    print(
        f"Weekly report ({report_date}): {stale_label} of {total_active} sites{ioc_label}. Sending email."
    )

    send_stale_email(
        stale_sites, active_sites, total_active, report_date,
        ai_weekly_cost=ai_weekly_cost,
        ioc_stats=ioc_stats,
        ioc_by_site=ioc_by_site,
        ratings=ratings,
        last_active_raw=last_active,
        failing_set=currently_failing,
        degraded_sources=degraded_sources if degraded_sources else None,
        narrative=narrative,
    )


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python weekly_report.py config.json last_active.json [ioc_export.json]")
        sys.exit(1)
    cfg      = sys.argv[1]
    la       = sys.argv[2]
    ioc_path = sys.argv[3] if len(sys.argv) > 3 else None
    main(cfg, la, ioc_path)
