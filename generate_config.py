"""
Builds the starter config.json for the scraper pipeline directly from your
feed-check results file. Confirmed feed sites are fully configured
automatically. Non-feed sites are added as stubs you fill in later using
inspect_site.py. Known dead-ends (bot-walled, dead domains) are marked
skip=true so the scraper ignores them without deleting the record.

Usage:
    python generate_config.py CTI_Feed_Check_Round4.xlsx config.json
"""

import sys
import json
import openpyxl

# Sites confirmed as real bot-walls or dead domains as of round 4 - not worth
# retrying automatically. Edit this list if you later find a workaround.
KNOWN_DEADENDS = {
    "Akamai", "Human Security", "iZoologic", "F.A.C.C.T.", "Forescout",
    "SOCradar", "Blackpoint", "Lab52",
}

# Heuristic matches from the browser-href-heuristic round that were confirmed
# junk on manual review (sitemap.xml, single-post links, unrelated feeds).
# Adjust this set based on what you find when you manually check the 13.
KNOWN_JUNK_HEURISTIC_MATCHES = {
    "Datadog Security Labs", "txOne", "AFINE", "GetSafety", "Netcraft", "Lumen",
}


def main(input_path, output_path):
    wb = openpyxl.load_workbook(input_path, data_only=True)
    ws = wb.active
    rows = list(ws.iter_rows(min_row=2, values_only=True))
    header = ["Blog Name", "Original URL", "Feed Found", "Feed URL", "Detection Method", "Notes"]

    sites = []
    for r in rows:
        d = dict(zip(header, r))
        name = d["Blog Name"]
        base_url = (d["Original URL"] or "").split("\n")[0].strip()

        if name in KNOWN_DEADENDS:
            sites.append({
                "name": name, "type": "skip", "url": base_url,
                "notes": "Bot-walled or dead domain as of last check - manual monitoring only"
            })
            continue

        if d["Feed Found"] == "Yes" and name not in KNOWN_JUNK_HEURISTIC_MATCHES:
            sites.append({
                "name": name,
                "type": "feed",
                "url": d["Feed URL"],
            })
            continue

        # Everything else: needs manual selector config
        sites.append({
            "name": name,
            "type": "html_TODO",
            "url": base_url,
            "post_container": "TODO - CSS selector matching each post card/row",
            "link_selector": "TODO - CSS selector for the <a> tag within a post card, or 'self' if the container itself is the <a>",
            "date_selector": "TODO - CSS selector for the date element within a post card, or null if no date shown on listing page",
            "date_format": "TODO - e.g. '%B %d, %Y' for 'January 5, 2026', or 'auto' to try common formats",
            "needs_js": True,
            "notes": "Run inspect_site.py on this URL to get selector suggestions"
        })

    config = {"sites": sites}
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    counts = {}
    for s in sites:
        counts[s["type"]] = counts.get(s["type"], 0) + 1
    print("Config generated:", counts)
    print(f"Saved to {output_path}")
    print(f"\nNext: run inspect_site.py against each 'html_TODO' site to fill in selectors.")


if __name__ == "__main__":
    inp = sys.argv[1] if len(sys.argv) > 1 else "CTI_Feed_Check_Round4.xlsx"
    out = sys.argv[2] if len(sys.argv) > 2 else "config.json"
    main(inp, out)
