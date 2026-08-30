import os
import requests
from datetime import datetime, timezone

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/500/"
MAX_URLS = 500


def fetch_url_iocs(api_key: str) -> list[dict]:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    try:
        resp = requests.post(
            URLHAUS_API,
            headers={"Auth-Key": api_key},
            data={"limit": MAX_URLS},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"URLhaus fetch failed: {e}")
        return []

    if data.get("query_status") != "ok":
        print(f"URLhaus returned: {data.get('query_status')}")
        return []

    urls = data.get("urls") or []
    # Keep only online URLs
    online = [u for u in urls if u.get("url_status") == "online"]
    print(f"URLhaus: {len(urls)} total, {len(online)} online URLs fetched.")

    result = []
    for entry in online[:MAX_URLS]:
        date_added = (entry.get("date_added") or today)[:10]
        tags = entry.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]

        # Compute score: online URL, last_seen = today, tau=7, ltv=1.0 → near 100
        from ioc_scorer import compute_score
        score = compute_score(today, 7.0, 1.0)

        result.append({
            "value":          entry.get("url", ""),
            "type":           "url",
            "apt":            None,
            "score":          score,
            "tau":            7.0,
            "ltv":            1.0,
            "source_blog":    "URLhaus",
            "source_article": entry.get("url", ""),
            "first_seen":     date_added,
            "last_seen":      today,
            "vt_malicious":   None,
            "vt_verified":    False,
            "shodan_tags":    [],
            "shodan_ports":   [],
            # URL-specific extra fields
            "url_status":     entry.get("url_status", "online"),
            "url_threat":     entry.get("threat", ""),
            "url_tags":       tags,
        })

    return result
