import os
import requests
from datetime import datetime, timezone

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{limit}/"
MAX_URLS = 500


def fetch_url_iocs(api_key: str) -> list[dict]:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    try:
        resp = requests.post(
            URLHAUS_API.format(limit=MAX_URLS),
            headers={"Auth-Key": api_key, "Content-Type": "application/json"},
            json={},
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

        # URLhaus only surfaces online malware-hosting URLs → verdict is always malicious.
        from ioc_scorer import compute_score, TAU_DEFAULT
        tau = TAU_DEFAULT["url"]
        score = compute_score(today, tau, 1.0, "malicious")

        result.append({
            "value":          entry.get("url", ""),
            "type":           "url",
            "apt":            None,
            "score":          score,
            "tau":            float(tau),
            "ltv":            1.0,
            "verdict":        "malicious",
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
