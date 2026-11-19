"""Hybrid Analysis (CrowdStrike) hash enrichment.

Requires HA_API_KEY environment variable (free tier: 200 req/min, 2000 req/hour).
Supports SHA256, SHA1, and MD5. Returns sandbox verdict, threat score,
and malware family name from the most severe report found.

A hash is only marked ha_checked after a definitive answer (HTTP 200, or 404
meaning "not in the database"). Any other response leaves it unchecked so it
is retried on a later run, and a few consecutive failures stop the batch.
"""
import time
import requests
import psycopg2.extras

HA_URL = "https://www.hybrid-analysis.com/api/v2/search/hash"
SLEEP_BETWEEN = 0.4  # 200 req/min limit → 0.4s gives ~150 req/min with headroom
MAX_CONSECUTIVE_FAILURES = 5

_VERDICT_RANK = {"malicious": 3, "suspicious": 2, "no verdict": 1, "whitelisted": 0}
_EMPTY = {"verdict": None, "threat_score": None, "malware_family": None}
_logged_shape = False


def _reports(payload) -> list:
    """Normalise the response into a list of report dicts (API returns a list or {"reports": [...]})."""
    if isinstance(payload, dict):
        payload = payload.get("reports") or []
    return [r for r in payload if isinstance(r, dict)] if isinstance(payload, list) else []


def _lookup(value: str, api_key: str):
    """Returns a result dict, or None when the response was not a definitive answer."""
    global _logged_shape
    try:
        resp = requests.get(
            HA_URL,
            headers={"api-key": api_key, "User-Agent": "Falcon Sandbox"},
            params={"hash": value},
            timeout=20,
        )
    except requests.RequestException as e:
        print(f"Hybrid Analysis request failed: {e}")
        return None
    if resp.status_code in (401, 403, 429):
        raise RuntimeError(f"HA rate limit or auth failure ({resp.status_code})")
    if resp.status_code == 404:
        return dict(_EMPTY)
    if resp.status_code == 400 and "expected hashes" in resp.text:
        # Stored value isn't a valid MD5/SHA1/SHA256/SHA512: definitive, never retry it.
        return dict(_EMPTY)
    if resp.status_code != 200:
        print(f"Hybrid Analysis unexpected status {resp.status_code}: {resp.text[:150]!r}")
        return None
    try:
        payload = resp.json()
    except ValueError:
        print(f"Hybrid Analysis non-JSON 200 response: {resp.text[:150]!r}")
        return None
    if not _logged_shape:
        _logged_shape = True
        keys = list(payload.keys()) if isinstance(payload, dict) else f"list[{len(payload)}]"
        print(f"Hybrid Analysis response shape: {type(payload).__name__} {keys}")
    results = _reports(payload)
    if not results:
        return dict(_EMPTY)
    # Pick the most severe verdict across all sandbox reports for this hash.
    best = max(results, key=lambda r: _VERDICT_RANK.get(r.get("verdict") or "no verdict", 1))
    return {
        "verdict":        best.get("verdict"),
        "threat_score":   best.get("threat_score"),
        "malware_family": best.get("vx_family") or best.get("malware_family"),
    }


def enrich_pending_hashes(conn, api_key: str, limit: int = 100) -> None:
    """Enrich hashes not yet checked against Hybrid Analysis."""
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, value, type FROM ioc_indicators "
            "WHERE ha_checked = FALSE "
            "AND type IN ('sha256', 'sha1', 'md5') "
            "ORDER BY created_at DESC LIMIT %s",
            (limit,),
        )
        rows = cur.fetchall()
    done = failures = 0
    for i, row in enumerate(rows):
        if i > 0:
            time.sleep(SLEEP_BETWEEN)
        try:
            result = _lookup(row["value"], api_key)
            if result is None:
                failures += 1
                if failures >= MAX_CONSECUTIVE_FAILURES:
                    print("Hybrid Analysis: too many consecutive failures — stopping early.")
                    break
                continue
            failures = 0
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE ioc_indicators SET "
                    "ha_checked=TRUE, ha_verdict=%s, ha_threat_score=%s, "
                    "ha_malware_family=%s, updated_at=NOW() WHERE id=%s",
                    (result["verdict"], result["threat_score"], result["malware_family"], row["id"]),
                )
            conn.commit()
            done += 1
        except RuntimeError as e:
            print(f"Hybrid Analysis stopping early: {e}")
            conn.rollback()
            break
        except Exception as e:
            print(f"Hybrid Analysis enrichment error ({row['value'][:20]}...): {e}")
            conn.rollback()
    if rows:
        print(f"Hybrid Analysis: enriched {done} of {len(rows)} hash(es).")
