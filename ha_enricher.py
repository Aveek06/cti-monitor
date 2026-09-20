"""Hybrid Analysis (CrowdStrike) hash enrichment.

Requires HA_API_KEY environment variable (free tier: ~100 req/min).
Supports SHA256, SHA1, and MD5. Returns sandbox verdict, threat score,
and malware family name from the most severe report found.
"""
import time
import requests
import psycopg2.extras

HA_URL = "https://www.hybrid-analysis.com/api/v2/search/hash"
SLEEP_BETWEEN = 0.4  # 200 req/min limit → 0.4s gives ~150 req/min with headroom

_VERDICT_RANK = {"malicious": 3, "suspicious": 2, "no verdict": 1, "whitelisted": 0}


def _lookup(value: str, api_key: str) -> dict:
    try:
        resp = requests.post(
            HA_URL,
            headers={"api-key": api_key, "User-Agent": "Falcon Sandbox"},
            data={"hash": value},
            timeout=20,
        )
        if resp.status_code == 429:
            raise RuntimeError("HA rate limit")
        if resp.status_code != 200:
            return {"verdict": None, "threat_score": None, "malware_family": None}
        results = resp.json()
        if not results:
            return {"verdict": None, "threat_score": None, "malware_family": None}
        # Pick the most severe verdict across all sandbox reports for this hash.
        best = max(results, key=lambda r: _VERDICT_RANK.get(r.get("verdict") or "no verdict", 1))
        return {
            "verdict":        best.get("verdict"),
            "threat_score":   best.get("threat_score"),
            "malware_family": best.get("vx_family") or best.get("malware_family"),
        }
    except RuntimeError:
        raise
    except Exception:
        return {"verdict": None, "threat_score": None, "malware_family": None}


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
    for i, row in enumerate(rows):
        if i > 0:
            time.sleep(SLEEP_BETWEEN)
        try:
            result = _lookup(row["value"], api_key)
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE ioc_indicators SET "
                    "ha_checked=TRUE, ha_verdict=%s, ha_threat_score=%s, "
                    "ha_malware_family=%s, updated_at=NOW() WHERE id=%s",
                    (result["verdict"], result["threat_score"], result["malware_family"], row["id"]),
                )
            conn.commit()
        except RuntimeError:
            print("Hybrid Analysis rate limit reached — stopping enrichment early.")
            conn.rollback()
            break
        except Exception as e:
            print(f"Hybrid Analysis enrichment error ({row['value'][:20]}...): {e}")
            conn.rollback()
    if rows:
        print(f"Hybrid Analysis: enriched {len(rows)} hash(es).")
