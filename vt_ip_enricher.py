"""VirusTotal IP address enrichment.

Requires VT_API_KEY_IP environment variable (free tier: 4 req/min).
Queries /api/v3/ip_addresses/{ip} for IPv4 and IPv6 IOCs and writes
vt_verified + vt_malicious — the same columns used by the hash enricher,
so get_verdict() picks them up via the existing VT vote path.
"""
import time
import requests
import psycopg2.extras

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
SLEEP_BETWEEN = 15  # VT free tier: 4 req/min


def enrich_ip(value: str, api_key: str) -> dict | None:
    try:
        resp = requests.get(
            VT_URL.format(ip=value),
            headers={"x-apikey": api_key},
            timeout=20,
        )
        if resp.status_code == 429:
            raise RuntimeError("VT IP rate limit")
        if resp.status_code == 404:
            return {"malicious": 0}
        if resp.status_code != 200:
            return None
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {"malicious": stats.get("malicious", 0)}
    except RuntimeError:
        raise
    except Exception:
        return None


def enrich_pending_ips(conn, api_key: str, limit: int = 20) -> None:
    """Enrich IP IOCs not yet checked against VirusTotal."""
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, value FROM ioc_indicators "
            "WHERE vt_verified = FALSE AND type IN ('ipv4', 'ipv6') "
            "ORDER BY created_at DESC LIMIT %s",
            (limit,),
        )
        rows = cur.fetchall()
    for i, row in enumerate(rows):
        if i > 0:
            time.sleep(SLEEP_BETWEEN)
        try:
            result = enrich_ip(row["value"], api_key)
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE ioc_indicators SET "
                    "vt_verified=TRUE, vt_malicious=%s, updated_at=NOW() "
                    "WHERE id=%s",
                    (result["malicious"] if result else None, row["id"]),
                )
            conn.commit()
        except RuntimeError:
            print("VT IP rate limit reached — stopping enrichment early.")
            conn.rollback()
            break
        except Exception as e:
            print(f"VT IP enrichment error ({row['value']}): {e}")
            conn.rollback()
    if rows:
        print(f"VT IP enricher: enriched {len(rows)} IP(s).")
