import logging
import requests
import psycopg2.extras

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def enrich_ip(value: str, api_key: str) -> dict | None:
    try:
        resp = requests.get(
            ABUSEIPDB_URL,
            params={"ipAddress": value, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=15,
        )
        if resp.status_code == 429:
            raise RuntimeError("AbuseIPDB rate limit")
        if resp.status_code != 200:
            return None
        d = resp.json().get("data", {})
        return {
            "score":       d.get("abuseConfidenceScore", 0),
            "reports":     d.get("totalReports", 0),
            "isp":         d.get("isp", ""),
            "usage_type":  d.get("usageType", ""),
        }
    except RuntimeError:
        raise
    except Exception:
        return None


def enrich_pending_ips(conn, api_key: str, limit: int = 20) -> None:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, value FROM ioc_indicators "
            "WHERE abuseipdb_checked = FALSE AND type IN ('ipv4','ipv6') "
            "ORDER BY created_at DESC LIMIT %s",
            (limit,)
        )
        rows = cur.fetchall()
    for row in rows:
        try:
            result = enrich_ip(row["value"], api_key)
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE ioc_indicators SET abuseipdb_checked=TRUE, "
                    "abuseipdb_score=%s, abuseipdb_reports=%s, "
                    "abuseipdb_isp=%s, abuseipdb_usage_type=%s, updated_at=NOW() "
                    "WHERE id=%s",
                    (
                        result["score"]      if result else None,
                        result["reports"]    if result else None,
                        result["isp"]        if result else None,
                        result["usage_type"] if result else None,
                        row["id"],
                    ),
                )
            conn.commit()
        except RuntimeError:
            logging.warning("AbuseIPDB rate limit reached — stopping enrichment early.")
            conn.rollback()
            break
        except Exception as e:
            logging.warning(f"AbuseIPDB enrichment error for {row['value']}: {e}")
            conn.rollback()
