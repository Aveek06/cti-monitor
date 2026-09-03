import requests
import psycopg2.extras

IPINFO_URL = "https://ipinfo.io/{ip}/json"


def enrich_ip(value: str, api_key: str) -> dict | None:
    try:
        resp = requests.get(
            IPINFO_URL.format(ip=value),
            params={"token": api_key},
            timeout=15,
        )
        if resp.status_code == 429:
            raise RuntimeError("IPinfo rate limit")
        if resp.status_code != 200:
            return None
        d = resp.json()
        return {
            "org":      d.get("org", ""),       # e.g. "AS14061 DigitalOcean, LLC"
            "country":  d.get("country", ""),
            "city":     d.get("city", ""),
            "hostname": d.get("hostname", ""),
        }
    except RuntimeError:
        raise
    except Exception:
        return None


def enrich_pending_ips(conn, api_key: str, limit: int = 50) -> None:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, value FROM ioc_indicators "
            "WHERE ipinfo_checked = FALSE AND type IN ('ipv4','ipv6') "
            "ORDER BY created_at DESC LIMIT %s",
            (limit,)
        )
        rows = cur.fetchall()
    for row in rows:
        try:
            result = enrich_ip(row["value"], api_key)
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE ioc_indicators SET ipinfo_checked=TRUE, "
                    "ipinfo_org=%s, ipinfo_country=%s, ipinfo_city=%s, "
                    "ipinfo_hostname=%s, updated_at=NOW() "
                    "WHERE id=%s",
                    (
                        result["org"]      if result else None,
                        result["country"]  if result else None,
                        result["city"]     if result else None,
                        result["hostname"] if result else None,
                        row["id"],
                    ),
                )
            conn.commit()
        except RuntimeError:
            print("IPinfo rate limit reached — stopping enrichment early.")
            conn.rollback()
            break
        except Exception as e:
            print(f"IPinfo enrichment error for {row['value']}: {e}")
            conn.rollback()
