import json
import time
import requests

SHODAN_URL = "https://api.shodan.io/shodan/host/{ip}"
RATE_SLEEP  = 1  # 1 req/sec — Shodan membership rate


def enrich_ip(value: str, api_key: str) -> dict | None:
    try:
        resp = requests.get(
            SHODAN_URL.format(ip=value),
            params={"key": api_key},
            timeout=15,
        )
        if resp.status_code == 404:
            return None
        if resp.status_code == 429:
            raise RuntimeError("Shodan rate limit")
        if resp.status_code != 200:
            return None
        data = resp.json()
        return {
            "tags":  data.get("tags")  or [],
            "ports": data.get("ports") or [],
        }
    except RuntimeError:
        raise
    except Exception:
        return None


def enrich_pending_ips(conn, api_key: str) -> None:
    import psycopg2.extras
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, value FROM ioc_indicators "
            "WHERE shodan_checked = FALSE AND type IN ('ipv4','ipv6') "
            "ORDER BY created_at DESC LIMIT 20"
        )
        rows = cur.fetchall()
    for row in rows:
        try:
            result = enrich_ip(row["value"], api_key)
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE ioc_indicators SET shodan_checked=TRUE, shodan_tags=%s, "
                    "shodan_ports=%s, updated_at=NOW() WHERE id=%s",
                    (
                        json.dumps(result["tags"])  if result else None,
                        json.dumps(result["ports"]) if result else None,
                        row["id"],
                    ),
                )
            conn.commit()
            time.sleep(RATE_SLEEP)
        except RuntimeError:
            print("Shodan rate limit reached — stopping enrichment early.")
            conn.rollback()
            break
        except Exception as e:
            print(f"Shodan enrichment error for {row['value']}: {e}")
            conn.rollback()
