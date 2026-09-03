import requests
import psycopg2.extras

GREYNOISE_URL = "https://api.greynoise.io/v3/community/{ip}"


def enrich_ip(value: str, api_key: str) -> dict | None:
    try:
        resp = requests.get(
            GREYNOISE_URL.format(ip=value),
            headers={"key": api_key},
            timeout=15,
        )
        if resp.status_code == 404:
            return {"noise": False, "riot": False, "classification": "unknown", "name": ""}
        if resp.status_code == 429:
            raise RuntimeError("GreyNoise rate limit")
        if resp.status_code != 200:
            return None
        d = resp.json()
        return {
            "noise":          d.get("noise", False),
            "riot":           d.get("riot", False),
            "classification": d.get("classification", "unknown"),
            "name":           d.get("name", ""),
        }
    except RuntimeError:
        raise
    except Exception:
        return None


def enrich_pending_ips(conn, api_key: str, limit: int = 50) -> None:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, value FROM ioc_indicators "
            "WHERE greynoise_checked = FALSE AND type IN ('ipv4','ipv6') "
            "ORDER BY created_at DESC LIMIT %s",
            (limit,)
        )
        rows = cur.fetchall()
    for row in rows:
        try:
            result = enrich_ip(row["value"], api_key)
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE ioc_indicators SET greynoise_checked=TRUE, "
                    "greynoise_noise=%s, greynoise_riot=%s, "
                    "greynoise_classification=%s, greynoise_name=%s, updated_at=NOW() "
                    "WHERE id=%s",
                    (
                        result["noise"]          if result else None,
                        result["riot"]           if result else None,
                        result["classification"] if result else None,
                        result["name"]           if result else None,
                        row["id"],
                    ),
                )
            conn.commit()
        except RuntimeError:
            print("GreyNoise rate limit reached — stopping enrichment early.")
            conn.rollback()
            break
        except Exception as e:
            print(f"GreyNoise enrichment error for {row['value']}: {e}")
            conn.rollback()
