import time
import requests

VT_URL        = "https://www.virustotal.com/api/v3/files/{hash}"
VT_IP_URL     = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
MIN_MALICIOUS    = 10  # threshold for hashes (many AV engines)
MIN_MALICIOUS_IP = 3   # threshold for IPs (fewer engines report IPs)
RATE_SLEEP    = 15  # free tier = 4 requests/min


def enrich_hash(value: str, api_key: str) -> dict | None:
    try:
        resp = requests.get(
            VT_URL.format(hash=value),
            headers={"x-apikey": api_key},
            timeout=15,
        )
        if resp.status_code == 404:
            return None
        if resp.status_code == 429:
            raise RuntimeError("VT rate limit")
        if resp.status_code != 200:
            return None
        attrs = resp.json().get("data", {}).get("attributes", {})
        malicious = attrs.get("last_analysis_stats", {}).get("malicious", 0)
        if malicious < MIN_MALICIOUS:
            return None
        first_sub = attrs.get("first_submission_date", 0)
        last_sub  = attrs.get("last_submission_date", 0)
        ttl_days  = max(1, (last_sub - first_sub) // 86400) if first_sub and last_sub else None
        return {"malicious_count": malicious, "vt_ttl_days": ttl_days}
    except RuntimeError:
        raise
    except Exception:
        return None


def enrich_ip(value: str, api_key: str) -> dict | None:
    try:
        resp = requests.get(
            VT_IP_URL.format(ip=value),
            headers={"x-apikey": api_key},
            timeout=15,
        )
        if resp.status_code == 404:
            return None
        if resp.status_code == 429:
            raise RuntimeError("VT rate limit")
        if resp.status_code != 200:
            return None
        attrs = resp.json().get("data", {}).get("attributes", {})
        malicious = attrs.get("last_analysis_stats", {}).get("malicious", 0)
        if malicious < MIN_MALICIOUS_IP:
            return None
        return {"malicious_count": malicious, "vt_ttl_days": None}
    except RuntimeError:
        raise
    except Exception:
        return None


def enrich_pending_ips(conn, api_key: str) -> None:
    import psycopg2.extras
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, value, type FROM ioc_indicators "
            "WHERE vt_verified = FALSE AND type IN ('ipv4','ipv6') "
            "ORDER BY created_at DESC LIMIT 20"
        )
        rows = cur.fetchall()
    for row in rows:
        try:
            result = enrich_ip(row["value"], api_key)
            with conn.cursor() as cur:
                if result is None:
                    cur.execute(
                        "UPDATE ioc_indicators SET vt_verified=TRUE, updated_at=NOW() WHERE id=%s",
                        (row["id"],),
                    )
                else:
                    cur.execute(
                        "UPDATE ioc_indicators SET vt_verified=TRUE, vt_malicious=%s, "
                        "vt_ttl_days=%s, updated_at=NOW() WHERE id=%s",
                        (result["malicious_count"], result["vt_ttl_days"], row["id"]),
                    )
            conn.commit()
            time.sleep(RATE_SLEEP)
        except RuntimeError:
            print("VT rate limit reached — stopping IP enrichment early.")
            conn.rollback()
            break
        except Exception as e:
            print(f"VT IP enrichment error for {row['value']}: {e}")
            conn.rollback()


def enrich_pending_hashes(conn, api_key: str) -> None:
    import psycopg2.extras
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, value, type FROM ioc_indicators "
            "WHERE vt_verified = FALSE AND type IN ('sha256','sha1') "
            "ORDER BY created_at DESC LIMIT 20"
        )
        rows = cur.fetchall()
    for row in rows:
        try:
            result = enrich_hash(row["value"], api_key)
            with conn.cursor() as cur:
                if result is None:
                    cur.execute(
                        "UPDATE ioc_indicators SET vt_verified=TRUE, updated_at=NOW() WHERE id=%s",
                        (row["id"],),
                    )
                else:
                    cur.execute(
                        "UPDATE ioc_indicators SET vt_verified=TRUE, vt_malicious=%s, "
                        "vt_ttl_days=%s, updated_at=NOW() WHERE id=%s",
                        (result["malicious_count"], result["vt_ttl_days"], row["id"]),
                    )
            conn.commit()
            time.sleep(RATE_SLEEP)
        except RuntimeError:
            print("VT rate limit reached — stopping enrichment early.")
            conn.rollback()
            break
        except Exception as e:
            print(f"VT enrichment error for {row['value']}: {e}")
            conn.rollback()
