import time
import requests
import psycopg2

VT_URL        = "https://www.virustotal.com/api/v3/files/{hash}"
VT_IP_URL     = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
RATE_SLEEP    = 15  # free tier = 4 requests/min


def enrich_hash(value: str, api_key: str) -> dict | None:
    """Returns the VT result whatever it is (including 0 = clean); None only
    means VT has no record for this hash (404) or the lookup failed."""
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
        first_sub = attrs.get("first_submission_date", 0)
        last_sub  = attrs.get("last_submission_date", 0)
        ttl_days  = max(1, (last_sub - first_sub) // 86400) if first_sub and last_sub else None
        return {"malicious_count": malicious, "vt_ttl_days": ttl_days}
    except RuntimeError:
        raise
    except Exception:
        return None


def enrich_ip(value: str, api_key: str) -> dict | None:
    """Returns the VT result whatever it is (including 0 = clean); None only
    means VT has no record for this IP (404) or the lookup failed."""
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


def _reconnect(conn):
    """Long catchup runs (hundreds of rows, 15s apart) can outlast Supabase's
    pooler connection lifetime. Re-open using the same DSN so the caller's
    reference stays live instead of the whole run crashing on the next query."""
    dsn = conn.dsn
    try:
        conn.close()
    except Exception:
        pass
    return psycopg2.connect(dsn)


def enrich_pending_hashes(conn, api_key: str, limit: int = 30):
    """Returns the live connection (reconnected if the original dropped
    mid-run) so callers running a long catchup loop keep a working conn."""
    import psycopg2.extras
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, value, type FROM ioc_indicators "
            "WHERE vt_verified = FALSE AND type IN ('sha256','sha1','md5') "
            "ORDER BY created_at DESC LIMIT %s",
            (limit,)
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
        except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
            print(f"VT enrichment: connection dropped ({e}); reconnecting...")
            conn = _reconnect(conn)
        except Exception as e:
            print(f"VT enrichment error for {row['value']}: {e}")
            conn.rollback()
    return conn
