import json
import time
from datetime import datetime, timezone
import requests
import psycopg2.extras

VT_URL = "https://www.virustotal.com/api/v3/domains/{domain}"
SLEEP_BETWEEN = 15  # VT free tier: 4 req/min


def enrich_domain(value: str, api_key: str) -> dict | None:
    try:
        resp = requests.get(
            VT_URL.format(domain=value),
            headers={"x-apikey": api_key},
            timeout=20,
        )
        if resp.status_code == 429:
            raise RuntimeError("VT domain rate limit")
        if resp.status_code == 404:
            return {"malicious": 0, "categories": {}, "creation_date": None}
        if resp.status_code != 200:
            return None
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        creation_date = None
        raw_ts = attrs.get("creation_date")
        if raw_ts:
            try:
                creation_date = datetime.fromtimestamp(int(raw_ts), tz=timezone.utc).strftime("%Y-%m-%d")
            except Exception:
                pass
        return {
            "malicious":     stats.get("malicious", 0),
            "categories":    attrs.get("categories", {}),
            "creation_date": creation_date,
        }
    except RuntimeError:
        raise
    except Exception:
        return None


def enrich_pending_domains(conn, api_key: str, limit: int = 30) -> None:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, value, domain_registered FROM ioc_indicators "
            "WHERE vt_domain_checked = FALSE AND type = 'domain'"
            "ORDER BY created_at DESC LIMIT %s",
            (limit,)
        )
        rows = cur.fetchall()
    for i, row in enumerate(rows):
        if i > 0:
            time.sleep(SLEEP_BETWEEN)
        try:
            result = enrich_domain(row["value"], api_key)
            # Only write creation_date when RDAP hasn't already filled it in.
            new_reg = result["creation_date"] if result else None
            if row.get("domain_registered"):
                new_reg = row["domain_registered"]
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE ioc_indicators SET vt_domain_checked=TRUE, "
                    "vt_domain_malicious=%s, vt_domain_categories=%s, "
                    "domain_registered=COALESCE(domain_registered, %s), "
                    "updated_at=NOW() WHERE id=%s",
                    (
                        result["malicious"]              if result else None,
                        json.dumps(result["categories"]) if result else None,
                        new_reg,
                        row["id"],
                    ),
                )
            conn.commit()
        except RuntimeError:
            print("VT domain rate limit reached — stopping enrichment early.")
            conn.rollback()
            break
        except Exception as e:
            print(f"VT domain enrichment error for {row['value']}: {e}")
            conn.rollback()
