"""MalwareBazaar + ThreatFox enrichment for SHA256/SHA1/MD5 hashes, run as one pass."""
import json
import requests
import psycopg2.extras

MB_URL = "https://mb-api.abuse.ch/api/v1/"
TF_URL = "https://threatfox-api.abuse.ch/api/v1/"


def _malwarebazaar_check(value: str) -> dict:
    try:
        resp = requests.post(MB_URL, data={"query": "get_info", "hash": value}, timeout=15)
        if resp.status_code != 200:
            return {"found": False}
        d = resp.json()
        if d.get("query_status") != "hash_present":
            return {"found": False}
        data = (d.get("data") or [{}])[0]
        return {
            "found":     True,
            "file_type": data.get("file_type", "") or "",
            "file_name": data.get("file_name", "") or "",
            "signature": data.get("signature", "") or "",  # malware family
            "tags":      data.get("tags") or [],
        }
    except Exception:
        return {"found": False}


def _threatfox_check(value: str) -> dict:
    try:
        resp = requests.post(TF_URL, json={"query": "search_ioc", "search_term": value}, timeout=15)
        if resp.status_code != 200:
            return {"found": False}
        d = resp.json()
        if d.get("query_status") != "ok" or not d.get("data"):
            return {"found": False}
        best = max(d["data"], key=lambda x: x.get("confidence_level", 0))
        return {
            "found":       True,
            "threat_type": best.get("threat_type", "") or "",
            "malware":     best.get("malware", "") or "",
            "confidence":  best.get("confidence_level", 0),
        }
    except Exception:
        return {"found": False}


def enrich_pending_hashes(conn, limit: int = 50) -> None:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, value FROM ioc_indicators "
            "WHERE hash_meta_checked = FALSE AND type IN ('sha256','sha1','md5') "
            "ORDER BY created_at DESC LIMIT %s",
            (limit,)
        )
        rows = cur.fetchall()
    for row in rows:
        try:
            mb = _malwarebazaar_check(row["value"])
            tf = _threatfox_check(row["value"])
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE ioc_indicators SET hash_meta_checked=TRUE, "
                    "mb_file_type=%s, mb_file_name=%s, mb_signature=%s, mb_tags=%s, "
                    "tf_threat_type=%s, tf_malware=%s, tf_confidence=%s, "
                    "updated_at=NOW() WHERE id=%s",
                    (
                        mb["file_type"] if mb["found"] else None,
                        mb["file_name"] if mb["found"] else None,
                        mb["signature"] if mb["found"] else None,
                        json.dumps(mb["tags"]) if mb["found"] else None,
                        tf["threat_type"] if tf["found"] else None,
                        tf["malware"]     if tf["found"] else None,
                        tf["confidence"]  if tf["found"] else None,
                        row["id"],
                    ),
                )
            conn.commit()
        except Exception as e:
            print(f"Hash meta enrichment error for {row['value']}: {e}")
            conn.rollback()
