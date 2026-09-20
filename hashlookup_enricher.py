"""CIRCL HASHLOOKUP enrichment — no API key required.

Checks SHA256, SHA1, and MD5 hashes against the CIRCL HASHLOOKUP dataset
(NSRL, open malware corpora, software package registries). A high trust
score (>= 70) indicates a known-good file, which is used as a clean signal
in verdict classification to reduce false positives.
"""
import requests
import psycopg2.extras

HASHLOOKUP_URL = "https://hashlookup.circl.lu/lookup/{algo}/{value}"

_ALGO = {"sha256": "sha256", "sha1": "sha1", "md5": "md5"}


def _lookup(value: str, ioc_type: str) -> dict:
    algo = _ALGO.get(ioc_type)
    if not algo:
        return {"known": None, "trust": None}
    try:
        resp = requests.get(
            HASHLOOKUP_URL.format(algo=algo, value=value),
            timeout=10,
        )
        if resp.status_code == 404:
            return {"known": False, "trust": None}
        if resp.status_code != 200:
            return {"known": None, "trust": None}
        d = resp.json()
        raw_trust = d.get("hashlookup:trust")
        trust = int(raw_trust) if raw_trust is not None else None
        return {"known": True, "trust": trust}
    except Exception:
        return {"known": None, "trust": None}


def enrich_pending_hashes(conn, limit: int = 200) -> None:
    """Enrich hashes not yet checked against CIRCL HASHLOOKUP."""
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, value, type FROM ioc_indicators "
            "WHERE hashlookup_checked = FALSE "
            "AND type IN ('sha256', 'sha1', 'md5') "
            "ORDER BY created_at DESC LIMIT %s",
            (limit,),
        )
        rows = cur.fetchall()
    for row in rows:
        result = _lookup(row["value"], row["type"])
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE ioc_indicators SET "
                    "hashlookup_checked=TRUE, hashlookup_known=%s, hashlookup_trust=%s, "
                    "updated_at=NOW() WHERE id=%s",
                    (result["known"], result["trust"], row["id"]),
                )
            conn.commit()
        except Exception as e:
            print(f"HASHLOOKUP enrichment error ({row['value'][:20]}...): {e}")
            conn.rollback()
    if rows:
        print(f"CIRCL HASHLOOKUP: enriched {len(rows)} hash(es).")
