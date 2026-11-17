"""URLhaus host check + RDAP registration data + DNS live resolution, run as one pass.

Registration date lookup order:
  1. RDAP via rdap.org (good gTLD coverage)
  2. python-whois fallback (covers ccTLDs and TLDs without RDAP servers)
"""
import json
import os
import socket
import requests
import psycopg2.extras

import url_refiner

URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/host/"
RDAP_URL    = "https://rdap.org/domain/{domain}"


def _urlhaus_check(value: str) -> dict:
    try:
        key = os.environ.get("URLHAUS_API_KEY", "")
        resp = requests.post(URLHAUS_URL, data={"host": value},
                             headers={"Auth-Key": key} if key else {}, timeout=15)
        if resp.status_code != 200:
            return {"status": None, "threat": None}
        d = resp.json()
        if d.get("query_status") != "is_host":
            return {"status": "not listed", "threat": None}
        bl = d.get("blacklists", {})
        spamhaus = bl.get("spamhaus_dbl", "")
        surbl    = bl.get("surbl", "")
        threat = None
        if spamhaus and spamhaus != "not listed":
            threat = spamhaus
        elif surbl and surbl != "not listed":
            threat = surbl
        return {"status": "listed", "threat": threat}
    except Exception:
        return {"status": None, "threat": None}


def _rdap_check(value: str) -> dict:
    try:
        resp = requests.get(RDAP_URL.format(domain=value), timeout=15, allow_redirects=True)
        if resp.status_code != 200:
            return {"registered": None, "registrar": None}
        d = resp.json()
        registered = None
        for event in d.get("events", []):
            if event.get("eventAction") == "registration":
                registered = (event.get("eventDate") or "")[:10]  # YYYY-MM-DD
                break
        registrar = None
        for entity in d.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [[], []])[1]
                for field in vcard:
                    if isinstance(field, list) and field[0] == "fn":
                        registrar = field[3]
                        break
                if not registrar:
                    registrar = entity.get("handle", None)
                break
        return {"registered": registered, "registrar": registrar}
    except Exception:
        return {"registered": None, "registrar": None}


def _whois_fallback(value: str) -> str | None:
    """Return registration date via python-whois when RDAP returns nothing."""
    try:
        import whois
        w = whois.query(value)
        if w is None:
            return None
        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        if cd is None:
            return None
        return cd.strftime("%Y-%m-%d")
    except Exception:
        return None


def _dns_check(value: str) -> dict:
    try:
        infos = socket.getaddrinfo(value, None, socket.AF_INET)
        ips = list({info[4][0] for info in infos})
        return {"resolves": bool(ips), "ips": ips[:10]}
    except socket.gaierror:
        return {"resolves": False, "ips": []}
    except Exception:
        return {"resolves": None, "ips": []}


def _write_meta(conn, row_id, uh: dict, rdap: dict, dns: dict) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE ioc_indicators SET domain_meta_checked=TRUE, "
            "urlhaus_domain_status=%s, urlhaus_domain_threat=%s, "
            "domain_registered=%s, domain_registrar=%s, "
            "domain_resolves=%s, domain_resolved_ips=%s, "
            "updated_at=NOW() WHERE id=%s",
            (
                uh["status"],
                uh["threat"],
                rdap["registered"],
                rdap["registrar"],
                dns["resolves"],
                json.dumps(dns["ips"]),
                row_id,
            ),
        )
    conn.commit()


def enrich_pending_domains(conn, limit: int = 50) -> None:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, value FROM ioc_indicators "
            "WHERE domain_meta_checked = FALSE AND type = 'domain'"
            "ORDER BY created_at DESC LIMIT %s",
            (limit,)
        )
        rows = cur.fetchall()
    for row in rows:
        try:
            uh   = _urlhaus_check(row["value"])
            rdap = _rdap_check(row["value"])
            if rdap["registered"] is None:
                rdap["registered"] = _whois_fallback(row["value"])
            dns  = _dns_check(row["value"])
            _write_meta(conn, row["id"], uh, rdap, dns)
        except Exception as e:
            print(f"Domain meta enrichment error for {row['value']}: {e}")
            conn.rollback()


def _host_meta(host: str, cache: dict):
    """URLhaus + RDAP + DNS for a URL's host, cached so URLs sharing a host cost one lookup."""
    if host in cache:
        return cache[host]
    uh = _urlhaus_check(host)
    if url_refiner.is_ip_host(host):
        rdap = {"registered": None, "registrar": None}
        dns = {"resolves": None, "ips": [host.strip("[]")]}
    else:
        rdap = _rdap_check(host)
        if rdap["registered"] is None:
            rdap["registered"] = _whois_fallback(host)
        dns = _dns_check(host)
    cache[host] = (uh, rdap, dns)
    return cache[host]


def enrich_pending_url_hosts(conn, limit: int = 50) -> None:
    """Run the host-level checks for stored URL IOCs, writing results onto the URL row."""
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, value FROM ioc_indicators "
            "WHERE domain_meta_checked = FALSE AND type = 'url' "
            "ORDER BY created_at DESC LIMIT %s",
            (limit,)
        )
        rows = cur.fetchall()
    cache: dict = {}
    for row in rows:
        try:
            host = url_refiner.host_of(row["value"])
            if not host:
                _write_meta(conn, row["id"], {"status": None, "threat": None},
                            {"registered": None, "registrar": None}, {"resolves": None, "ips": []})
                continue
            uh, rdap, dns = _host_meta(host, cache)
            _write_meta(conn, row["id"], uh, rdap, dns)
        except Exception as e:
            print(f"URL host enrichment error for {row['value'][:60]}: {e}")
            conn.rollback()
    if rows:
        print(f"URL host enrichment: {len(rows)} URL(s) processed ({len(cache)} unique host(s)).")
