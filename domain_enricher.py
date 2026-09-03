"""URLhaus host check + RDAP registration data + DNS live resolution, run as one pass."""
import json
import socket
import requests
import psycopg2.extras

URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/host/"
RDAP_URL    = "https://rdap.org/domain/{domain}"


def _urlhaus_check(value: str) -> dict:
    try:
        resp = requests.post(URLHAUS_URL, data={"host": value}, timeout=15)
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


def _dns_check(value: str) -> dict:
    try:
        infos = socket.getaddrinfo(value, None, socket.AF_INET)
        ips = list({info[4][0] for info in infos})
        return {"resolves": bool(ips), "ips": ips[:10]}
    except socket.gaierror:
        return {"resolves": False, "ips": []}
    except Exception:
        return {"resolves": None, "ips": []}


def enrich_pending_domains(conn, limit: int = 50) -> None:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, value FROM ioc_indicators "
            "WHERE domain_meta_checked = FALSE AND type = 'fqdn' "
            "ORDER BY created_at DESC LIMIT %s",
            (limit,)
        )
        rows = cur.fetchall()
    for row in rows:
        try:
            uh   = _urlhaus_check(row["value"])
            rdap = _rdap_check(row["value"])
            dns  = _dns_check(row["value"])
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
                        row["id"],
                    ),
                )
            conn.commit()
        except Exception as e:
            print(f"Domain meta enrichment error for {row['value']}: {e}")
            conn.rollback()
