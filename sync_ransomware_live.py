"""Daily sync of ransomware.live Pro API group profiles into
threat_actor_profiles, plus a feed of supported-type IOCs into the main
ioc_indicators table.

Unlike the MITRE sync, this runs from inside ioc_pipeline.py on every
pipeline invocation (ransomware.live's victim/leak-site data changes daily).
Requires RANSOMWARE_LIVE_API_KEY -- never commit the literal key value
anywhere; it is read from the environment only.

Two-phase design, verified directly against the live Pro API:
  1. Bulk index calls (/groups, /negotiations, /iocs, /ransomnotes) are
     lightweight group-name + count summaries -- used to skip a detail call
     entirely for groups with zero data of that kind.
  2. Per matched group, detail calls (/groups/{name}, /negotiations/{name},
     /iocs/{name}, /ransomnotes/{name}, /victims/) fetch the real content.
No rate-limit sleep is needed -- 500,000 req/month makes ~160 calls/run a
non-issue.
"""
import datetime
import ipaddress
import os

import requests

import actor_matching
import ioc_db
import ioc_scorer
import stix_converter

BASE_URL = "https://api-pro.ransomware.live"
RECENT_VICTIM_WINDOW_DAYS = 90
RECENT_VICTIM_LIMIT = 25

# ransomware.live IOC type -> our internal type. "ip" needs runtime sniffing
# (ipv4 vs ipv6), handled separately. Types not listed here (btc, mutex,
# telegram, tox, twitter, ...) are outside our ioc_indicators taxonomy and
# ioc_scorer decay model -- explicitly skipped and counted, never silently
# dropped without visibility.
_SUPPORTED_TYPES = {"md5", "sha256", "sha1", "domain", "url", "email"}


def _get(path: str, api_key: str, params: dict | None = None) -> dict:
    resp = requests.get(
        f"{BASE_URL}{path}",
        headers={"X-API-KEY": api_key},
        params=params or {},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def _parse_usd(s) -> float | None:
    if not s or not isinstance(s, str) or s.strip().upper() == "N/A":
        return None
    try:
        return float(s.replace("$", "").replace(",", "").strip())
    except ValueError:
        return None


def _date_only(iso_str: str | None) -> str | None:
    if not iso_str:
        return None
    return iso_str.split("T")[0]


def _build_negotiation_stats(chats: list[dict]) -> dict | None:
    if not chats:
        return None
    initial = [v for v in (_parse_usd(c.get("initialransom")) for c in chats) if v is not None]
    negotiated = [v for v in (_parse_usd(c.get("negotiatedransom")) for c in chats) if v is not None]
    paid_count = sum(1 for c in chats if c.get("paid"))
    return {
        "chat_count": len(chats),
        "avg_initial_usd": round(sum(initial) / len(initial), 2) if initial else None,
        "avg_negotiated_usd": round(sum(negotiated) / len(negotiated), 2) if negotiated else None,
        "payment_rate": round(paid_count / len(chats), 3),
    }


def sync(conn, api_key: str, rel_lookup: dict | None = None) -> dict:
    ioc_db.init_actor_profile_schema(conn)

    print("sync_ransomware_live: fetching bulk index endpoints...")
    groups_idx = _get("/groups", api_key).get("groups", [])
    negotiations_idx = {g["group"]: g.get("chats", 0) for g in _get("/negotiations", api_key).get("groups", [])}
    iocs_idx = {g["group"]: g.get("ioc_types", {}) for g in _get("/iocs", api_key).get("groups", [])}
    ransomnotes_idx = {g["group"]: g.get("ransomnotes_count", 0) for g in _get("/ransomnotes", api_key).get("groups", [])}
    print(f"sync_ransomware_live: {len(groups_idx)} groups in index.")

    index = actor_matching.build_alias_index()
    stats = {"exact": 0, "alias": 0, "unmatched": 0, "iocs_imported": 0, "iocs_skipped_unsupported": 0}
    cutoff = (datetime.date.today() - datetime.timedelta(days=RECENT_VICTIM_WINDOW_DAYS)).isoformat()

    for entry in groups_idx:
        slug = entry.get("group")
        if not slug:
            continue
        altname = entry.get("altname")
        canonical, method = actor_matching.match_actor(index, slug, [altname] if altname else [])
        if not canonical:
            stats["unmatched"] += 1
            continue
        stats[method] += 1

        try:
            detail = _get(f"/groups/{slug}", api_key)
        except Exception as e:
            print(f"sync_ransomware_live: /groups/{slug} failed: {e}")
            continue

        chats = []
        if negotiations_idx.get(slug, 0) > 0:
            try:
                chats = _get(f"/negotiations/{slug}", api_key).get("chats", [])
            except Exception as e:
                print(f"sync_ransomware_live: /negotiations/{slug} failed: {e}")

        ransom_note_names = []
        if ransomnotes_idx.get(slug, 0) > 0:
            try:
                ransom_note_names = _get(f"/ransomnotes/{slug}", api_key).get("ransomnotes", [])
            except Exception as e:
                print(f"sync_ransomware_live: /ransomnotes/{slug} failed: {e}")

        raw_iocs: dict = {}
        if iocs_idx.get(slug):
            try:
                raw_iocs = _get(f"/iocs/{slug}", api_key).get("iocs", {})
            except Exception as e:
                print(f"sync_ransomware_live: /iocs/{slug} failed: {e}")

        recent_victims, sectors = [], set()
        try:
            victims_resp = _get("/victims/", api_key, params={"group": slug})
            for v in victims_resp.get("victims", []):
                attackdate = v.get("attackdate") or v.get("discovered") or ""
                if attackdate and _date_only(attackdate) < cutoff:
                    continue
                sector = v.get("activity")
                if sector:
                    sectors.add(sector)
                recent_victims.append({
                    "victim": v.get("victim"),
                    "activity": sector,
                    "country": v.get("country"),
                    "attackdate": _date_only(attackdate),
                    "description": (v.get("description") or "")[:300],
                })
                if len(recent_victims) >= RECENT_VICTIM_LIMIT:
                    break
        except Exception as e:
            print(f"sync_ransomware_live: /victims/ for {slug} failed: {e}")

        try:
            ioc_db.upsert_ransomware_profile(
                conn, canonical,
                ransomware_live_id=slug,
                ransomware_description=detail.get("description"),
                victim_count=detail.get("victims"),
                first_seen_rw=_date_only(detail.get("firstseen")),
                last_seen_rw=_date_only(detail.get("lastseen")),
                recent_victims=recent_victims,
                sectors_targeted=sorted(sectors),
                tools=detail.get("tools", {}),
                ransomware_ttps=detail.get("ttps", []),
                leak_sites=detail.get("locations", []),
                vulnerabilities=detail.get("vulnerabilities", []),
                negotiation_stats=_build_negotiation_stats(chats),
                ransom_note_names=ransom_note_names,
                match_method=method,
            )
        except Exception as e:
            print(f"sync_ransomware_live: upsert failed for '{canonical}': {e}")
            conn.rollback()
            continue

        # Feed supported-type IOCs into the main pipeline.
        group_permalink = f"https://www.ransomware.live/group/{slug}"
        last_seen = _date_only(detail.get("lastseen")) or datetime.date.today().isoformat()
        site_rel = 80
        if rel_lookup:
            site_rel = int(rel_lookup.get("ransomware.live", 80))

        for raw_type, values in raw_iocs.items():
            if raw_type == "ip":
                for v in values:
                    try:
                        ip_type = "ipv6" if isinstance(ipaddress.ip_address(v), ipaddress.IPv6Address) else "ipv4"
                    except ValueError:
                        stats["iocs_skipped_unsupported"] += 1
                        continue
                    _upsert_rw_ioc(conn, v, ip_type, canonical, last_seen, group_permalink, site_rel)
                    stats["iocs_imported"] += 1
            elif raw_type in _SUPPORTED_TYPES:
                for v in values:
                    _upsert_rw_ioc(conn, v, raw_type, canonical, last_seen, group_permalink, site_rel)
                    stats["iocs_imported"] += 1
            else:
                stats["iocs_skipped_unsupported"] += len(values)

    print(f"sync_ransomware_live: done. exact={stats['exact']} alias={stats['alias']} "
          f"unmatched={stats['unmatched']} iocs_imported={stats['iocs_imported']} "
          f"iocs_skipped_unsupported={stats['iocs_skipped_unsupported']}")
    return stats


def _upsert_rw_ioc(conn, value: str, ioc_type: str, apt: str, last_seen: str,
                    group_permalink: str, site_reliability: int):
    try:
        stix_obj = stix_converter.ioc_to_indicator(
            value, ioc_type, last_seen, group_permalink, "ransomware.live", last_seen,
        )
        ioc_db.upsert_ioc(
            conn, stix_obj, value, ioc_type,
            first_seen=last_seen, last_seen=last_seen,
            apt=apt,
            ltv=ioc_scorer.get_ltv(apt, ioc_type),
            tau=ioc_scorer.TAU_DEFAULT.get(ioc_scorer.ioc_group(ioc_type), 30),
            source_article=group_permalink,
            source_blog="ransomware.live",
            apt_match_method="ransomware_live",
            site_reliability=site_reliability,
        )
    except Exception as e:
        print(f"sync_ransomware_live: IOC upsert failed ({value[:30]}...): {e}")
        conn.rollback()


if __name__ == "__main__":
    import sys
    import psycopg2

    db_url = os.environ.get("DATABASE_URL")
    key = os.environ.get("RANSOMWARE_LIVE_API_KEY")
    if not db_url:
        print("sync_ransomware_live: DATABASE_URL not set.")
        sys.exit(1)
    if not key:
        print("sync_ransomware_live: RANSOMWARE_LIVE_API_KEY not set.")
        sys.exit(1)
    connection = psycopg2.connect(db_url)
    try:
        sync(connection, key)
    finally:
        connection.close()
