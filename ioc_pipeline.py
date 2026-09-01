import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import ioc_extractor
import ioc_scorer
import stix_converter
import ioc_db
import vt_enricher
import shodan_enricher
import ttp_extractor
import urlhaus_fetcher
import ai_extractor


def run(new_items: list[dict], rel_lookup: dict | None = None) -> dict:
    results = {"new": [], "active": [], "expiring": []}

    if not os.environ.get("DATABASE_URL"):
        print("IOC pipeline: DATABASE_URL not set — skipping.")
        return results

    try:
        conn = ioc_db.get_connection()
    except Exception as e:
        print(f"IOC pipeline: DB connection failed: {e}")
        return results

    try:
        ioc_db.init_schema(conn)
        ioc_db.init_ttp_schema(conn)
        ioc_db.init_ratings_schema(conn)
    except Exception as e:
        print(f"IOC pipeline: schema init failed: {e}")
        conn.close()
        return results

    # Auto-prune FP domains and version-number IPs that slipped in before filtering was tightened
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, value FROM ioc_indicators WHERE type = 'domain'")
            rows = cur.fetchall()
        fp_ids = [row[0] for row in rows if ioc_extractor._is_fp(row[1])]
        if fp_ids:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM ioc_indicators WHERE id = ANY(%s)", (fp_ids,))
            conn.commit()
            print(f"IOC pipeline: pruned {len(fp_ids)} false-positive domain(s) from DB.")
    except Exception as e:
        print(f"IOC pipeline: FP domain cleanup failed: {e}")

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, value FROM ioc_indicators WHERE type = 'ipv4'")
            rows = cur.fetchall()
        bogon_ids = []
        for row_id, val in rows:
            if val in ioc_extractor._FP_IPS:
                bogon_ids.append(row_id)
                continue
            parts = val.split(".")
            if len(parts) == 4 and max(int(x) for x in parts) < 60:
                bogon_ids.append(row_id)
        if bogon_ids:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM ioc_indicators WHERE id = ANY(%s)", (bogon_ids,))
            conn.commit()
            print(f"IOC pipeline: pruned {len(bogon_ids)} version-number/bogon IPv4(s) from DB.")
    except Exception as e:
        print(f"IOC pipeline: IPv4 bogon cleanup failed: {e}")

    today          = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    total_iocs     = 0
    total_ttps     = 0
    anthropic_key  = os.environ.get("ANTHROPIC_API_KEY", "")
    ttp_ai_budget  = ttp_extractor.MAX_ARTICLES_PER_RUN  # cost guard

    # Phase 1: fetch all article texts in parallel (requests.get is thread-safe)
    def _fetch_text(item):
        return item, ioc_extractor.fetch_article_text(item["link"]) or ""

    fetched_items: list[tuple] = []
    n_workers = min(10, len(new_items)) if new_items else 0
    if n_workers:
        with ThreadPoolExecutor(max_workers=n_workers) as pool:
            futs = {pool.submit(_fetch_text, it): it for it in new_items}
            for fut in as_completed(futs):
                fetched_items.append(fut.result())
    print(f"IOC pipeline: fetched {len(fetched_items)} article text(s) in parallel.")

    # High-reliability sites process first so they get Claude API budget priority
    if rel_lookup:
        fetched_items.sort(key=lambda x: rel_lookup.get(x[0]["site"], 50), reverse=True)

    # Phase 2: sequential IOC/TTP extraction + DB writes (psycopg2 is not thread-safe)
    for item, text in fetched_items:
        if not text:
            continue
        apt  = ioc_extractor.detect_apt(item["site"] + " " + text)
        iocs = ioc_extractor.extract_iocs(text, item["link"])

        # Combined AI extraction: TTPs + additional IOCs + APT attribution in one call
        use_ai = anthropic_key and ttp_ai_budget > 0
        if use_ai:
            ai = ai_extractor.extract_all(text, item["link"], anthropic_key)
            if ai.get("ttps") or ai.get("iocs") or ai.get("apt"):
                ttp_ai_budget -= 1
            ttps = ai["ttps"] if ai["ttps"] else ttp_extractor.extract_ttps(text, "")
            _seen = {(r["value"], r["type"]) for r in iocs}
            for ai_ioc in (ai["iocs"] or []):
                v, t = ai_ioc.get("value", "").strip(), ai_ioc.get("type", "").strip()
                if not v or not t:
                    continue
                if t == "domain" and ioc_extractor.is_benign_domain(v):
                    continue
                if t == "ipv4" and v in ioc_extractor._FP_IPS:
                    continue
                if t == "ipv4":
                    try:
                        parts = v.split(".")
                        if len(parts) == 4 and max(int(x) for x in parts) < 60:
                            continue
                    except ValueError:
                        pass
                if (v, t) not in _seen:
                    iocs.append({"value": v, "type": t})
                    _seen.add((v, t))
            if ai["apt"]:
                apt = ai["apt"]
        else:
            ttps = ttp_extractor.extract_ttps(text, "")

        for ioc in iocs:
            ltv      = ioc_scorer.get_ltv(apt, ioc["type"])
            if rel_lookup:
                _s = rel_lookup.get(item["site"], 50)
                ltv *= 1.3 if _s >= 70 else 0.7 if _s < 40 else 1.0
            tau      = ioc_scorer.TAU_DEFAULT.get(ioc_scorer.ioc_group(ioc["type"]), 30)
            try:
                stix_obj = stix_converter.ioc_to_indicator(
                    ioc["value"], ioc["type"],
                    item["date"], item["link"], item["site"],
                    today,
                )
                ioc_db.upsert_ioc(
                    conn, stix_obj,
                    ioc["value"], ioc["type"],
                    item["date"], item["date"],
                    apt, ltv, tau,
                    item["link"], item["site"],
                )
                total_iocs += 1
            except Exception as e:
                print(f"IOC upsert failed ({ioc['value'][:20]}...): {e}")
                conn.rollback()

        for ttp in ttps:
            try:
                ioc_db.upsert_ttp(
                    conn,
                    ttp["technique_id"], ttp["technique_name"], ttp["tactic"],
                    item["link"], item["site"], apt, item["date"],
                )
                total_ttps += 1
            except Exception as e:
                print(f"TTP upsert failed ({ttp['technique_id']}): {e}")
                conn.rollback()

    print(f"IOC pipeline: {total_iocs} IOC(s) upserted from {len(fetched_items)} article(s).")
    print(f"IOC pipeline: {total_ttps} TTP(s) upserted.")

    vt_api_key = os.environ.get("VT_API_KEY", "")
    if vt_api_key:
        print("Running VirusTotal enrichment (up to 20 hashes, 15s between calls)...")
        try:
            vt_enricher.enrich_pending_hashes(conn, vt_api_key)
        except Exception as e:
            print(f"VT enrichment error: {e}")
    else:
        print("VT_API_KEY not set — skipping VirusTotal enrichment.")

    shodan_key = os.environ.get("SHODAN_API_KEY", "")
    if shodan_key:
        print("Running Shodan IP enrichment (up to 20 IPs, 1s between calls)...")
        try:
            shodan_enricher.enrich_pending_ips(conn, shodan_key)
        except Exception as e:
            print(f"Shodan enrichment error: {e}")
    else:
        print("SHODAN_API_KEY not set — skipping Shodan enrichment.")

    try:
        results["new"]      = ioc_db.get_new_iocs_since(conn, today)
        all_active          = ioc_db.get_active_iocs(conn, min_score=1)
        results["active"]   = [r for r in all_active if r["score"] >= 30]
        results["expiring"] = [r for r in all_active if r["score"] < 30]

        # Export scored IOC list for the dashboard
        export = sorted([
            {
                "value":          r["value"],
                "type":           r["type"],
                "apt":            r.get("attributed_apt"),
                "score":          r.get("score", 0),
                "tau":            float(r.get("tau") or ioc_scorer.TAU_DEFAULT[ioc_scorer.ioc_group(r["type"])]),
                "ltv":            float(r.get("ltv") or 1.0),
                "source_blog":    r.get("source_blog"),
                "source_article": r.get("source_article"),
                "first_seen":     str(r["first_seen"]),
                "last_seen":      str(r["last_seen"]),
                "vt_malicious":   r.get("vt_malicious"),
                "vt_verified":    r.get("vt_verified", False),
                "shodan_tags":    r.get("shodan_tags") or [],
                "shodan_ports":   r.get("shodan_ports") or [],
            }
            for r in all_active
        ], key=lambda x: x["score"], reverse=True)
        # Merge URLhaus online URLs into the export
        urlhaus_key = os.environ.get("URLHAUS_API_KEY", "")
        if urlhaus_key:
            url_iocs = urlhaus_fetcher.fetch_url_iocs(urlhaus_key)
            if url_iocs:
                export.extend(url_iocs)
                export.sort(key=lambda x: x["score"], reverse=True)
                print(f"IOC pipeline: merged {len(url_iocs)} URLhaus URL(s).")
        else:
            print("URLHAUS_API_KEY not set — skipping URLhaus URL enrichment.")

        with open("ioc_export.json", "w", encoding="utf-8") as f:
            json.dump(export, f, indent=2, default=str)
        print(f"IOC pipeline: exported {len(export)} active IOC(s) to ioc_export.json")

        # Export TTP aggregates for the dashboard heat map
        raw_ttps = ioc_db.get_all_ttps(conn)
        ttp_export = [
            {
                "technique_id":        r["technique_id"],
                "technique_name":      r["technique_name"],
                "tactic":              r["tactic"],
                "article_count":       r["article_count"],
                "total_observations":  r["total_observations"],
                "last_seen":           r["last_seen"],
                "apts":                r["apts"] or [],
                "sources":             r["sources"] or [],
            }
            for r in raw_ttps
        ]
        with open("ttp_export.json", "w", encoding="utf-8") as f:
            json.dump(ttp_export, f, indent=2, default=str)
        print(f"IOC pipeline: exported {len(ttp_export)} TTP(s) to ttp_export.json")

        pruned = ioc_db.prune_expired(conn, grace_days=90)
        if pruned:
            print(f"IOC pipeline: pruned {pruned} IOC(s) older than 90 days.")
    except Exception as e:
        print(f"IOC pipeline: result query / export failed: {e}")

    results["rel_snapshot"] = rel_lookup or {}
    conn.close()
    return results
