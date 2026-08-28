import json
import os
from datetime import datetime, timezone

import ioc_extractor
import ioc_scorer
import stix_converter
import ioc_db
import vt_enricher


def run(new_items: list[dict]) -> dict:
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
    except Exception as e:
        print(f"IOC pipeline: schema init failed: {e}")
        conn.close()
        return results

    # Auto-prune any FP domains that slipped into the DB before filtering was tightened
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

    today      = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    total_iocs = 0

    for item in new_items:
        text = ioc_extractor.fetch_article_text(item["link"]) or ""
        if not text:
            continue
        apt  = ioc_extractor.detect_apt(item["site"] + " " + text)
        iocs = ioc_extractor.extract_iocs(text)
        if not iocs:
            continue
        for ioc in iocs:
            ltv      = ioc_scorer.get_ltv(apt, ioc["type"])
            tau      = ioc_scorer.TAU_DEFAULT[ioc_scorer.ioc_group(ioc["type"])]
            stix_obj = stix_converter.ioc_to_indicator(
                ioc["value"], ioc["type"],
                item["date"], item["link"], item["site"],
                today,
            )
            try:
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

    print(f"IOC pipeline: {total_iocs} IOC(s) upserted from {len(new_items)} article(s).")

    vt_api_key = os.environ.get("VT_API_KEY", "")
    if vt_api_key:
        print("Running VirusTotal enrichment (up to 20 hashes, 15s between calls)...")
        try:
            vt_enricher.enrich_pending_hashes(conn, vt_api_key)
        except Exception as e:
            print(f"VT enrichment error: {e}")
    else:
        print("VT_API_KEY not set — skipping VirusTotal enrichment.")

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
            }
            for r in all_active
        ], key=lambda x: x["score"], reverse=True)
        with open("ioc_export.json", "w", encoding="utf-8") as f:
            json.dump(export, f, indent=2, default=str)
        print(f"IOC pipeline: exported {len(export)} active IOC(s) to ioc_export.json")

        pruned = ioc_db.prune_expired(conn, grace_days=90)
        if pruned:
            print(f"IOC pipeline: pruned {pruned} IOC(s) older than 90 days.")
    except Exception as e:
        print(f"IOC pipeline: result query / export failed: {e}")

    conn.close()
    return results
