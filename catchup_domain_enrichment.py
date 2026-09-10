"""
One-shot catchup: re-enrich all domains that are missing VT data.

Resets vt_domain_checked for domains where the previous attempt returned
NULL (timed out / API error), then drains the full backlog with no per-run
cap. Runs the free-tier enrichers (URLhaus/RDAP/DNS) for any domain still
missing domain_meta_checked as well.

Usage:
  DATABASE_URL=... VT_API_KEY_DOMAIN=... python catchup_domain_enrichment.py
  DATABASE_URL=... VT_API_KEY_DOMAIN=... python catchup_domain_enrichment.py --vt-only
  DATABASE_URL=... VT_API_KEY_DOMAIN=... python catchup_domain_enrichment.py --meta-only
"""

import os
import sys
import argparse
import psycopg2
import domain_enricher
import vt_domain_enricher


def reset_failed_vt(conn):
    """Reset vt_domain_checked=TRUE rows that have no malicious score."""
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE ioc_indicators "
            "SET vt_domain_checked = FALSE "
            "WHERE type = 'domain' "
            "  AND vt_domain_checked = TRUE "
            "  AND vt_domain_malicious IS NULL"
        )
        count = cur.rowcount
    conn.commit()
    return count


def count_pending(conn, flag_col):
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT COUNT(*) FROM ioc_indicators WHERE type='domain' AND {flag_col}=FALSE"
        )
        return cur.fetchone()[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--vt-only",   action="store_true", help="Only run VT domain enrichment")
    parser.add_argument("--meta-only", action="store_true", help="Only run URLhaus/RDAP/DNS enrichment")
    args = parser.parse_args()

    db_url     = os.environ.get("DATABASE_URL")
    vt_key     = os.environ.get("VT_API_KEY_DOMAIN", "")

    if not db_url:
        print("ERROR: DATABASE_URL is not set.")
        sys.exit(1)

    conn = psycopg2.connect(db_url)

    run_vt   = not args.meta_only
    run_meta = not args.vt_only

    if run_vt:
        if not vt_key:
            print("WARNING: VT_API_KEY_DOMAIN is not set — skipping VT enrichment.")
            run_vt = False
        else:
            reset_count = reset_failed_vt(conn)
            print(f"Reset {reset_count} previously-failed VT domain checks back to pending.")

            pending = count_pending(conn, "vt_domain_checked")
            print(f"VT domain enrichment: {pending} domains pending.")
            if pending:
                print(f"Starting VT enrichment (15s between calls — estimated {pending * 15 // 60}m {pending * 15 % 60}s)...")
                vt_domain_enricher.enrich_pending_domains(conn, vt_key, limit=pending + 1)
                print("VT domain enrichment complete.")

    if run_meta:
        pending = count_pending(conn, "domain_meta_checked")
        print(f"Domain meta enrichment (URLhaus/RDAP/DNS): {pending} domains pending.")
        if pending:
            print("Starting meta enrichment...")
            domain_enricher.enrich_pending_domains(conn, limit=pending + 1)
            print("Domain meta enrichment complete.")

    conn.close()
    print("Done.")


if __name__ == "__main__":
    main()
