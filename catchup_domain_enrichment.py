"""
One-shot catchup: re-enrich all IOCs missing VT or meta data.

Resets previously-failed checks (checked=TRUE but result=NULL) and drains
the full backlog with no per-run cap.

Usage:
  DATABASE_URL=... VT_API_KEY_DOMAIN=... VT_API_KEY=... python catchup_domain_enrichment.py
  DATABASE_URL=... VT_API_KEY_DOMAIN=... python catchup_domain_enrichment.py --domain-vt-only
  DATABASE_URL=... VT_API_KEY=...        python catchup_domain_enrichment.py --hash-vt-only
  DATABASE_URL=...                       python catchup_domain_enrichment.py --meta-only
"""

import os
import sys
import argparse
import psycopg2
import domain_enricher
import vt_domain_enricher
import vt_enricher
import hash_enricher


def reset_failed(conn, flag_col, result_col, types):
    """Reset flag=TRUE rows where the result column is still NULL."""
    type_list = "','".join(types)
    with conn.cursor() as cur:
        cur.execute(
            f"UPDATE ioc_indicators "
            f"SET {flag_col} = FALSE "
            f"WHERE type IN ('{type_list}') "
            f"  AND {flag_col} = TRUE "
            f"  AND {result_col} IS NULL"
        )
        count = cur.rowcount
    conn.commit()
    return count


def count_pending_flag(conn, flag_col, types):
    type_list = "','".join(types)
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT COUNT(*) FROM ioc_indicators "
            f"WHERE type IN ('{type_list}') AND {flag_col} = FALSE"
        )
        return cur.fetchone()[0]


def count_pending_verified(conn, types):
    type_list = "','".join(types)
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT COUNT(*) FROM ioc_indicators "
            f"WHERE type IN ('{type_list}') AND vt_verified = FALSE"
        )
        return cur.fetchone()[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain-vt-only", action="store_true", help="Only VT domain enrichment")
    parser.add_argument("--hash-vt-only",   action="store_true", help="Only VT hash enrichment (sha256/sha1/md5)")
    parser.add_argument("--meta-only",      action="store_true", help="Only URLhaus/RDAP/DNS domain meta enrichment")
    args = parser.parse_args()

    any_filter = args.domain_vt_only or args.hash_vt_only or args.meta_only
    run_domain_vt = args.domain_vt_only or not any_filter
    run_hash_vt   = args.hash_vt_only   or not any_filter
    run_meta      = args.meta_only       or not any_filter

    db_url        = os.environ.get("DATABASE_URL")
    vt_hash_key   = os.environ.get("VT_API_KEY", "")
    vt_domain_key = os.environ.get("VT_API_KEY_DOMAIN", "")
    vt_backup_key = os.environ.get("VT_API_KEY_BACKUP", "")

    if not db_url:
        print("ERROR: DATABASE_URL is not set.")
        sys.exit(1)

    conn = psycopg2.connect(db_url)

    # --- Domain VT ---
    if run_domain_vt:
        if not vt_domain_key:
            print("WARNING: VT_API_KEY_DOMAIN not set — skipping VT domain enrichment.")
        else:
            reset_count = reset_failed(conn, "vt_domain_checked", "vt_domain_malicious", ["domain", "fqdn"])
            print(f"Reset {reset_count} previously-failed VT domain checks back to pending.")
            pending = count_pending_flag(conn, "vt_domain_checked", ["domain", "fqdn"])
            print(f"VT domain enrichment: {pending} pending.")
            if pending:
                est = pending * 15
                print(f"Starting (15s/call — ~{est//60}m {est%60}s)...")
                vt_domain_enricher.enrich_pending_domains(conn, vt_domain_key, limit=pending + 1, backup_api_key=vt_backup_key)
                print("VT domain enrichment complete.")

    # --- Hash VT (sha256 / sha1 / md5) ---
    if run_hash_vt:
        if not vt_hash_key:
            print("WARNING: VT_API_KEY not set — skipping VT hash enrichment.")
        else:
            reset_count = reset_failed(conn, "vt_verified", "vt_malicious", ["sha256", "sha1", "md5"])
            print(f"Reset {reset_count} previously-failed VT hash checks back to pending.")
            pending = count_pending_verified(conn, ["sha256", "sha1", "md5"])
            print(f"VT hash enrichment: {pending} pending.")
            if pending:
                est = pending * 15
                print(f"Starting (15s/call — ~{est//60}m {est%60}s)...")
                conn = vt_enricher.enrich_pending_hashes(conn, vt_hash_key, limit=pending + 1, backup_api_key=vt_backup_key)
                print("VT hash enrichment complete.")

    # --- Domain meta (URLhaus / RDAP / DNS) ---
    if run_meta:
        pending = count_pending_flag(conn, "domain_meta_checked", ["domain", "fqdn"])
        print(f"Domain meta enrichment (URLhaus/RDAP/DNS): {pending} pending.")
        if pending:
            print("Starting meta enrichment...")
            domain_enricher.enrich_pending_domains(conn, limit=pending + 1)
            print("Domain meta enrichment complete.")

    # --- Hash meta (MalwareBazaar / ThreatFox) ---
    if run_hash_vt or (not any_filter):
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM ioc_indicators "
                "WHERE type IN ('sha256','sha1','md5') AND hash_meta_checked = FALSE"
            )
            mb_pending = cur.fetchone()[0]
        print(f"Hash meta enrichment (MalwareBazaar/ThreatFox): {mb_pending} pending.")
        if mb_pending:
            print("Starting hash meta enrichment...")
            hash_enricher.enrich_pending_hashes(conn, limit=mb_pending + 1)
            print("Hash meta enrichment complete.")

    conn.close()
    print("Done.")


if __name__ == "__main__":
    main()
