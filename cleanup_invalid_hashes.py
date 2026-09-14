"""
One-shot cleanup: delete hash IOCs that fail strict hex validation.

Removes sha256/sha1/md5 rows whose value contains non-hex characters or
has the wrong length — false positives that slipped in before strict
validation was added to ioc_extractor.py.

Usage:
  DATABASE_URL=... python cleanup_invalid_hashes.py
  DATABASE_URL=... python cleanup_invalid_hashes.py --dry-run
"""

import os
import sys
import argparse
import psycopg2

HASH_RULES = {
    "sha256": 64,
    "sha1":   40,
    "md5":    32,
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be deleted without deleting")
    args = parser.parse_args()

    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        print("ERROR: DATABASE_URL is not set.")
        sys.exit(1)

    conn = psycopg2.connect(db_url)
    all_bad = []

    for hash_type, length in HASH_RULES.items():
        with conn.cursor() as cur:
            # Match rows that are NOT exactly <length> lowercase hex chars
            cur.execute(
                """
                SELECT id, value, type
                FROM ioc_indicators
                WHERE type = %s
                  AND NOT (length(lower(value)) = %s
                           AND lower(value) ~ '^[0-9a-f]+$')
                ORDER BY value
                """,
                (hash_type, length),
            )
            rows = cur.fetchall()
        if rows:
            print(f"\nInvalid {hash_type.upper()} ({len(rows)} row(s)):")
            for _, value, _ in rows:
                print(f"  {value}")
            all_bad.extend(rows)

    if not all_bad:
        print("No invalid hash IOCs found. Nothing to clean up.")
        conn.close()
        return

    print(f"\nTotal: {len(all_bad)} invalid hash IOC(s).")

    if args.dry_run:
        print("--dry-run: no rows deleted.")
        conn.close()
        return

    ids = [r[0] for r in all_bad]
    with conn.cursor() as cur:
        cur.execute("DELETE FROM ioc_indicators WHERE id = ANY(%s)", (ids,))
        deleted = cur.rowcount
    conn.commit()
    conn.close()
    print(f"Deleted {deleted} row(s).")


if __name__ == "__main__":
    main()
