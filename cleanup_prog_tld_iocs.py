"""
One-shot cleanup: delete domain IOCs whose TLD is a programming keyword.

Removes rows like f.read, o2.read, user.email that iocsearcher extracted
as FQDNs from code snippets. Safe to re-run; exits cleanly if nothing found.

Usage:
  DATABASE_URL=... python cleanup_prog_tld_iocs.py
  DATABASE_URL=... python cleanup_prog_tld_iocs.py --dry-run
"""

import os
import sys
import argparse
import psycopg2

# Must match _PROG_PSEUDO_TLDS in ioc_extractor.py
PROG_PSEUDO_TLDS = {
    "read", "write", "open", "close", "split", "strip", "join",
    "lower", "upper", "find", "replace", "format", "decode", "encode",
    "append", "extend", "sort", "reverse", "pop", "push", "keys",
    "values", "items", "load", "dump", "parse", "execute", "connect",
    "recv", "send", "flush", "seek", "tell", "readline", "readlines",
    "writelines", "count", "index", "copy", "delete", "update", "insert",
    "select", "create", "exit", "run", "start", "stop", "get", "set",
    "name", "path", "text", "body", "head", "tail", "size", "length",
    "type", "email", "username", "password", "token", "session",
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
    tld_array = list(PROG_PSEUDO_TLDS)

    with conn.cursor() as cur:
        # regexp_replace strips everything up to and including the last dot,
        # leaving just the TLD (e.g. "f.read" -> "read")
        preview_sql = """
            SELECT id, value, type
            FROM ioc_indicators
            WHERE type IN ('domain', 'fqdn')
              AND regexp_replace(lower(value), '^.*\\.', '') = ANY(%s)
            ORDER BY value
        """
        cur.execute(preview_sql, (tld_array,))
        rows = cur.fetchall()

    if not rows:
        print("No programming pseudo-TLD IOCs found. Nothing to clean up.")
        conn.close()
        return

    print(f"Found {len(rows)} IOC(s) to remove:")
    for _, value, ioc_type in rows:
        print(f"  [{ioc_type}] {value}")

    if args.dry_run:
        print("\n--dry-run: no rows deleted.")
        conn.close()
        return

    ids = [r[0] for r in rows]
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM ioc_indicators WHERE id = ANY(%s)",
            (ids,)
        )
        deleted = cur.rowcount
    conn.commit()
    conn.close()
    print(f"\nDeleted {deleted} row(s).")


if __name__ == "__main__":
    main()
