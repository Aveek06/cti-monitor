#!/usr/bin/env python3
# Adds rater_ip and created_at columns to site_ratings for DB-backed rate limiting.
# Usage: DATABASE_URL="..." python dashboard/scripts/migrate_ratings.py
import os, psycopg2

db_url = os.environ.get('DATABASE_URL')
if not db_url:
    print("Set DATABASE_URL environment variable.")
    exit(1)

conn = psycopg2.connect(db_url)
cur = conn.cursor()
cur.execute("ALTER TABLE site_ratings ADD COLUMN IF NOT EXISTS rater_ip TEXT")
cur.execute("ALTER TABLE site_ratings ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()")
cur.execute("CREATE INDEX IF NOT EXISTS idx_site_ratings_ip_ts ON site_ratings (rater_ip, created_at)")
conn.commit()
conn.close()
print("Migration complete.")
