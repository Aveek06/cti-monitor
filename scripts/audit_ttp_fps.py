"""
Audit ttp_observations for likely false positives.

Prints two categories to stdout as TSV:
  1. Rows with technique_name IS NULL — ID was not in TECHNIQUE_LOOKUP at extraction time
  2. Single-mention observations older than 7 days — never corroborated by a second pipeline run

Does NOT delete anything. Review the output and delete confirmed FPs manually or via:
  DELETE FROM ttp_observations WHERE id IN (<ids>);
"""

import os
import sys
import psycopg2
from datetime import date, timedelta

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    # Try loading from dashboard/.env.local
    env_path = os.path.join(os.path.dirname(__file__), "..", "dashboard", ".env.local")
    if os.path.exists(env_path):
        for line in open(env_path):
            line = line.strip()
            if line.startswith("DATABASE_URL="):
                DATABASE_URL = line.split("=", 1)[1].strip().strip('"').strip("'")
                break

if not DATABASE_URL:
    print("ERROR: DATABASE_URL not set. Run: set DATABASE_URL=<connection string>", file=sys.stderr)
    sys.exit(1)

conn = psycopg2.connect(DATABASE_URL)
cur = conn.cursor()

cutoff = date.today() - timedelta(days=7)

print("=== Category 1: NULL technique_name (ID not in ATT&CK lookup at extraction time) ===")
print("id\ttechnique_id\tsource_blog\tsource_article\tfirst_seen")
cur.execute("""
    SELECT id, technique_id, source_blog, source_article, first_seen
    FROM ttp_observations
    WHERE technique_name IS NULL
    ORDER BY first_seen DESC
""")
rows = cur.fetchall()
for r in rows:
    print("\t".join(str(x) if x is not None else "" for x in r))
print(f"  → {len(rows)} row(s)\n")

print("=== Category 2: Single-mention, older than 7 days (never corroborated) ===")
print("id\ttechnique_id\ttechnique_name\tsource_blog\tsource_article\tfirst_seen\tobservation_count")
cur.execute("""
    SELECT id, technique_id, technique_name, source_blog, source_article, first_seen, observation_count
    FROM ttp_observations
    WHERE observation_count = 1
      AND first_seen < %s
    ORDER BY first_seen DESC
""", (cutoff,))
rows = cur.fetchall()
for r in rows:
    print("\t".join(str(x) if x is not None else "" for x in r))
print(f"  → {len(rows)} row(s)\n")

cur.close()
conn.close()
