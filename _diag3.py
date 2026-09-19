import json
import os
import psycopg2

conn = psycopg2.connect(os.environ["DATABASE_URL"])
with conn.cursor() as cur:
    cur.execute("""
        SELECT actor_name, mitre_group_id, ransomware_live_id,
               jsonb_array_length(COALESCE(techniques,'[]'::jsonb)) AS mitre_tech_ct,
               jsonb_array_length(COALESCE(software,'[]'::jsonb)) AS mitre_sw_ct,
               jsonb_typeof(tools) AS tools_type
        FROM threat_actor_profiles
        WHERE mitre_group_id IS NOT NULL AND ransomware_live_id IS NOT NULL
        ORDER BY actor_name
    """)
    rows = cur.fetchall()
print(f"Dual-matched actors (both MITRE and ransomware.live): {len(rows)}")
for r in rows:
    print(r)

with conn.cursor() as cur2:
    cur2.execute("SELECT COUNT(*) FROM threat_actor_profiles WHERE mitre_group_id IS NOT NULL")
    print("MITRE-only-or-dual rows:", cur2.fetchone()[0])
    cur2.execute("SELECT COUNT(*) FROM threat_actor_profiles WHERE ransomware_live_id IS NOT NULL")
    print("Ransomware-only-or-dual rows:", cur2.fetchone()[0])

conn.close()
