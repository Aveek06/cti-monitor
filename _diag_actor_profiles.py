import json
import os
import psycopg2
import psycopg2.extras

conn = psycopg2.connect(os.environ["DATABASE_URL"])
with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
    cur.execute("""
        SELECT actor_name, mitre_group_id, ransomware_live_id,
               jsonb_array_length(COALESCE(vulnerabilities, '[]'::jsonb)) AS vuln_ct,
               jsonb_array_length(COALESCE(ransomware_ttps, '[]'::jsonb)) AS rwttp_ct,
               jsonb_array_length(COALESCE(leak_sites, '[]'::jsonb)) AS leak_ct,
               jsonb_array_length(COALESCE(ransom_note_names, '[]'::jsonb)) AS note_ct,
               jsonb_array_length(COALESCE(yara_rules, '[]'::jsonb)) AS yara_ct,
               negotiation_stats
        FROM threat_actor_profiles
        WHERE ransomware_live_id IS NOT NULL
        ORDER BY actor_name
    """)
    rows = cur.fetchall()

print(f"Total ransomware.live-matched rows: {len(rows)}")
total_vulns = sum(r["vuln_ct"] for r in rows)
print(f"Sum of vulnerabilities across all rows: {total_vulns}")
for r in rows:
    print(f"{r['actor_name']:25s} vulns={r['vuln_ct']:3d} rwttp={r['rwttp_ct']:3d} leak={r['leak_ct']:3d} notes={r['note_ct']:3d} yara={r['yara_ct']:3d} neg={bool(r['negotiation_stats'])}")

# Show raw vulnerabilities content for the first row that has any
for r2 in rows:
    if r2["vuln_ct"] > 0:
        with conn.cursor() as cur2:
            cur2.execute("SELECT vulnerabilities FROM threat_actor_profiles WHERE actor_name=%s", (r2["actor_name"],))
            raw = cur2.fetchone()[0]
            print(f"\nSample non-empty vulnerabilities for {r2['actor_name']}:")
            print(json.dumps(raw, indent=2)[:800])
        break
else:
    print("\nNo row has any vulnerabilities data at all.")

with conn.cursor() as cur3:
    cur3.execute("SELECT ransomware_ttps, tools, leak_sites FROM threat_actor_profiles WHERE actor_name='Akira'")
    ttps_raw, tools_raw, leak_raw = cur3.fetchone()
    print("\nAkira ransomware_ttps sample:")
    print(json.dumps(ttps_raw, indent=2)[:1200])
    print("\nAkira tools sample:")
    print(json.dumps(tools_raw, indent=2)[:600])
    print("\nAkira leak_sites sample:")
    print(json.dumps(leak_raw, indent=2)[:600])

conn.close()
