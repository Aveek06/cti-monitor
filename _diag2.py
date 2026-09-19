import os
import psycopg2

conn = psycopg2.connect(os.environ["DATABASE_URL"])
with conn.cursor() as cur:
    cur.execute("SELECT actor_name, negotiation_stats, vulnerabilities FROM threat_actor_profiles WHERE actor_name IN ('Akira','Clop','LockBit') ORDER BY actor_name")
    for name, neg, vulns in cur.fetchall():
        vuln_sample = vulns[0] if vulns else None
        print(f"{name}: negotiation_stats={neg}")
        print(f"{name}: first vuln entry={vuln_sample}")
conn.close()
