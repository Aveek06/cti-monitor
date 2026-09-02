#!/usr/bin/env python3
# Creates token_revocations and login_attempts tables required by auth hardening.
# Usage: DATABASE_URL="..." python dashboard/scripts/migrate_auth.py
import os, psycopg2

db_url = os.environ.get("DATABASE_URL")
if not db_url:
    print("Set DATABASE_URL environment variable.")
    exit(1)

conn = psycopg2.connect(db_url)
cur = conn.cursor()

# JWT revocation table — stores jti of revoked tokens until they naturally expire
cur.execute("""
    CREATE TABLE IF NOT EXISTS token_revocations (
        jti        TEXT PRIMARY KEY,
        expires_at TIMESTAMPTZ NOT NULL
    )
""")
cur.execute(
    "CREATE INDEX IF NOT EXISTS idx_token_rev_exp ON token_revocations (expires_at)"
)

# DB-backed login attempt tracking — replaces in-memory Map that resets on cold start
cur.execute("""
    CREATE TABLE IF NOT EXISTS login_attempts (
        id           BIGSERIAL PRIMARY KEY,
        ip           TEXT        NOT NULL,
        attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
""")
cur.execute(
    "CREATE INDEX IF NOT EXISTS idx_login_ip_ts ON login_attempts (ip, attempted_at)"
)

conn.commit()
conn.close()
print("Migration complete: token_revocations and login_attempts tables ready.")
print()
print("Tip: prune expired revocations periodically with:")
print("  DELETE FROM token_revocations WHERE expires_at < NOW();")
print("  DELETE FROM login_attempts WHERE attempted_at < NOW() - INTERVAL '1 day';")
