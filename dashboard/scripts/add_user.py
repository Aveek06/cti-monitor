#!/usr/bin/env python3
# Usage: python dashboard/scripts/add_user.py <email> [--admin] [--password <pw>]
# Requires: pip install psycopg2-binary bcrypt
import sys, secrets, psycopg2

try:
    import bcrypt
except ImportError:
    print("Run: pip install bcrypt")
    sys.exit(1)

args = sys.argv[1:]
email = next((a for a in args if not a.startswith('--')), None)
is_admin = '--admin' in args
pw_idx = args.index('--password') if '--password' in args else -1
password = args[pw_idx + 1] if pw_idx != -1 else None

if not email:
    print("Usage: python add_user.py <email> [--admin] [--password <pw>]")
    sys.exit(1)

db_url = sys.argv[0] and __import__('os').environ.get('DATABASE_URL')
if not db_url:
    print("Set DATABASE_URL environment variable.")
    sys.exit(1)

if not password:
    password = secrets.token_urlsafe(16)
    print(f"Generated password: {password}")
elif len(password) < 12:
    print("Password must be at least 12 characters.")
    sys.exit(1)

pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()

conn = psycopg2.connect(db_url)
cur = conn.cursor()

cur.execute("""
    INSERT INTO allowed_users (email, added_by, is_admin)
    VALUES (%s, 'cli', %s)
    ON CONFLICT (email) DO UPDATE SET active = TRUE, is_admin = %s
""", (email.lower().strip(), is_admin, is_admin))

cur.execute("""
    INSERT INTO user_credentials (email, password_hash)
    VALUES (%s, %s)
    ON CONFLICT (email) DO UPDATE SET password_hash = %s
""", (email.lower().strip(), pw_hash, pw_hash))

conn.commit()
conn.close()
print(f"\n✓ User provisioned: {email}{' (admin)' if is_admin else ''}")
print("  Share password securely with the analyst.")
