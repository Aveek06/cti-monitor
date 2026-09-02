#!/usr/bin/env python3
# Usage: python dashboard/scripts/add_user.py <email> [--admin] [--password <pw>]
# Requires: pip install psycopg2-binary bcrypt requests
import sys, secrets, re, hashlib, psycopg2

try:
    import bcrypt
except ImportError:
    print("Run: pip install bcrypt")
    sys.exit(1)

try:
    import requests as _requests
except ImportError:
    _requests = None


def check_pwned(password):
    """Returns True if password appears in the Have I Been Pwned database."""
    if _requests is None:
        return False
    try:
        h = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = h[:5], h[5:]
        r = _requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5,
            headers={"User-Agent": "cti-monitor-add-user/1.0"},
        )
        return any(line.split(":")[0] == suffix for line in r.text.splitlines())
    except Exception:
        return False  # HIBP unreachable; don't block provisioning


def validate_password(pw):
    if len(pw) < 12:
        return "Password must be at least 12 characters."
    if not re.search(r"[A-Z]", pw):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[0-9]", pw):
        return "Password must contain at least one digit."
    if not re.search(r"[^A-Za-z0-9]", pw):
        return "Password must contain at least one special character."
    if check_pwned(pw):
        return "Password found in breach database (Have I Been Pwned). Choose a different one."
    return None


args = sys.argv[1:]
email = next((a for a in args if not a.startswith("--")), None)
is_admin = "--admin" in args
pw_idx = args.index("--password") if "--password" in args else -1
password = args[pw_idx + 1] if pw_idx != -1 and pw_idx + 1 < len(args) else None

if not email:
    print("Usage: python add_user.py <email> [--admin] [--password <pw>]")
    sys.exit(1)

import os
db_url = os.environ.get("DATABASE_URL")
if not db_url:
    print("Set DATABASE_URL environment variable.")
    sys.exit(1)

if not password:
    password = secrets.token_urlsafe(16)
    print(f"Generated password: {password}")
else:
    err = validate_password(password)
    if err:
        print(f"Password rejected: {err}")
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
