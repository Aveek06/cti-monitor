const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { SignJWT, jwtVerify } = require('jose');
const { randomUUID } = require('crypto');

const COOKIE_NAME = 'cti_session';
const COOKIE_MAX_AGE = 60 * 60 * 24 * 7; // 7 days
const LIVE_THRESHOLD_MINUTES = 3;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

let _pool;
function pool() {
  if (!_pool) _pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 3 });
  return _pool;
}

function secret() {
  if (!process.env.SESSION_SECRET) throw new Error('SESSION_SECRET not set');
  return new TextEncoder().encode(process.env.SESSION_SECRET);
}

// Handles values containing '=' (e.g. base64 in non-JWT cookies)
function parseCookie(header) {
  if (!header) return {};
  const out = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

function cookieHeader(token, maxAge) {
  if (maxAge === 0) {
    return `${COOKIE_NAME}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Strict`;
  }
  return `${COOKIE_NAME}=${token}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}

// Verify JWT signature and check token not in revocation table.
// Returns payload or null.
async function verifyToken(cookieHeader) {
  try {
    const token = parseCookie(cookieHeader)[COOKIE_NAME];
    if (!token) return null;
    const { payload } = await jwtVerify(token, secret());
    if (payload.jti) {
      const { rows } = await pool().query(
        'SELECT 1 FROM token_revocations WHERE jti=$1', [payload.jti]
      );
      if (rows.length) return null;
    }
    return payload;
  } catch {
    return null;
  }
}

async function revokeToken(jti) {
  if (!jti) return;
  await pool().query(
    `INSERT INTO token_revocations (jti, expires_at)
     VALUES ($1, NOW() + INTERVAL '7 days')
     ON CONFLICT (jti) DO NOTHING`,
    [jti]
  ).catch(() => {});
}

// DB-backed rate limiting — survives serverless cold starts
async function checkLoginRateLimit(ip) {
  const { rows } = await pool().query(
    `SELECT COUNT(*) AS cnt FROM login_attempts
     WHERE ip=$1 AND attempted_at > NOW() - INTERVAL '${LOCKOUT_MINUTES} minutes'`,
    [ip]
  );
  return +rows[0].cnt < MAX_LOGIN_ATTEMPTS;
}

async function recordFailedLogin(ip) {
  await pool().query(
    'INSERT INTO login_attempts (ip, attempted_at) VALUES ($1, NOW())', [ip]
  );
}

async function clearLoginAttempts(ip) {
  await pool().query(
    `DELETE FROM login_attempts
     WHERE ip=$1 AND attempted_at > NOW() - INTERVAL '${LOCKOUT_MINUTES} minutes'`,
    [ip]
  );
}

module.exports = async function handler(req, res) {
  if (!process.env.DATABASE_URL) return res.status(500).json({ error: 'DATABASE_URL not set' });

  const action = req.query.action;

  // POST /api/auth?action=login
  if (req.method === 'POST' && action === 'login') {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '')
      .split(',')[0].trim() || 'unknown';

    const allowed = await checkLoginRateLimit(ip);
    if (!allowed) return res.status(429).json({ error: 'Too many failed attempts. Try again in 15 minutes.' });

    const { rows } = await pool().query(
      `SELECT u.email, u.active, u.is_admin, c.password_hash
       FROM allowed_users u
       JOIN user_credentials c ON c.email = u.email
       WHERE u.email = $1`,
      [email.toLowerCase().trim()]
    );

    const user = rows[0];
    if (!user || !user.active) {
      await recordFailedLogin(ip);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      await recordFailedLogin(ip);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    await clearLoginAttempts(ip);
    await pool().query('UPDATE user_credentials SET last_login = NOW() WHERE email = $1', [user.email]);

    const jti = randomUUID();
    const token = await new SignJWT({ email: user.email, is_admin: user.is_admin, jti })
      .setProtectedHeader({ alg: 'HS256' })
      .setExpirationTime('7d')
      .sign(secret());

    res.setHeader('Set-Cookie', cookieHeader(token, COOKIE_MAX_AGE));
    return res.json({ ok: true, email: user.email, is_admin: user.is_admin });
  }

  // POST /api/auth?action=logout
  if (req.method === 'POST' && action === 'logout') {
    const user = await verifyToken(req.headers.cookie);
    if (user?.jti) await revokeToken(user.jti);
    res.setHeader('Set-Cookie', cookieHeader('', 0));
    return res.json({ ok: true });
  }

  // POST /api/auth?action=heartbeat
  if (req.method === 'POST' && action === 'heartbeat') {
    const user = await verifyToken(req.headers.cookie);
    if (!user) return res.status(401).json({ error: 'Unauthenticated' });

    const ua = req.headers['user-agent']?.slice(0, 200) || null;
    const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '')
      .split(',')[0].trim() || null;

    await pool().query(
      `INSERT INTO user_sessions (email, last_seen, user_agent, ip)
       VALUES ($1, NOW(), $2, $3)
       ON CONFLICT (email) DO UPDATE SET last_seen = NOW(), user_agent = $2, ip = $3`,
      [user.email, ua, ip]
    );
    return res.json({ ok: true });
  }

  // GET /api/auth?action=whoami
  if (req.method === 'GET' && action === 'whoami') {
    const user = await verifyToken(req.headers.cookie);
    if (!user) return res.status(401).json({ error: 'Unauthenticated' });
    // Re-verify active status and is_admin from DB — JWT claim may be stale
    const { rows } = await pool().query(
      'SELECT is_admin FROM allowed_users WHERE email=$1 AND active=TRUE', [user.email]
    );
    if (!rows[0]) return res.status(401).json({ error: 'Account deactivated' });
    return res.json({ email: user.email, is_admin: rows[0].is_admin });
  }

  // POST /api/auth?action=change-password
  if (req.method === 'POST' && action === 'change-password') {
    const user = await verifyToken(req.headers.cookie);
    if (!user) return res.status(401).json({ error: 'Unauthenticated' });

    const { current_password, new_password } = req.body || {};
    if (!current_password || !new_password)
      return res.status(400).json({ error: 'current_password and new_password required' });
    if (new_password.length < 12)
      return res.status(400).json({ error: 'Password must be at least 12 characters' });
    if (!/[A-Z]/.test(new_password) || !/[0-9]/.test(new_password))
      return res.status(400).json({ error: 'Password must contain at least one uppercase letter and one digit' });

    const { rows } = await pool().query(
      'SELECT password_hash FROM user_credentials WHERE email=$1', [user.email]
    );
    if (!rows[0]) return res.status(404).json({ error: 'User not found' });

    const valid = await bcrypt.compare(current_password, rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: 'Current password incorrect' });

    const newHash = await bcrypt.hash(new_password, 12);
    await pool().query(
      'UPDATE user_credentials SET password_hash=$1 WHERE email=$2', [newHash, user.email]
    );

    // Revoke the current token — user must re-authenticate with new password
    if (user.jti) await revokeToken(user.jti);
    res.setHeader('Set-Cookie', cookieHeader('', 0));
    return res.json({ ok: true, message: 'Password changed. Please log in again.' });
  }

  // GET /api/auth?action=active-users (admin only)
  if (req.method === 'GET' && action === 'active-users') {
    const user = await verifyToken(req.headers.cookie);
    if (!user) return res.status(403).json({ error: 'Forbidden' });
    const { rows: adminRows } = await pool().query(
      'SELECT is_admin FROM allowed_users WHERE email=$1 AND active=TRUE', [user.email]
    );
    if (!adminRows[0]?.is_admin) return res.status(403).json({ error: 'Forbidden' });

    const { rows } = await pool().query(
      `SELECT s.email, s.last_seen, s.ip,
              EXTRACT(EPOCH FROM (NOW() - s.last_seen)) AS seconds_ago
       FROM user_sessions s
       JOIN allowed_users u ON u.email = s.email
       WHERE s.last_seen > NOW() - INTERVAL '${LIVE_THRESHOLD_MINUTES} minutes'
         AND u.active = TRUE
       ORDER BY s.last_seen DESC`
    );
    return res.json({ users: rows });
  }

  res.setHeader('Allow', 'GET, POST');
  return res.status(405).json({ error: 'Method not allowed' });
};
