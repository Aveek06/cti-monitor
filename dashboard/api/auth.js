const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { SignJWT, jwtVerify } = require('jose');

const COOKIE_NAME = 'cti_session';
const COOKIE_MAX_AGE = 60 * 60 * 24 * 7; // 7 days
const LIVE_THRESHOLD_MINUTES = 3;

let _pool;
function pool() {
  if (!_pool) _pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 3 });
  return _pool;
}

function secret() {
  if (!process.env.SESSION_SECRET) throw new Error('SESSION_SECRET not set');
  return new TextEncoder().encode(process.env.SESSION_SECRET);
}

const _loginAttempts = new Map();
function checkLoginRateLimit(ip) {
  const now = Date.now();
  const entry = _loginAttempts.get(ip) || { count: 0, until: 0 };
  if (now < entry.until) return false;
  return entry;
}
function recordFailedLogin(ip) {
  const now = Date.now();
  const entry = _loginAttempts.get(ip) || { count: 0, until: 0 };
  entry.count++;
  if (entry.count >= 5) entry.until = now + 15 * 60 * 1000;
  _loginAttempts.set(ip, entry);
}
function clearLoginAttempts(ip) {
  _loginAttempts.delete(ip);
}

async function getUser(token) {
  try {
    const { payload } = await jwtVerify(token, secret());
    return payload;
  } catch {
    return null;
  }
}

function cookieHeader(token, maxAge) {
  if (maxAge === 0) {
    return `${COOKIE_NAME}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Strict`;
  }
  return `${COOKIE_NAME}=${token}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}

function parseCookie(header) {
  if (!header) return {};
  return Object.fromEntries(
    header.split(';').map(s => s.trim().split('=').map(decodeURIComponent))
  );
}

module.exports = async function handler(req, res) {
  if (!process.env.DATABASE_URL) return res.status(500).json({ error: 'DATABASE_URL not set' });

  const action = req.query.action;

  // POST /api/auth?action=login
  if (req.method === 'POST' && action === 'login') {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').split(',')[0].trim() || 'unknown';
    const rateEntry = checkLoginRateLimit(ip);
    if (rateEntry === false) return res.status(429).json({ error: 'Too many failed attempts. Try again in 15 minutes.' });

    const { rows } = await pool().query(
      `SELECT u.email, u.active, u.is_admin, c.password_hash
       FROM allowed_users u
       JOIN user_credentials c ON c.email = u.email
       WHERE u.email = $1`,
      [email.toLowerCase().trim()]
    );

    const user = rows[0];
    if (!user || !user.active) { recordFailedLogin(ip); return res.status(401).json({ error: 'Invalid credentials' }); }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) { recordFailedLogin(ip); return res.status(401).json({ error: 'Invalid credentials' }); }

    clearLoginAttempts(ip);
    await pool().query('UPDATE user_credentials SET last_login = NOW() WHERE email = $1', [user.email]);

    const token = await new SignJWT({ email: user.email, is_admin: user.is_admin })
      .setProtectedHeader({ alg: 'HS256' })
      .setExpirationTime('7d')
      .sign(secret());

    res.setHeader('Set-Cookie', cookieHeader(token, COOKIE_MAX_AGE));
    return res.json({ ok: true, email: user.email, is_admin: user.is_admin });
  }

  // POST /api/auth?action=logout
  if (req.method === 'POST' && action === 'logout') {
    res.setHeader('Set-Cookie', cookieHeader('', 0));
    return res.json({ ok: true });
  }

  // POST /api/auth?action=heartbeat
  if (req.method === 'POST' && action === 'heartbeat') {
    const cookies = parseCookie(req.headers.cookie);
    const user = await getUser(cookies[COOKIE_NAME]);
    if (!user) return res.status(401).json({ error: 'Unauthenticated' });

    const ua = req.headers['user-agent']?.slice(0, 200) || null;
    const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').split(',')[0].trim() || null;

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
    const cookies = parseCookie(req.headers.cookie);
    const user = await getUser(cookies[COOKIE_NAME]);
    if (!user) return res.status(401).json({ error: 'Unauthenticated' });
    return res.json({ email: user.email, is_admin: user.is_admin });
  }

  // GET /api/auth?action=active-users (admin only)
  if (req.method === 'GET' && action === 'active-users') {
    const cookies = parseCookie(req.headers.cookie);
    const user = await getUser(cookies[COOKIE_NAME]);
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
