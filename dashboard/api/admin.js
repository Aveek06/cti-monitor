const { Pool } = require('pg');
const { jwtVerify } = require('jose');

let _pool;
function pool() {
  if (!_pool) _pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 2 });
  return _pool;
}
function secret() {
  return new TextEncoder().encode(process.env.SESSION_SECRET);
}
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

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET') return res.status(405).end();

  const cookies = parseCookie(req.headers.cookie);
  const token = cookies['cti_session'];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  let payload;
  try {
    ({ payload } = await jwtVerify(token, secret()));
  } catch { return res.status(401).json({ error: 'Invalid session' }); }

  if (!payload.is_admin) return res.status(403).json({ error: 'Admin only' });

  const db = pool();
  try {
    const [usersRes, sessionsRes, attemptsRes, revocationsRes, ratingsRes] = await Promise.all([
      db.query(`SELECT au.email, au.is_admin, au.active, au.added_by, uc.last_login
                FROM allowed_users au
                LEFT JOIN user_credentials uc ON uc.email = au.email
                ORDER BY au.is_admin DESC, au.email ASC`),
      db.query(`SELECT email, ip, user_agent, last_seen FROM user_sessions ORDER BY last_seen DESC LIMIT 50`),
      db.query(`SELECT ip, COUNT(*) as count, MAX(attempted_at) as last_attempt
                FROM login_attempts WHERE attempted_at > NOW() - INTERVAL '24 hours'
                GROUP BY ip ORDER BY count DESC LIMIT 30`),
      db.query(`SELECT jti, expires_at FROM token_revocations WHERE expires_at > NOW() ORDER BY expires_at DESC LIMIT 20`),
      db.query(`SELECT id, site_name, rating, note, rater, rated_at, rater_ip FROM site_ratings ORDER BY rated_at DESC LIMIT 30`),
    ]);

    const liveThreshold = new Date(Date.now() - 3 * 60 * 1000);
    const liveSessions = sessionsRes.rows.filter(s => new Date(s.last_seen) > liveThreshold);

    res.status(200).json({
      users: usersRes.rows,
      sessions: sessionsRes.rows,
      liveSessions: liveSessions.length,
      loginAttempts: attemptsRes.rows,
      revocations: revocationsRes.rows,
      ratings: ratingsRes.rows,
      stats: {
        totalUsers: usersRes.rows.length,
        activeUsers: usersRes.rows.filter(u => u.active).length,
        adminCount: usersRes.rows.filter(u => u.is_admin).length,
        liveSessions: liveSessions.length,
        failedLogins24h: attemptsRes.rows.reduce((s, r) => s + parseInt(r.count, 10), 0),
        activeRevocations: revocationsRes.rows.length,
      },
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};
