// Vercel serverless — GET returns per-site rating aggregates, POST inserts a new rating.
// Uses DATABASE_URL (same Supabase connection as other pipeline code).

const { Pool } = require("pg");
const { jwtVerify } = require("jose");

let _pool;
function pool() {
  if (!_pool) _pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 3 });
  return _pool;
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

async function getSessionEmail(req) {
  try {
    const token = parseCookie(req.headers.cookie)['cti_session'];
    if (!token || !process.env.SESSION_SECRET) return null;
    const secret = new TextEncoder().encode(process.env.SESSION_SECRET);
    const { payload } = await jwtVerify(token, secret);
    return payload.email || null;
  } catch {
    return null;
  }
}

module.exports = async function handler(req, res) {
  if (!process.env.DATABASE_URL)
    return res.status(500).json({ error: "DATABASE_URL not configured" });

  if (req.method === "GET") {
    res.setHeader("Cache-Control", "s-maxage=300, stale-while-revalidate=600");
    try {
      const { rows } = await pool().query(`
        SELECT site_name,
               ROUND(AVG(rating)::numeric, 1) AS avg,
               COUNT(*)::int                  AS count
        FROM site_ratings
        GROUP BY site_name
      `);
      const out = {};
      for (const r of rows)
        out[r.site_name] = { avg: parseFloat(r.avg), count: r.count };
      return res.json(out);
    } catch (e) {
      console.error("GET /api/ratings error:", e);
      return res.status(500).json({ error: "Internal server error" });
    }
  }

  if (req.method === "POST") {
    const { site_name, rating, note } = req.body || {};
    if (!site_name || !Number.isInteger(+rating) || +rating < 1 || +rating > 5)
      return res.status(400).json({ error: "site_name and rating (1–5) required" });
    if (typeof site_name !== "string" || site_name.length > 120)
      return res.status(400).json({ error: "site_name must be a string ≤ 120 chars" });
    if (/[<>"'`]/.test(site_name))
      return res.status(400).json({ error: "site_name contains disallowed characters" });
    if (note && (typeof note !== "string" || note.length > 500))
      return res.status(400).json({ error: "note must be ≤ 500 chars" });

    // Rater comes from the verified session, not the request body
    const rater = await getSessionEmail(req);

    const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";
    try {
      const { rows: recent } = await pool().query(
        `SELECT 1 FROM site_ratings WHERE rater_ip=$1 AND created_at > NOW() - INTERVAL '10 minutes' LIMIT 1`,
        [ip]
      );
      if (recent.length) return res.status(429).json({ error: "Rate limit: one rating per 10 minutes" });
      await pool().query(
        "INSERT INTO site_ratings (site_name, rating, note, rater, rater_ip) VALUES ($1,$2,$3,$4,$5)",
        [site_name, +rating, note || null, rater || null, ip]
      );
      return res.json({ ok: true });
    } catch (e) {
      console.error("POST /api/ratings error:", e);
      return res.status(500).json({ error: "Internal server error" });
    }
  }

  res.setHeader("Allow", "GET, POST");
  return res.status(405).json({ error: "Method not allowed" });
};
