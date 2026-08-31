// Vercel serverless — GET returns per-site rating aggregates, POST inserts a new rating.
// Uses DATABASE_URL (same Supabase connection as other pipeline code).

const { Pool } = require("pg");

let _pool;
function pool() {
  if (!_pool) _pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 3 });
  return _pool;
}

const _postLog = new Map();
const POST_LIMIT_MS = 10 * 60 * 1000;

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
    const { site_name, rating, note, rater } = req.body || {};
    if (!site_name || !Number.isInteger(+rating) || +rating < 1 || +rating > 5)
      return res.status(400).json({ error: "site_name and rating (1–5) required" });
    if (typeof site_name !== "string" || site_name.length > 120)
      return res.status(400).json({ error: "site_name must be a string ≤ 120 chars" });
    if (/[<>"'`]/.test(site_name))
      return res.status(400).json({ error: "site_name contains disallowed characters" });
    if (note   && (typeof note   !== "string" || note.length   > 500))
      return res.status(400).json({ error: "note must be ≤ 500 chars" });
    if (rater  && (typeof rater  !== "string" || rater.length  > 100))
      return res.status(400).json({ error: "rater must be ≤ 100 chars" });
    const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";
    const lastPost = _postLog.get(ip) || 0;
    if (Date.now() - lastPost < POST_LIMIT_MS)
      return res.status(429).json({ error: "Rate limit: one rating per 10 minutes" });
    _postLog.set(ip, Date.now());
    try {
      await pool().query(
        "INSERT INTO site_ratings (site_name, rating, note, rater) VALUES ($1,$2,$3,$4)",
        [site_name, +rating, note || null, rater || null]
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
