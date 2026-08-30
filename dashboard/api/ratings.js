// Vercel serverless — GET returns per-site rating aggregates, POST inserts a new rating.
// Uses DATABASE_URL (same Supabase connection as other pipeline code).

const { Pool } = require("pg");

let _pool;
function pool() {
  if (!_pool) _pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 3 });
  return _pool;
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
      return res.status(500).json({ error: e.message });
    }
  }

  if (req.method === "POST") {
    const { site_name, rating, note, rater } = req.body || {};
    if (!site_name || !Number.isInteger(+rating) || +rating < 1 || +rating > 5)
      return res.status(400).json({ error: "site_name and rating (1–5) required" });
    try {
      await pool().query(
        "INSERT INTO site_ratings (site_name, rating, note, rater) VALUES ($1,$2,$3,$4)",
        [site_name, +rating, note || null, rater || null]
      );
      return res.json({ ok: true });
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  res.setHeader("Allow", "GET, POST");
  return res.status(405).json({ error: "Method not allowed" });
};
