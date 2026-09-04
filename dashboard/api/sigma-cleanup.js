// Vercel Cron — runs daily at 02:00 UTC.
// Hard-deletes sigma_rules rows older than 5 days.
// Protected by CRON_SECRET set in Vercel environment variables.

const { Pool } = require("pg");

let _pool;
function pool() {
  if (!_pool) _pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 3 });
  return _pool;
}

module.exports = async function handler(req, res) {
  // Vercel sets Authorization: Bearer <CRON_SECRET> on cron-triggered requests.
  const auth = req.headers.authorization || "";
  if (!process.env.CRON_SECRET || auth !== `Bearer ${process.env.CRON_SECRET}`)
    return res.status(401).json({ error: "Unauthorized" });

  if (!process.env.DATABASE_URL)
    return res.status(500).json({ error: "DATABASE_URL not configured" });

  try {
    const { rowCount } = await pool().query(
      "DELETE FROM sigma_rules WHERE created_at < NOW() - INTERVAL '5 days'"
    );
    console.log(`sigma-cleanup: deleted ${rowCount} expired rule(s)`);
    return res.json({ ok: true, deleted: rowCount });
  } catch (e) {
    console.error("sigma-cleanup error:", e);
    return res.status(500).json({ error: "Internal server error" });
  }
};
