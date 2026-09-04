// Vercel serverless — GET all sigma rules (live DB, not artifact)
// DELETE /api/sigma-rules — admin only, removes rule by ID from DB

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
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx < 0) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

async function requireAdmin(req) {
  try {
    const token = parseCookie(req.headers.cookie)["cti_session"];
    if (!token || !process.env.SESSION_SECRET) return false;
    const secret = new TextEncoder().encode(process.env.SESSION_SECRET);
    const { payload } = await jwtVerify(token, secret);
    return payload.is_admin === true;
  } catch {
    return false;
  }
}

module.exports = async function handler(req, res) {
  if (!process.env.DATABASE_URL)
    return res.status(500).json({ error: "DATABASE_URL not configured" });

  // GET — return rules created within the last 5 days (older ones are auto-expired)
  if (req.method === "GET") {
    try {
      const { rows } = await pool().query(
        "SELECT * FROM sigma_rules WHERE created_at > NOW() - INTERVAL '5 days' ORDER BY created_at DESC"
      );
      return res.json({ sigma_rules: rows });
    } catch (e) {
      console.error("GET /api/sigma-rules error:", e);
      return res.status(500).json({ error: "Internal server error" });
    }
  }

  // DELETE — admin only
  if (req.method === "DELETE") {
    if (!(await requireAdmin(req)))
      return res.status(403).json({ error: "Admin access required" });

    const { id } = req.body || {};
    if (!id || !Number.isInteger(+id) || +id < 1)
      return res.status(400).json({ error: "id (positive integer) required" });

    try {
      const { rowCount } = await pool().query(
        "DELETE FROM sigma_rules WHERE id=$1", [+id]
      );
      if (rowCount === 0)
        return res.status(404).json({ error: "Sigma rule not found" });
      return res.json({ ok: true, id: +id });
    } catch (e) {
      console.error("DELETE /api/sigma-rules error:", e);
      return res.status(500).json({ error: "Internal server error" });
    }
  }

  res.setHeader("Allow", "GET, DELETE");
  return res.status(405).json({ error: "Method not allowed" });
};
