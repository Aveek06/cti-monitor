// Vercel serverless — PATCH updates sigma_status for a sigma_rules row.
// Body: { id: number, status: "draft"|"reviewed"|"promoted"|"retired" }

const { Pool } = require("pg");
const { jwtVerify } = require("jose");

const VALID_STATUSES = new Set(["draft", "reviewed", "promoted", "retired"]);

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

async function requireAuth(req) {
  try {
    const token = parseCookie(req.headers.cookie)["cti_session"];
    if (!token || !process.env.SESSION_SECRET) return false;
    const secret = new TextEncoder().encode(process.env.SESSION_SECRET);
    await jwtVerify(token, secret);
    return true;
  } catch {
    return false;
  }
}

module.exports = async function handler(req, res) {
  if (req.method !== "PATCH") {
    res.setHeader("Allow", "PATCH");
    return res.status(405).json({ error: "Method not allowed" });
  }

  if (!(await requireAuth(req)))
    return res.status(401).json({ error: "Unauthorized" });

  if (!process.env.DATABASE_URL)
    return res.status(500).json({ error: "DATABASE_URL not configured" });

  const { id, status } = req.body || {};
  if (!id || !Number.isInteger(+id) || +id < 1)
    return res.status(400).json({ error: "id (positive integer) required" });
  if (!status || !VALID_STATUSES.has(status))
    return res.status(400).json({ error: `status must be one of: ${[...VALID_STATUSES].join(", ")}` });

  try {
    const { rowCount } = await pool().query(
      "UPDATE sigma_rules SET sigma_status=$1 WHERE id=$2",
      [status, +id]
    );
    if (rowCount === 0)
      return res.status(404).json({ error: "Sigma rule not found" });
    return res.json({ ok: true, id: +id, sigma_status: status });
  } catch (e) {
    console.error("PATCH /api/sigma-status error:", e);
    return res.status(500).json({ error: "Internal server error" });
  }
};
