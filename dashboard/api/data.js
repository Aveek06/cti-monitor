// Vercel serverless — reads dashboard data directly from Supabase (PostgreSQL).
// Replaces the previous GitHub Actions artifact approach so data is always
// fresh and never subject to 7-day artifact expiry.

const { Pool } = require("pg");

let _pool;
function pool() {
  if (!_pool)
    _pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 3 });
  return _pool;
}

const OWNER = process.env.GITHUB_OWNER || "Aveek06";
const REPO  = process.env.GITHUB_REPO  || "cti-monitor";
const REF   = process.env.GITHUB_REF   || "main";

async function fetchConfig(token) {
  const res = await fetch(
    `https://api.github.com/repos/${OWNER}/${REPO}/contents/config.json?ref=${REF}`,
    {
      headers: {
        Authorization:          `Bearer ${token}`,
        Accept:                 "application/vnd.github.raw+json",
        "User-Agent":           "cti-dashboard/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
      },
    }
  );
  if (!res.ok) throw new Error(`GitHub config fetch ${res.status}`);
  return res.json();
}

async function getPipelineState(key) {
  const { rows } = await pool().query(
    "SELECT data FROM pipeline_state WHERE key = $1",
    [key]
  );
  return rows[0]?.data ?? null;
}

module.exports = async function handler(req, res) {
  const token = process.env.GITHUB_TOKEN;
  if (!token)
    return res.status(500).json({ error: "GITHUB_TOKEN env var not configured." });
  if (!process.env.DATABASE_URL)
    return res.status(500).json({ error: "DATABASE_URL env var not configured." });

  if (req.query.bust) {
    res.setHeader("Cache-Control", "no-store");
  } else {
    res.setHeader("Cache-Control", "s-maxage=300, stale-while-revalidate=600");
  }

  try {
    const [config, state, lastActive, prevRunLinks, iocExport, ttpExport, sigmaExport, actorExport] =
      await Promise.all([
        fetchConfig(token),
        getPipelineState("state"),
        getPipelineState("last_active"),
        getPipelineState("prev_run_links"),
        getPipelineState("ioc_export"),
        getPipelineState("ttp_export"),
        getPipelineState("sigma_export"),
        getPipelineState("actor_export"),
      ]);

    if (!state && !lastActive) {
      return res.status(404).json({
        error:
          "No pipeline data in database yet. " +
          "Run the cti-monitor workflow at least once with DATABASE_URL set, then reload.",
      });
    }

    return res.json({
      config:       config  || { sites: [] },
      state:        state   || {},
      lastActive:   lastActive || {},
      prevRunLinks: prevRunLinks || [],
      iocExport:    iocExport   || [],
      ttpExport:    ttpExport   || [],
      sigmaExport:  sigmaExport || [],
      actorExport:  actorExport || [],
      updatedAt:    new Date().toISOString(),
    });
  } catch (err) {
    console.error("GET /api/data error:", err);
    return res.status(500).json({ error: err.message || "Internal server error" });
  }
};
